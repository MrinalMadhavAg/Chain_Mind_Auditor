import { WebSocketProvider } from "ethers";
import { sanitizeTx } from "../security/sanitize.js";
import type { PendingTx } from "../types.js";
import { logger } from "../util/logger.js";

// Fallback path only: cap on concurrent eth_getTransactionByHash lookups.
// Pending hashes arrive far faster than lookups complete, so without a cap
// in-flight requests grow unbounded. Excess hashes are dropped and counted.
const MAX_INFLIGHT_LOOKUPS = 10;
const STATS_INTERVAL_MS = 30_000;
const SUBSCRIBE_TIMEOUT_MS = 15_000;
const RECONNECT_DELAY_MS = 2_000;

type Subscriber = Parameters<WebSocketProvider["_register"]>[1];

// ethers types the socket without onclose, but the underlying `ws` object
// has it. Widening the type here is the only way to detect a drop, since
// ethers v6 does not reconnect on its own.
type ClosableSocket = WebSocketProvider["websocket"] & { onclose: null | ((ev: unknown) => void) };

export interface MempoolStats {
  seen: number;
  invalid: number;
  dropped: number;
}

export interface MempoolWatcher {
  stats: MempoolStats;
  stop(): Promise<void>;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${what} timed out after ${ms / 1000}s`)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(t);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

// Callback interface rather than an async iterator: the consumer (rule
// engine plus render) is synchronous and fast, so there is nothing to pull.
export function watchMempool(
  wssUrl: string,
  onTx: (tx: PendingTx) => void,
  onFatal: (reason: string) => void,
): MempoolWatcher {
  const stats: MempoolStats = { seen: 0, invalid: 0, dropped: 0 };
  let provider: WebSocketProvider | null = null;
  let stopping = false;
  // One reconnect per drop. The budget is restored once a connection
  // subscribes successfully, so isolated drops over a long run are survived
  // but a dead endpoint does not loop forever.
  let reconnectAvailable = true;
  let inflight = 0;

  const deliver = (raw: unknown) => {
    const tx = sanitizeTx(raw);
    if (!tx) {
      stats.invalid++;
      return;
    }
    stats.seen++;
    try {
      onTx(tx);
    } catch (err) {
      logger.warn(`tx handler threw: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Preferred path. alchemy_pendingTransactions pushes full tx objects, so
  // no follow-up request per hash. ethers has no API for custom
  // subscriptions, but its _register hook routes messages for a
  // subscription id we created ourselves to our handler.
  async function subscribeAlchemy(p: WebSocketProvider): Promise<void> {
    const id: unknown = await withTimeout(
      p.send("eth_subscribe", ["alchemy_pendingTransactions", { hashesOnly: false }]),
      SUBSCRIBE_TIMEOUT_MS,
      "alchemy_pendingTransactions subscribe",
    );
    if (typeof id !== "string") throw new Error("subscribe returned no subscription id");
    const handler = { _handleMessage: (msg: unknown) => deliver(msg) } as unknown as Subscriber;
    p._register(id, handler);
  }

  // Fallback for non-Alchemy endpoints: newPendingTransactions yields hashes
  // only, so each tx costs an extra eth_getTransactionByHash round trip.
  // That is one RPC per tx instead of zero, which is why this path is capped.
  async function subscribeHashes(p: WebSocketProvider): Promise<void> {
    await withTimeout(
      p.on("pending", (hash: string) => {
        if (inflight >= MAX_INFLIGHT_LOOKUPS) {
          stats.dropped++;
          return;
        }
        inflight++;
        p.getTransaction(hash)
          .then((tx) => {
            // Null means the tx was mined or evicted before we asked.
            if (tx) deliver(tx);
          })
          .catch(() => {
            stats.invalid++;
          })
          .finally(() => {
            inflight--;
          });
      }),
      SUBSCRIBE_TIMEOUT_MS,
      "newPendingTransactions subscribe",
    );
  }

  async function connect(): Promise<void> {
    // Passing the network skips chain id detection, which ethers otherwise
    // retries forever against an unreachable endpoint.
    const p = new WebSocketProvider(wssUrl, "mainnet");
    provider = p;
    const socket = p.websocket as ClosableSocket;
    socket.onerror = (ev: unknown) => {
      const msg = (ev as { message?: string } | null)?.message ?? "socket error";
      logger.warn(`websocket error: ${msg}`);
    };
    socket.onclose = () => {
      if (!stopping && provider === p) void handleDrop("connection closed");
    };
    // Errors emitted by ethers itself (e.g. unexpected messages) must not
    // become unhandled events.
    p.on("error", (err: unknown) => logger.debug(`provider error: ${err instanceof Error ? err.message : String(err)}`)).catch(() => {});

    // Path chosen by host, not by trial: some non-Alchemy nodes accept the
    // alchemy_pendingTransactions subscribe call and then never send
    // anything, which would look like a quiet mempool.
    let useAlchemy = false;
    try {
      useAlchemy = new URL(wssUrl).hostname.endsWith("alchemy.com");
    } catch {
      // Unparseable URL: the connection itself will fail and be reported.
    }

    if (useAlchemy) {
      try {
        await subscribeAlchemy(p);
        logger.info("subscribed via alchemy_pendingTransactions (full tx objects)");
        reconnectAvailable = true;
        return;
      } catch (err) {
        if (stopping) return;
        logger.info(`alchemy_pendingTransactions failed (${err instanceof Error ? err.message : String(err)}), falling back`);
      }
    }
    await subscribeHashes(p);
    // ethers registers the subscription lazily, so confirm the socket is
    // really live before declaring success.
    await withTimeout(p.getBlockNumber(), SUBSCRIBE_TIMEOUT_MS, "connection check");
    logger.info("subscribed via newPendingTransactions (one lookup per tx)");
    reconnectAvailable = true;
  }

  // A single drop can be reported twice (socket close and a failed pending
  // subscribe), so a guard keeps one drop from spending the reconnect budget
  // twice.
  let handling = false;

  async function handleDrop(reason: string): Promise<void> {
    if (handling || stopping) return;
    handling = true;
    let retryReason: string | null = null;
    try {
      const old = provider;
      provider = null;
      if (old) await old.destroy().catch(() => {});
      if (!reconnectAvailable) {
        onFatal(`${reason}; reconnect already attempted, giving up`);
        return;
      }
      reconnectAvailable = false;
      logger.info(`${reason}, reconnecting in ${RECONNECT_DELAY_MS / 1000}s`);
      await new Promise((r) => setTimeout(r, RECONNECT_DELAY_MS));
      if (stopping) return;
      await connect();
      logger.info("reconnected");
    } catch (err) {
      retryReason = `reconnect failed: ${err instanceof Error ? err.message : String(err)}`;
    } finally {
      handling = false;
    }
    if (retryReason) await handleDrop(retryReason);
  }

  const statsTimer = setInterval(() => {
    logger.info(`mempool: ${stats.seen} analyzed, ${stats.invalid} malformed or vanished, ${stats.dropped} dropped by backpressure`);
  }, STATS_INTERVAL_MS);

  connect().catch((err: unknown) => {
    void handleDrop(`connect failed: ${err instanceof Error ? err.message : String(err)}`);
  });

  return {
    stats,
    async stop() {
      stopping = true;
      clearInterval(statsTimer);
      const p = provider;
      provider = null;
      if (p) await p.destroy().catch(() => {});
    },
  };
}
