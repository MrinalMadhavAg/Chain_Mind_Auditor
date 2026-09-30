import { formatEther, formatUnits } from "ethers";
import type { Finding, PendingTx } from "../types.js";

export interface Rule {
  id: string;
  name: string;
  weight: number;
  check(tx: PendingTx): Finding | null;
}

// Selectors (first 4 bytes of keccak256 of the signature), verified with
// ethers.id(). Only used to decide whether a value-moving call is "known".
export const KNOWN_SELECTORS: Record<string, string> = {
  "0xa9059cbb": "transfer(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0x095ea7b3": "approve(address,uint256)",
  "0x7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
  "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
  "0x18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
  "0xfb3bdb41": "swapETHForExactTokens(uint256,address[],address,uint256)",
  "0xac9650d8": "multicall(bytes[])",
  "0x5ae401dc": "multicall(uint256,bytes[])",
  "0x3593564c": "execute(bytes,bytes[],uint256)",
  "0x24856bc3": "execute(bytes,bytes[])",
  "0x414bf389": "exactInputSingle(...)",
  "0xd0e30db0": "deposit()",
  "0x2e1a7d4d": "withdraw(uint256)",
  "0x42842e0e": "safeTransferFrom(address,address,uint256)",
  "0xa22cb465": "setApprovalForAll(address,bool)",
};

const APPROVE_SELECTOR = "0x095ea7b3";
const MAX_UINT256_HEX = "f".repeat(64);
const HIGH_VALUE_WEI = 100_000_000_000_000_000n; // 0.1 ETH

// Thresholds for the stateful rules.
const GAS_WINDOW = 50;
const GAS_MULTIPLIER = 5n;
// Below this many samples a median is noise, so the gas rule stays quiet
// at startup instead of flagging the first expensive tx it sees.
const GAS_MIN_SAMPLES = 20;
const BURST_WINDOW_MS = 30_000;
const BURST_THRESHOLD = 5;
// Bound on tracked senders. The mempool has far more unique senders than
// repeat senders, so without a sweep this map would only grow.
const MAX_TRACKED_SENDERS = 10_000;

// Rolling state shared by the stateful rules. The engine records a tx only
// after all rules have run, so a tx is never compared against itself.
export class TxHistory {
  private gasPrices: bigint[] = [];
  private senders = new Map<string, number[]>();

  constructor(private readonly now: () => number = Date.now) {}

  record(tx: PendingTx): void {
    if (tx.gasPrice !== null) {
      this.gasPrices.push(tx.gasPrice);
      if (this.gasPrices.length > GAS_WINDOW) this.gasPrices.shift();
    }
    const t = this.now();
    const times = this.recentSends(tx.from);
    times.push(t);
    this.senders.set(tx.from, times);
    if (this.senders.size > MAX_TRACKED_SENDERS) this.sweep();
  }

  medianGasPrice(): { median: bigint; samples: number } | null {
    if (this.gasPrices.length < GAS_MIN_SAMPLES) return null;
    const sorted = [...this.gasPrices].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return { median: sorted[Math.floor(sorted.length / 2)]!, samples: sorted.length };
  }

  recentSends(from: string): number[] {
    const cutoff = this.now() - BURST_WINDOW_MS;
    return (this.senders.get(from) ?? []).filter((t) => t > cutoff);
  }

  private sweep(): void {
    for (const [from] of this.senders) {
      const recent = this.recentSends(from);
      if (recent.length === 0) this.senders.delete(from);
      else this.senders.set(from, recent);
    }
  }
}

function selectorOf(tx: PendingTx): string | null {
  return tx.input.length >= 10 ? tx.input.slice(0, 10) : null;
}

function gwei(wei: bigint): string {
  return `${Number(formatUnits(wei, "gwei")).toFixed(2)} gwei`;
}

function short(addr: string): string {
  return `${addr.slice(0, 8)}...${addr.slice(-6)}`;
}

export function createRules(history: TxHistory): Rule[] {
  const finding = (rule: Omit<Rule, "check">, explanation: string): Finding => ({
    ruleId: rule.id,
    ruleName: rule.name,
    weight: rule.weight,
    explanation,
  });

  const unlimitedApproval: Rule = {
    id: "unlimited-approval",
    name: "Unlimited ERC-20 approval",
    weight: 40,
    check(tx) {
      if (selectorOf(tx) !== APPROVE_SELECTOR) return null;
      // Layout: 0x | selector (8) | spender word (64) | amount word (64)
      const spenderWord = tx.input.slice(10, 74);
      const amount = tx.input.slice(74, 138);
      if (amount !== MAX_UINT256_HEX) return null;
      const spender = spenderWord.length === 64 ? `0x${spenderWord.slice(24)}` : "unknown";
      return finding(
        this,
        `Grants ${short(spender)} permission to spend an unlimited amount of the token at ${tx.to ? short(tx.to) : "?"}. ` +
          `If that spender is malicious or later compromised, the whole balance can be drained without another signature.`,
      );
    },
  };

  const contractCreation: Rule = {
    id: "contract-creation",
    name: "Contract deployment",
    weight: 25,
    check(tx) {
      if (tx.to !== null) return null;
      return finding(
        this,
        `No recipient: this deploys a new contract with ${(tx.input.length - 2) / 2} bytes of init code. ` +
          `Fresh deployments are unaudited by definition and are how scam tokens and drainers enter the chain.`,
      );
    },
  };

  const malformedCalldata: Rule = {
    id: "malformed-calldata",
    name: "Non-standard calldata length",
    weight: 30,
    check(tx) {
      // Deployments carry raw init code, not ABI-encoded arguments, so the
      // length rule does not apply to them.
      if (tx.to === null) return null;
      const len = tx.input.length - 2;
      // Every ABI-encoded call is a 4-byte selector plus whole 32-byte words,
      // including dynamic types, which are padded to 32 bytes.
      if (len === 0 || (len >= 8 && (len - 8) % 64 === 0)) return null;
      return finding(
        this,
        `Calldata is ${len} hex chars, which is not a 4-byte selector plus whole 32-byte words. ` +
          `Standard ABI encoders never produce this; it suggests hand-packed calldata, a fuzzing attempt, or a parser exploit.`,
      );
    },
  };

  const unknownSelectorHighValue: Rule = {
    id: "unknown-selector-high-value",
    name: "Unknown selector moving value",
    weight: 35,
    check(tx) {
      const sel = selectorOf(tx);
      if (sel === null || tx.to === null) return null;
      if (KNOWN_SELECTORS[sel] !== undefined || tx.value <= HIGH_VALUE_WEI) return null;
      return finding(
        this,
        `Sends ${formatEther(tx.value)} ETH to an unrecognized function ${sel}. ` +
          `Value sent to an opaque function is a common pattern in fake "claim" and wallet drainer contracts.`,
      );
    },
  };

  const gasPriceOutlier: Rule = {
    id: "gas-price-outlier",
    name: "Extreme gas price",
    weight: 20,
    check(tx) {
      if (tx.gasPrice === null) return null;
      const stats = history.medianGasPrice();
      if (!stats || stats.median === 0n) return null;
      if (tx.gasPrice <= stats.median * GAS_MULTIPLIER) return null;
      // Ratio computed in hundredths to stay in bigint until display.
      const ratio = Number((tx.gasPrice * 100n) / stats.median) / 100;
      return finding(
        this,
        `Gas price ${gwei(tx.gasPrice)} is ${ratio.toFixed(1)}x the rolling median of ${gwei(stats.median)} ` +
          `over the last ${stats.samples} txs. Overpaying this much usually means front-running, a sandwich attack, or a racing exploit.`,
      );
    },
  };

  const senderBurst: Rule = {
    id: "sender-burst",
    name: "High-frequency sender",
    weight: 15,
    check(tx) {
      // +1 counts this tx, which the history has not recorded yet.
      const count = history.recentSends(tx.from).length + 1;
      if (count <= BURST_THRESHOLD) return null;
      return finding(
        this,
        `Sender ${short(tx.from)} has submitted ${count} txs in the last ${BURST_WINDOW_MS / 1000}s. ` +
          `Humans do not sign this fast; this is a bot, which is normal for MEV but also for spam and automated drainers.`,
      );
    },
  };

  const repeatedAddress: Rule = {
    id: "repeated-address-in-calldata",
    name: "Address repetition in payload",
    weight: 20,
    check(tx) {
      // Scanning ABI words rather than every 40-char substring: an address
      // argument is a 32-byte word with 12 zero bytes of left padding. The
      // extra check that the address itself does not start with 4 zero bytes
      // filters out small integers, which have the same padding.
      const counts = new Map<string, number>();
      for (let i = 10; i + 64 <= tx.input.length; i += 64) {
        const word = tx.input.slice(i, i + 64);
        if (!word.startsWith("0".repeat(24))) continue;
        const addr = word.slice(24);
        if (addr.startsWith("00000000")) continue;
        counts.set(addr, (counts.get(addr) ?? 0) + 1);
      }
      let top: [string, number] | null = null;
      for (const entry of counts) if (!top || entry[1] > top[1]) top = entry;
      if (!top || top[1] < 3) return null;
      return finding(
        this,
        `Address ${short(`0x${top[0]}`)} appears ${top[1]} times in the calldata. ` +
          `Repeating one address across arguments is typical of batched drains and approval-harvesting payloads.`,
      );
    },
  };

  // Order matches the spec table; output order follows it.
  return [
    unlimitedApproval,
    contractCreation,
    malformedCalldata,
    unknownSelectorHighValue,
    gasPriceOutlier,
    senderBurst,
    repeatedAddress,
  ];
}
