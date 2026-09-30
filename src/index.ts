import chalk from "chalk";
import { auditContract } from "./analyze/llm.js";
import { HeuristicEngine } from "./analyze/heuristics.js";
import { ConfigError, initBaseConfig, requireEtherscan, requireLLM, requireMempool } from "./config.js";
import { EtherscanError, fetchContractSource } from "./ingest/etherscan.js";
import { watchMempool } from "./ingest/mempool.js";
import { createProvider } from "./llm/provider.js";
import { renderAnalysis, renderSourceMeta, renderTxReport, txSummaryLine } from "./render/output.js";
import { logger } from "./util/logger.js";

// Backstop only. Every external call is meant to be wrapped at its source;
// these handlers exist so a missed case is logged with a clear message
// instead of a raw stack trace, and the process exits non-zero.
process.on("unhandledRejection", (reason) => {
  logger.error(`Unhandled rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
  process.exitCode = 1;
});
process.on("uncaughtException", (err) => {
  logger.error(`Uncaught exception: ${err.message}`);
  process.exit(1);
});

function printUsage(): void {
  const cmd = chalk.cyan;
  const dim = chalk.dim;
  console.log(`
${chalk.bold("Chain-Mind Auditor")} ${dim("on-chain security analysis for Ethereum")}

${chalk.bold("Usage")}
  ${cmd("npm run tx -- --watch")}            Stream pending mainnet transactions and flag anomalies
  ${cmd("npm run contract -- <address>")}    Summarize a verified contract and cross-check red flags
  ${cmd("npm run demo")}                     Run the hardcoded demo cases

${chalk.bold("Direct")}
  ${cmd("tsx src/index.ts <command> [args]")}

${chalk.bold("Commands")}
  tx --watch           ${dim("needs ALCHEMY_WSS_URL or ALCHEMY_API_KEY")}
  contract <address>   ${dim("needs ETHERSCAN_API_KEY and GROQ_API_KEY")}
  help                 ${dim("show this message")}
`);
}

async function runContract(address: string): Promise<number> {
  // Both groups are validated before any network call, so a missing Groq
  // key is reported up front instead of after spending an Etherscan request.
  const { etherscanApiKey } = requireEtherscan();
  const provider = createProvider(requireLLM());

  let source;
  try {
    source = await fetchContractSource(address, etherscanApiKey);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(err instanceof EtherscanError ? `Etherscan: ${msg}` : msg);
    return 1;
  }

  if (!source) {
    console.log(chalk.yellow(`\n${address} has no verified source on Etherscan.`));
    console.log(chalk.dim("  Unverified contracts cannot be summarized. Treat unverified code holding funds as high risk.\n"));
    return 0;
  }

  renderSourceMeta(source);
  const audit = await auditContract(source.sourceCode, provider);
  renderAnalysis(audit.analysis, audit.check, audit.llmError);
  return 0;
}

function runWatch(): Promise<number> {
  const { wssUrl } = requireMempool();
  const engine = new HeuristicEngine();
  let flagged = 0;

  return new Promise((resolve) => {
    let done = false;
    const finish = async (code: number) => {
      if (done) return;
      done = true;
      await watcher.stop();
      console.log(chalk.dim(`\n${watcher.stats.seen} txs analyzed, ${flagged} flagged, ${watcher.stats.dropped} dropped.`));
      // Normally the event loop is empty by now and the process ends on its
      // own. unref() means this timer only fires if some socket or timer
      // inside a dependency outlived stop(), so Ctrl+C always exits.
      setTimeout(() => process.exit(code), 1000).unref();
      resolve(code);
    };

    const watcher = watchMempool(
      wssUrl,
      (tx) => {
        const report = engine.analyze(tx);
        // Only flagged txs are rendered in full; the mempool moves too fast
        // for a line per clean tx to be readable. LOG_LEVEL=debug shows them.
        if (report.findings.length > 0) {
          flagged++;
          renderTxReport(report);
        } else {
          logger.debug(txSummaryLine(tx));
        }
      },
      (reason) => {
        logger.error(`mempool stream stopped: ${reason}`);
        void finish(1);
      },
    );

    logger.info("watching mainnet mempool, Ctrl+C to stop");
    process.once("SIGINT", () => void finish(0));
  });
}

// Hand-rolled parsing: two commands and one flag do not justify a CLI
// framework dependency.
async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;

  if (!command || command === "help" || command === "--help" || command === "-h") {
    printUsage();
    return 0;
  }

  initBaseConfig();

  switch (command) {
    case "tx": {
      if (!rest.includes("--watch")) {
        logger.error("tx requires --watch");
        printUsage();
        return 1;
      }
      return runWatch();
    }

    case "contract": {
      const address = rest[0];
      if (!address) {
        logger.error("contract requires an address argument");
        printUsage();
        return 1;
      }
      return runContract(address.trim());
    }

    default:
      logger.error(`Unknown command "${command}"`);
      printUsage();
      return 1;
  }
}

// Setting exitCode instead of calling process.exit lets pending stdout
// writes flush before the process ends.
main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    if (err instanceof ConfigError) {
      console.error(chalk.red(err.message));
      console.error(chalk.dim("See .env.example for the full list of variables."));
    } else {
      logger.error(err instanceof Error ? err.message : String(err));
    }
    process.exitCode = 1;
  });
