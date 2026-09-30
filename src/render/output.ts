import chalk from "chalk";
import Table from "cli-table3";
import { formatEther } from "ethers";
import type { ContractAnalysis, ContractSource, CrossCheckResult, PendingTx, RiskLevel, TxReport } from "../types.js";

// Capped so screenshots from a maximized terminal still have readable
// line lengths.
const WIDTH = Math.min(process.stdout.columns || 100, 110);

const RISK_COLOR: Record<RiskLevel, (s: string) => string> = {
  low: chalk.green,
  medium: chalk.yellow,
  high: chalk.red,
};

export function riskBadge(risk: RiskLevel): string {
  const bg = risk === "high" ? chalk.bgRed.white : risk === "medium" ? chalk.bgYellow.black : chalk.bgGreen.black;
  return bg.bold(` ${risk.toUpperCase()} `);
}

// Greedy word wrap with a hanging indent. Long unbroken tokens (hashes) are
// left intact rather than split mid-token.
function wrap(text: string, indent = 2, width = WIDTH): string {
  const pad = " ".repeat(indent);
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/)) {
    if (line && line.length + 1 + word.length > width - indent) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => pad + l).join("\n");
}

function heading(text: string): void {
  console.log(`\n${chalk.bold.underline(text)}`);
}

export function section(title: string): void {
  const bar = "=".repeat(WIDTH);
  console.log(`\n${chalk.cyan(bar)}\n${chalk.cyan.bold(`  ${title}`)}\n${chalk.cyan(bar)}`);
}

export function txSummaryLine(tx: PendingTx): string {
  const to = tx.to ?? chalk.magenta("(contract creation)");
  const calldata = (tx.input.length - 2) / 2;
  return `${chalk.dim(tx.hash.slice(0, 18) + "...")}  to ${to}  ${formatEther(tx.value)} ETH  ${calldata} bytes calldata`;
}

export function renderTxReport(report: TxReport): void {
  const { tx, findings, score, risk } = report;
  console.log(`\n${riskBadge(risk)} ${chalk.bold(`score ${score}`)}  ${txSummaryLine(tx)}`);
  console.log(chalk.dim(`  hash ${tx.hash}\n  from ${tx.from}`));
  if (findings.length === 0) return;

  const table = new Table({
    head: [chalk.bold("Rule"), chalk.bold("Weight"), chalk.bold("Why it was flagged")],
    colWidths: [26, 8, Math.max(40, WIDTH - 38)],
    wordWrap: true,
    style: { head: [], border: [] },
  });
  for (const f of findings) {
    table.push([f.ruleName, `+${f.weight}`, f.explanation]);
  }
  console.log(table.toString());
}

export function renderSourceMeta(src: ContractSource): void {
  console.log(`\n${chalk.bold(src.name)} ${chalk.dim(src.address)}`);
  console.log(chalk.dim(`  compiler ${src.compilerVersion}, ${src.sourceCode.length.toLocaleString()} chars of verified source`));
}

export function renderAnalysis(analysis: ContractAnalysis | null, check: CrossCheckResult, llmError?: string): void {
  if (analysis) {
    heading("Purpose");
    console.log(wrap(analysis.purpose));

    heading("Functions");
    if (analysis.functions.length === 0) {
      console.log(chalk.dim("  (none reported)"));
    } else {
      const table = new Table({
        head: [chalk.bold("Function"), chalk.bold("Risk"), chalk.bold("What it does")],
        colWidths: [24, 9, Math.max(40, WIDTH - 37)],
        wordWrap: true,
        style: { head: [], border: [] },
      });
      for (const f of analysis.functions) table.push([f.name, RISK_COLOR[f.risk](f.risk), f.does]);
      console.log(table.toString());
    }

    heading("Red flags (LLM)");
    if (analysis.red_flags.length === 0) console.log(chalk.green("  none reported"));
    for (const flag of analysis.red_flags) console.log(chalk.red("  ! ") + wrap(flag, 4).trimStart());
  } else {
    heading("LLM analysis");
    console.log(chalk.red(wrap(`unavailable: ${llmError ?? "unknown error"}`)));
    console.log(chalk.dim("  Showing deterministic cross-check results only."));
  }

  heading("Deterministic cross-check");
  console.log(
    check.regexSignals.length > 0
      ? `  regex hard signals: ${check.regexSignals.map((s) => chalk.yellow(s)).join(", ")}`
      : chalk.green("  regex hard signals: none"),
  );

  // Disagreements and injection attempts are the headline result, so they
  // get a full-width banner rather than a table row.
  if (check.injectionMarkers.length > 0) {
    banner("PROMPT INJECTION ATTEMPT DETECTED IN SOURCE", check.injectionMarkers);
  }
  if (check.disagreements.length > 0) {
    banner("DISAGREEMENT: LLM MISSED WHAT THE REGEX FOUND", [
      ...check.disagreements,
      "Risk escalated to HIGH. Do not trust the LLM summary above for this contract.",
    ]);
  } else if (analysis && check.regexSignals.length > 0) {
    console.log(chalk.green("  LLM reported every regex signal. The two engines agree."));
  }

  heading("Overall risk");
  const llmRisk = analysis ? analysis.overall_risk : null;
  const escalated = llmRisk !== null && llmRisk !== check.finalRisk;
  console.log(
    `  ${riskBadge(check.finalRisk)}` +
      (escalated ? chalk.dim(`  (LLM said ${llmRisk}, escalated by cross-check)`) : "") +
      "\n",
  );
}

function banner(title: string, lines: string[]): void {
  const bar = chalk.red("!".repeat(WIDTH));
  console.log(`\n${bar}`);
  console.log(chalk.bgRed.white.bold(` ${title} `.padEnd(WIDTH)));
  for (const l of lines) console.log(chalk.red(wrap(`- ${l}`, 2)));
  console.log(bar);
}
