export type LogLevel = "debug" | "info" | "warn" | "error";

export const LOG_LEVELS: readonly LogLevel[] = ["debug", "info", "warn", "error"];

const RANK: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };

let current: LogLevel = "info";

export function setLogLevel(level: LogLevel): void {
  current = level;
}

// Logs go to stderr so stdout carries only the analysis output. That keeps
// the report clean when piped to a file, and diagnostics never interleave
// with a rendered table.
function write(level: LogLevel, msg: string): void {
  if (RANK[level] < RANK[current]) return;
  const stamp = new Date().toISOString().slice(11, 19);
  process.stderr.write(`[${stamp}] ${level.toUpperCase().padEnd(5)} ${msg}\n`);
}

export const logger = {
  debug: (msg: string) => write("debug", msg),
  info: (msg: string) => write("info", msg),
  warn: (msg: string) => write("warn", msg),
  error: (msg: string) => write("error", msg),
};
