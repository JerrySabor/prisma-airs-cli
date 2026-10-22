// The npm launcher for the Rust Prisma AIRS CLI (the `airs` command). It finds the
// prebuilt binary in the platform package npm installed as an optional dependency and
// runs it. The package layout follows @openai/codex: the main package
// @cdot65/prisma-airs-cli depends on one version of itself per platform
// (`<version>-darwin-arm64`, `<version>-linux-x64`, `<version>-linux-arm64`), aliased as
// `@cdot65/prisma-airs-cli-<platform>`, each holding exactly the release binary at
// `vendor/<rust target>/airs`. There is no postinstall script and no download.
//
// docs/DESIGN.md §21.16 is the contract. Every message names `airs`, whatever name the
// launcher was started under (`airs` or `airs-cli`), and the binary never sees the
// launcher's argv[0]: it fixes its own program name (DESIGN §21.2).

import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { constants } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PACKAGE = "@cdot65/prisma-airs-cli";

/** The supported platforms: `<process.platform>-<process.arch>` → the Rust target. */
export const TARGETS = Object.freeze({
  "darwin-arm64": "aarch64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-musl",
  "linux-arm64": "aarch64-unknown-linux-musl",
});

/** The environment variable that tells `airs doctor` which launcher started it. */
export const LAUNCHER_VAR = "AIRS_NPM_LAUNCHER";

/** The signals forwarded to the binary (see `forwarded`). */
export const SIGNALS = Object.freeze(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"]);

const OTHER_WAYS = [
  "Install it another way:",
  "  cargo install --locked airs-cli",
  "  brew tap cdot65/prisma-airs-cli && brew trust cdot65/prisma-airs-cli && brew install airs-cli",
];

/** A launcher failure: the message to print and the exit code. */
export class LaunchError extends Error {
  constructor(message) {
    super(message);
    this.name = "LaunchError";
    this.exitCode = 1;
  }
}

/** The platform key (`darwin-arm64`, …) for a platform and an architecture. */
export function platformKey(platform, arch) {
  return `${platform}-${arch}`;
}

/** The platform package's alias name, e.g. `@cdot65/prisma-airs-cli-darwin-arm64`. */
export function platformPackage(key) {
  return `${PACKAGE}-${key}`;
}

/** The refusal for a platform with no prebuilt binary (Intel macOS, Windows, …). */
export function unsupportedMessage(platform, arch) {
  return [
    `airs: no prebuilt binary for ${platformKey(platform, arch)}; the npm package ${PACKAGE} ships macOS arm64, Linux x64 and Linux arm64 only.`,
    ...OTHER_WAYS,
  ].join("\n");
}

/** The refusal for a supported platform whose optional dependency is missing. */
export function missingMessage(key) {
  return [
    `airs: the platform package ${platformPackage(key)} is not installed. npm installs it as an optional dependency; it is skipped with --omit=optional (or --no-optional) and on a platform mismatch.`,
    `Reinstall: npm install -g ${PACKAGE}`,
    ...OTHER_WAYS,
  ].join("\n");
}

/**
 * The binary for this platform: `vendor/<target>/airs` in the platform package, found
 * with `resolve` (`require.resolve` relative to this package). Throws a LaunchError for an
 * unsupported platform or a missing package or binary.
 */
export function findBinary({ platform, arch, resolve }) {
  const key = platformKey(platform, arch);
  const target = TARGETS[key];
  if (!target) {
    throw new LaunchError(unsupportedMessage(platform, arch));
  }
  let manifest;
  try {
    manifest = resolve(`${platformPackage(key)}/package.json`);
  } catch {
    throw new LaunchError(missingMessage(key));
  }
  const binary = path.join(path.dirname(manifest), "vendor", target, "airs");
  if (!existsSync(binary)) {
    throw new LaunchError(missingMessage(key));
  }
  return binary;
}

/**
 * Whether a signal the launcher received is sent on to the binary. A terminal delivers
 * Ctrl-C (SIGINT) and Ctrl-\ (SIGQUIT) to the whole foreground process group, the binary
 * included, and the binary treats a second SIGINT as "exit at once" (DESIGN §2.5); so
 * when any standard stream is a terminal these two are left to the terminal. SIGTERM
 * and SIGHUP, and every signal in a session without a terminal, are forwarded.
 */
export function forwarded(signal, interactive) {
  return !(interactive && (signal === "SIGINT" || signal === "SIGQUIT"));
}

/** Whether stdin, stdout or stderr is a terminal. */
export function interactiveSession(proc = process) {
  return Boolean(proc.stdin?.isTTY || proc.stdout?.isTTY || proc.stderr?.isTTY);
}

/**
 * Ends this process the way the binary ended: with its exit code, or by the same
 * signal (re-raised after the forwarding handlers are removed, so the default action
 * applies; 128 + n if the process survives it).
 */
export function exitLike(result, proc = process) {
  if (result.signal) {
    for (const signal of SIGNALS) {
      proc.removeAllListeners(signal);
    }
    try {
      proc.kill(proc.pid, result.signal);
    } catch {
      // Fall through to the conventional code.
    }
    const number = constants.signals[result.signal];
    proc.exit(number ? 128 + number : 1);
    return;
  }
  proc.exit(result.code ?? 1);
}

/**
 * Runs the binary with the launcher's arguments and standard streams, forwards
 * signals, and resolves to `{ code, signal }` when it exits. `env` gets
 * AIRS_NPM_LAUNCHER, the launcher's real path, so `airs doctor` counts the npm links to
 * it as this program.
 *
 * The handlers are installed before the spawn: on Linux the binary can be running (and
 * a signal can arrive) before `spawn` returns, and a signal with no handler kills the
 * launcher and orphans the binary. A signal that arrives during the spawn is sent once
 * the child exists.
 */
export function run({ binary, args, launcher, proc = process, spawnFn = spawn }) {
  const env = { ...proc.env, [LAUNCHER_VAR]: launcher };
  const interactive = interactiveSession(proc);
  let child = null;
  const pending = [];
  const send = (signal) => {
    if (child.exitCode === null && child.signalCode === null) {
      try {
        child.kill(signal);
      } catch {
        // The child is gone; its exit event follows.
      }
    }
  };
  const handlers = new Map();
  for (const signal of SIGNALS) {
    const handler = () => {
      if (!forwarded(signal, interactive)) {
        return;
      }
      if (child === null) {
        pending.push(signal);
      } else {
        send(signal);
      }
    };
    handlers.set(signal, handler);
    proc.on(signal, handler);
  }
  child = spawnFn(binary, args, { stdio: "inherit", env });
  for (const signal of pending) {
    send(signal);
  }
  return new Promise((resolve, reject) => {
    child.on("error", (error) => {
      for (const [signal, handler] of handlers) {
        proc.removeListener(signal, handler);
      }
      reject(new LaunchError(`airs: cannot run ${binary}: ${error.message}`));
    });
    child.on("exit", (code, signal) => {
      resolve({ code, signal });
    });
  });
}

/** The launcher's entry point (`bin/airs.js`). */
export async function main(entry) {
  const require = createRequire(entry);
  const launcher = realpathSync(fileURLToPath(entry));
  let binary;
  try {
    binary = findBinary({
      platform: process.platform,
      arch: process.arch,
      resolve: (name) => require.resolve(name),
    });
  } catch (error) {
    if (error instanceof LaunchError) {
      process.stderr.write(`${error.message}\n`);
      process.exit(error.exitCode);
    }
    throw error;
  }
  try {
    const result = await run({ binary, args: process.argv.slice(2), launcher });
    exitLike(result);
  } catch (error) {
    if (error instanceof LaunchError) {
      process.stderr.write(`${error.message}\n`);
      process.exit(error.exitCode);
    }
    throw error;
  }
}
