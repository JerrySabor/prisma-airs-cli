// Tests for the npm launcher (DESIGN §21.16). Run with `node --test npm/test/`;
// tests/npm_package.rs runs them too. They never touch the network or the real npm
// prefix: the end-to-end cases copy the launcher into a temporary package with a stub
// binary in its platform package.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  LAUNCHER_VAR,
  LaunchError,
  PACKAGE,
  SIGNALS,
  TARGETS,
  exitLike,
  findBinary,
  forwarded,
  missingMessage,
  platformKey,
  platformPackage,
  unsupportedMessage,
} from "../lib/launcher.js";

const NPM_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HOST = platformKey(process.platform, process.arch);
const HOST_SUPPORTED = Object.hasOwn(TARGETS, HOST);
const scratch = mkdtempSync(path.join(tmpdir(), "airs-npm-launcher-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

const OTHER_WAYS =
  "Install it another way:\n  cargo install --locked airs-cli\n  brew tap cdot65/prisma-airs-cli && brew trust cdot65/prisma-airs-cli && brew install airs-cli";

describe("platforms", () => {
  test("three platforms map to the release targets", () => {
    assert.deepEqual(TARGETS, {
      "darwin-arm64": "aarch64-apple-darwin",
      "linux-x64": "x86_64-unknown-linux-musl",
      "linux-arm64": "aarch64-unknown-linux-musl",
    });
    assert.equal(platformPackage("linux-x64"), "@cdot65/prisma-airs-cli-linux-x64");
  });

  test("the manifest aliases one platform version per target", async () => {
    const manifest = JSON.parse(
      (await import("node:fs")).readFileSync(path.join(NPM_DIR, "package.json"), "utf8"),
    );
    assert.equal(manifest.name, PACKAGE);
    assert.deepEqual(manifest.bin, { airs: "bin/airs.js", "airs-cli": "bin/airs.js" });
    assert.deepEqual(manifest.engines, { node: ">=18" });
    assert.equal(manifest.license, "Apache-2.0");
    assert.equal(manifest.scripts, undefined, "no install scripts");
    const expected = {};
    for (const key of Object.keys(TARGETS)) {
      expected[platformPackage(key)] = `npm:${PACKAGE}@${manifest.version}-${key}`;
    }
    assert.deepEqual(manifest.optionalDependencies, expected);
  });

  for (const [platform, arch] of [
    ["darwin", "x64"],
    ["win32", "x64"],
    ["win32", "arm64"],
    ["linux", "ia32"],
    ["freebsd", "x64"],
  ]) {
    test(`${platform}-${arch} is refused with the other ways to install`, () => {
      assert.throws(
        () => findBinary({ platform, arch, resolve: () => assert.fail("not resolved") }),
        (error) => {
          assert.ok(error instanceof LaunchError);
          assert.equal(error.exitCode, 1);
          assert.equal(error.message, unsupportedMessage(platform, arch));
          assert.equal(
            error.message,
            `airs: no prebuilt binary for ${platform}-${arch}; the npm package @cdot65/prisma-airs-cli ships macOS arm64, Linux x64 and Linux arm64 only.\n${OTHER_WAYS}`,
          );
          return true;
        },
      );
    });
  }

  test("a missing optional dependency names the reinstall and the other ways", () => {
    assert.throws(
      () =>
        findBinary({
          platform: "linux",
          arch: "x64",
          resolve: () => {
            throw new Error("Cannot find module");
          },
        }),
      (error) => {
        assert.equal(error.message, missingMessage("linux-x64"));
        assert.match(error.message, /^airs: the platform package @cdot65\/prisma-airs-cli-linux-x64 is not installed/);
        assert.ok(error.message.includes("Reinstall: npm install -g @cdot65/prisma-airs-cli\n"));
        assert.ok(error.message.endsWith(OTHER_WAYS));
        return true;
      },
    );
  });

  test("a platform package without its binary is missing too", () => {
    const dir = path.join(scratch, "empty-platform");
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, "package.json"), "{}");
    assert.throws(
      () =>
        findBinary({
          platform: "darwin",
          arch: "arm64",
          resolve: () => path.join(dir, "package.json"),
        }),
      (error) => error.message === missingMessage("darwin-arm64"),
    );
  });

  test("the binary is vendor/<target>/airs in the platform package", () => {
    const dir = path.join(scratch, "full-platform");
    mkdirSync(path.join(dir, "vendor", "aarch64-unknown-linux-musl"), { recursive: true });
    writeFileSync(path.join(dir, "package.json"), "{}");
    writeFileSync(path.join(dir, "vendor", "aarch64-unknown-linux-musl", "airs"), "");
    let asked;
    const binary = findBinary({
      platform: "linux",
      arch: "arm64",
      resolve: (name) => {
        asked = name;
        return path.join(dir, "package.json");
      },
    });
    assert.equal(asked, "@cdot65/prisma-airs-cli-linux-arm64/package.json");
    assert.equal(binary, path.join(dir, "vendor", "aarch64-unknown-linux-musl", "airs"));
  });
});

describe("signals", () => {
  test("a terminal's SIGINT and SIGQUIT are left to the terminal; the rest are forwarded", () => {
    assert.deepEqual(SIGNALS, ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"]);
    const table = SIGNALS.map((signal) => [signal, forwarded(signal, true), forwarded(signal, false)]);
    assert.deepEqual(table, [
      ["SIGINT", false, true],
      ["SIGTERM", true, true],
      ["SIGHUP", true, true],
      ["SIGQUIT", false, true],
    ]);
  });

  test("exitLike exits with the code, or re-raises the signal without the handlers", () => {
    const calls = [];
    const fake = {
      pid: 4242,
      removeAllListeners: (signal) => calls.push(["remove", signal]),
      kill: (pid, signal) => calls.push(["kill", pid, signal]),
      exit: (code) => calls.push(["exit", code]),
    };
    exitLike({ code: 3, signal: null }, fake);
    assert.deepEqual(calls, [["exit", 3]]);
    calls.length = 0;
    exitLike({ code: null, signal: "SIGTERM" }, fake);
    assert.deepEqual(calls, [
      ["remove", "SIGINT"],
      ["remove", "SIGTERM"],
      ["remove", "SIGHUP"],
      ["remove", "SIGQUIT"],
      ["kill", 4242, "SIGTERM"],
      ["exit", 143],
    ]);
  });
});

/**
 * A copy of the launcher package in `scratch/<name>/pkg` with a stub binary (a shell
 * script) in the host's platform package. Returns the launcher path.
 */
function installed(name, stub) {
  const root = path.join(scratch, name, "pkg");
  mkdirSync(root, { recursive: true });
  cpSync(path.join(NPM_DIR, "bin"), path.join(root, "bin"), { recursive: true });
  cpSync(path.join(NPM_DIR, "lib"), path.join(root, "lib"), { recursive: true });
  cpSync(path.join(NPM_DIR, "package.json"), path.join(root, "package.json"));
  if (stub !== null) {
    const platform = path.join(root, "node_modules", platformPackage(HOST));
    const vendor = path.join(platform, "vendor", TARGETS[HOST]);
    mkdirSync(vendor, { recursive: true });
    writeFileSync(path.join(platform, "package.json"), JSON.stringify({ name: PACKAGE }));
    writeFileSync(path.join(vendor, "airs"), `#!/bin/sh\n${stub}\n`);
    chmodSync(path.join(vendor, "airs"), 0o755);
  }
  return path.join(root, "bin", "airs.js");
}

function launch(launcher, args, options = {}) {
  return spawnSync(process.execPath, [launcher, ...args], {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    ...options,
  });
}

describe("end to end", { skip: !HOST_SUPPORTED && `no prebuilt platform for ${HOST}` }, () => {
  test("arguments, stdin, stdout, stderr and the exit code pass through", () => {
    const launcher = installed(
      "passthrough",
      'printf "%s|" "$@"; echo; cat; echo "to stderr" >&2; exit 7',
    );
    const out = launch(launcher, ["runtime", "scan", "--profile", "a b", ""], { input: "piped\n" });
    assert.equal(out.status, 7, out.stderr);
    assert.equal(out.signal, null);
    assert.equal(out.stdout, "runtime|scan|--profile|a b||\npiped\n");
    assert.equal(out.stderr, "to stderr\n");
  });

  test("the binary runs under its own name and learns the launcher's real path", () => {
    const launcher = installed("name", `basename "$0"; printf '%s\\n' "$${LAUNCHER_VAR}"`);
    const alias = path.join(scratch, "name", "airs-cli");
    symlinkSync(launcher, alias);
    for (const start of [launcher, alias]) {
      const out = launch(start, []);
      assert.equal(out.status, 0, out.stderr);
      assert.equal(out.stdout, `airs\n${realpathSync(launcher)}\n`);
    }
  });

  test("exit codes 0, 1, 2, 130 and 143 are kept", () => {
    const launcher = installed("codes", 'exit "$1"');
    for (const code of [0, 1, 2, 130, 143]) {
      assert.equal(launch(launcher, [String(code)]).status, code);
    }
  });

  test("a binary killed by a signal kills the launcher with the same signal", () => {
    const launcher = installed("killed", 'kill -TERM $$; sleep 5');
    const out = launch(launcher, []);
    assert.equal(out.status, null);
    assert.equal(out.signal, "SIGTERM");
  });

  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
    test(`${signal} sent to the launcher reaches the binary (no terminal)`, async () => {
      const short = signal.slice(3);
      const launcher = installed(
        `forward-${short}`,
        `trap 'echo got-${short}; exit 42' ${short}; echo ready; while :; do sleep 0.05; done`,
      );
      const child = spawn(process.execPath, [launcher], { stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "";
      const ready = new Promise((resolve) => {
        child.stdout.on("data", (chunk) => {
          stdout += chunk;
          if (stdout.includes("ready\n")) resolve();
        });
      });
      const exited = new Promise((resolve) => child.on("exit", (code, sig) => resolve({ code, sig })));
      await ready;
      child.kill(signal);
      const result = await exited;
      assert.deepEqual(result, { code: 42, sig: null });
      assert.equal(stdout, `ready\ngot-${short}\n`);
    });
  }

  test("a missing platform package is refused with exit 1 and nothing on stdout", () => {
    const launcher = installed("missing", null);
    const out = launch(launcher, ["--version"]);
    assert.equal(out.status, 1);
    assert.equal(out.stdout, "");
    assert.equal(out.stderr, `${missingMessage(HOST)}\n`);
  });

  test("a binary that cannot run is reported, exit 1", () => {
    const launcher = installed("broken", "exit 0");
    const binary = path.join(
      path.dirname(path.dirname(launcher)),
      "node_modules",
      platformPackage(HOST),
      "vendor",
      TARGETS[HOST],
      "airs",
    );
    chmodSync(binary, 0o644);
    const out = launch(launcher, []);
    assert.equal(out.status, 1);
    assert.match(out.stderr, /^airs: cannot run .*airs: /);
  });
});
