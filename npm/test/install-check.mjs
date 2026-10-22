// Installs staged npm packages (scripts/npm-package.sh output) from a loopback registry
// into a temporary global prefix and runs the installed commands. tests/npm_package.rs
// runs it on macOS; by hand:
//
//   node npm/test/install-check.mjs target/npm/<version> <version>
//
// The registry serves only the staged tarballs on 127.0.0.1; npm runs with an empty user
// and global configuration, a private cache and prefix, and no audit, fund or update
// check, so nothing reaches the public registry and no npm credential is read. Prints
// one JSON line with what it saw; exits 1 on any failed check.
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

const [staged, version] = process.argv.slice(2);
if (!staged || !version) {
  console.error("usage: node npm/test/install-check.mjs <staged dir> <version>");
  process.exit(2);
}
const NAME = "@cdot65/prisma-airs-cli";
const PLATFORMS = ["darwin-arm64", "linux-x64", "linux-arm64"];
const TARGETS = {
  "darwin-arm64": "aarch64-apple-darwin",
  "linux-x64": "x86_64-unknown-linux-musl",
  "linux-arm64": "aarch64-unknown-linux-musl",
};
const host = `${process.platform}-${process.arch}`;
assert.ok(PLATFORMS.includes(host), `no platform package for ${host}`);

/** The manifest inside a packed tarball (package/package.json), read with tar. */
function manifestOf(file) {
  return JSON.parse(execFileSync("tar", ["-xzOf", file, "package/package.json"], { encoding: "utf8" }));
}

const files = readdirSync(staged).filter((file) => file.endsWith(".tgz"));
const expected = [`cdot65-prisma-airs-cli-${version}.tgz`, ...PLATFORMS.map((p) => `cdot65-prisma-airs-cli-${version}-${p}.tgz`)];
assert.deepEqual(files.sort(), expected.sort(), "the staged tarballs");

const scratch = mkdtempSync(path.join(tmpdir(), "airs-npm-install-"));
const versions = {};
const tarballs = new Map();
let server;
try {
  server = createServer((request, response) => {
    const url = decodeURIComponent(request.url ?? "");
    if (url === `/${NAME}`) {
      const port = server.address().port;
      const body = {
        name: NAME,
        "dist-tags": { latest: version },
        versions: Object.fromEntries(
          Object.entries(versions).map(([v, entry]) => [
            v,
            { ...entry.manifest, _id: `${NAME}@${v}`, dist: { ...entry.dist, tarball: `http://127.0.0.1:${port}/tarballs/${entry.file}` } },
          ]),
        ),
      };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
      return;
    }
    const tarball = url.startsWith("/tarballs/") ? tarballs.get(url.slice("/tarballs/".length)) : undefined;
    if (tarball) {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.end(tarball);
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end('{"error":"not found"}');
  });
  for (const file of files) {
    const bytes = readFileSync(path.join(staged, file));
    const manifest = manifestOf(path.join(staged, file));
    assert.equal(manifest.name, NAME, file);
    tarballs.set(file, bytes);
    versions[manifest.version] = {
      file,
      manifest,
      dist: {
        integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
        shasum: createHash("sha1").update(bytes).digest("hex"),
      },
    };
  }
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const registry = `http://127.0.0.1:${server.address().port}/`;

  const prefix = path.join(scratch, "prefix");
  const home = path.join(scratch, "home");
  mkdirSync(home, { recursive: true });
  writeFileSync(path.join(scratch, "npmrc-user"), "");
  writeFileSync(path.join(scratch, "npmrc-global"), "");
  const nodeDir = path.dirname(process.execPath);
  const env = {
    PATH: `${nodeDir}:/usr/bin:/bin`,
    HOME: home,
    npm_config_userconfig: path.join(scratch, "npmrc-user"),
    npm_config_globalconfig: path.join(scratch, "npmrc-global"),
    npm_config_cache: path.join(scratch, "cache"),
    npm_config_prefix: prefix,
    npm_config_registry: registry,
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_update_notifier: "false",
    npm_config_loglevel: "error",
  };
  const npm = path.join(nodeDir, "npm");
  // Asynchronous: the registry answers from this process's event loop.
  const install = await new Promise((resolve) => {
    const child = spawn(npm, ["install", "--global", `${NAME}@${version}`], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
  assert.equal(install.status, 0, `npm install failed:\n${install.stdout}\n${install.stderr}`);

  const root = path.join(prefix, "lib", "node_modules", NAME);
  const platformDirs = Object.fromEntries(
    PLATFORMS.map((p) => [p, existsSync(path.join(root, "node_modules", `${NAME}-${p}`, "vendor", TARGETS[p], "airs"))]),
  );
  const run = (command, args, extra = {}) =>
    spawnSync(path.join(prefix, "bin", command), args, {
      env: { PATH: `${path.join(prefix, "bin")}:${nodeDir}:/usr/bin:/bin`, HOME: home, NO_COLOR: "1", ...extra },
      encoding: "utf8",
    });
  const airs = run("airs", ["--version"]);
  const airsCli = run("airs-cli", ["--version"]);
  const store = path.join(scratch, "store");
  const doctor = run("airs", ["doctor", "--output", "json"], { AIRS_CLI_CONFIG_DIR: store });
  const help = run("airs-cli", ["--help"]);
  const result = {
    installed: platformDirs,
    airs: { code: airs.status, stdout: airs.stdout, stderr: airs.stderr },
    airsCli: { code: airsCli.status, stdout: airsCli.stdout, stderr: airsCli.stderr },
    helpUsage: help.stdout.split("\n").find((line) => line.startsWith("Usage: ")) ?? null,
    doctorCode: doctor.status,
    doctorFirst: JSON.parse(doctor.stdout || "[]")[0] ?? null,
  };
  console.log(JSON.stringify(result));
} finally {
  server?.close();
  rmSync(scratch, { recursive: true, force: true });
}
