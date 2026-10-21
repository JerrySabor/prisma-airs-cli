# CLAUDE.md

Follow [AGENTS.md](AGENTS.md). It holds the invariants and the required checks.
[docs/DESIGN.md](docs/DESIGN.md) is the behavioural contract. Its §12 lists every
intentional difference from the TypeScript CLI.

Quick commands (prefix with `export PATH="$HOME/.cargo/bin:$PATH";`):

```sh
cargo build --release                                   # target/release/airs-cli-rs (native arm64 on Apple Silicon)
cargo test --workspace                                  # unit + loopback executable + parity tests
AIRS_REQUIRE_PARITY=1 cargo test --workspace            # fail if the TS reference build is missing
scripts/build-reference-cli.sh                          # build the pinned TS reference into .reference/
AIRS_RS_LIVE=1 AIRS_E2E_TENANT=<name> [AIRS_E2E_PROFILE=<profile>] cargo test --test live -- --nocapture --test-threads=1   # bounded live comparison (DESIGN §10)
```

Layout:
- `src/`: the CLI. See DESIGN §11 for the module map.
- `crates/airs-test-harness`: the loopback fixture server, tenant sandbox and dual-CLI runner.
- `tests/`: executable-level tests.
- `docs/research/`: the subsystem specs the design was derived from.
