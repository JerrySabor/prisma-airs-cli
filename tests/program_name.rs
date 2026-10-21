//! The 1.0 rename (DESIGN §21.2, §21.4, §21.6): the executable is `airs`, the 1.x
//! compatibility binary `airs-cli-rs` is the same program, and no source, help text or
//! current document names the program `airs-cli-rs` (only the four kept file format
//! names carry it). The source and document scans only read files in this repository;
//! the help walk runs the real binary with no tenant, so it sends no request.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use airs_test_harness::PROGRAM_NEXT;

const OLD: &str = "airs-cli-rs";

/// The file format names 1.0 keeps (DESIGN §21.3, choice 7).
const KEPT_FORMATS: [&str; 4] = [
    ".bulk-scan",
    ".redteam-targets",
    ".dlp-resources",
    ".runtime-profiles",
];

/// The flags after which a name is an invocation besides the normaliser's words
/// ([`PROGRAM_NEXT`], DESIGN §21.6): the version and help flags, which documents put
/// after the program (`airs --version`, `airs -h`).
const VERSION_AND_HELP_FLAGS: [&str; 4] = ["--version", "-V", "--help", "-h"];

/// Whether `word` after a name makes it an invocation: one of the normaliser's words or
/// a version or help flag.
fn invocation_word(word: &str) -> bool {
    PROGRAM_NEXT.contains(&word) || VERSION_AND_HELP_FLAGS.contains(&word)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("cannot read {relative}: {error}"))
}

fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// The byte offsets of every `airs-cli-rs` in `text`.
fn occurrences(text: &str) -> impl Iterator<Item = usize> + '_ {
    text.match_indices(OLD).map(|(at, _)| at)
}

/// Every `airs-cli-rs` in `src/**/*.rs` is one of the four kept format names (DESIGN
/// §21.6 "Source scan").
#[test]
fn the_source_names_only_the_kept_format_names() {
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    assert!(files.len() > 50, "src/ holds the CLI: {}", files.len());
    let mut problems = Vec::new();
    let mut kept = 0;
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for at in occurrences(&text) {
            let after = &text[at + OLD.len()..];
            if KEPT_FORMATS.iter().any(|format| after.starts_with(format)) {
                kept += 1;
            } else {
                let line = text[..at].matches('\n').count() + 1;
                problems.push(format!("{}:{line}", file.display()));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "the program is `airs` (store::PROGRAM); these name it `airs-cli-rs`:\n{}",
        problems.join("\n")
    );
    assert!(
        kept >= 4,
        "the four FORMAT constants keep their names: {kept}"
    );
}

/// The text of `doc` the scan covers: DESIGN without §21 (which quotes the 0.x names).
fn scanned(doc: &str) -> String {
    let text = read(doc);
    if doc != "docs/DESIGN.md" {
        return text;
    }
    let section = common::design_section_21(&text);
    format!("{}{}", &text[..section.start], &text[section.end..])
}

/// Why the `airs-cli-rs` at byte `at` of `text` is an invocation, if it is one. A path
/// to it (`./airs-cli-rs`, `…/bin/airs-cli-rs`) is a deliberate run of the compatibility
/// name, not an invocation of the program by its old name (DESIGN §21.14 choice 40).
fn invocation(text: &str, at: usize) -> Option<&'static str> {
    let before = &text[..at];
    if before.ends_with('/') {
        return None;
    }
    if before.ends_with("$ ") {
        return Some("after `$ `");
    }
    if before.ends_with("Usage: ") {
        return Some("after `Usage: `");
    }
    let next = text[at + OLD.len()..].strip_prefix(' ')?;
    let end = next
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .unwrap_or(next.len());
    invocation_word(&next[..end]).then_some("before a command word")
}

/// The current documents invoke `airs` (DESIGN §21.6 "Docs scan"): no `airs-cli-rs`
/// after `$ ` or `Usage: `, or before a command word or a version or help flag.
/// History (release notes, research, BENCHMARKS, MILESTONES) is not scanned. RELEASING.md
/// joined the scan with chunk 2, which rewrote the release flow it describes (§21.6).
#[test]
fn current_docs_invoke_airs() {
    let docs = [
        "README.md",
        "AGENTS.md",
        "docs/DESIGN.md",
        "docs/TESTING.md",
        "docs/COMPATIBILITY.md",
        "docs/MIGRATION.md",
        "docs/RELEASING.md",
    ];
    let mut problems = Vec::new();
    for doc in docs {
        let text = scanned(doc);
        for at in occurrences(&text) {
            if let Some(why) = invocation(&text, at) {
                let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
                let line_end = text[at..].find('\n').map_or(text.len(), |i| at + i);
                problems.push(format!("{doc} ({why}): {}", &text[line_start..line_end]));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "documents that still invoke `airs-cli-rs`:\n{}",
        problems.join("\n")
    );
    // The scan sees the invocations it is meant to catch.
    let sample = "  $ airs-cli-rs doctor; Usage: airs-cli-rs [OPTIONS]; 'airs-cli-rs tenant import'; \
                  airs-cli-rs --version; airs-cli-rs.bulk-scan; the airs-cli-rs store; \
                  ./airs-cli-rs --version";
    let found: Vec<_> = occurrences(sample)
        .filter_map(|at| invocation(sample, at))
        .collect();
    assert_eq!(
        found,
        [
            "after `$ `",
            "after `Usage: `",
            "before a command word",
            "before a command word"
        ]
    );
}

/// The compatibility binary is the main binary (DESIGN §21.2): its source includes
/// `src/main.rs` and nothing else, and `Cargo.toml` declares exactly the two targets
/// with `default-run = "airs"`.
#[test]
fn the_compatibility_binary_is_the_main_binary() {
    assert_eq!(
        read("src/bin/airs-cli-rs.rs"),
        "//! The 1.x compatibility name (DESIGN §21.2): the same program as `airs`.\n\
         include!(\"../main.rs\");\n"
    );
    let manifest = read("Cargo.toml");
    let package = manifest
        .split("\n[package]\n")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("Cargo.toml has [package]");
    assert!(
        package.lines().any(|line| line == "default-run = \"airs\""),
        "{package}"
    );
    let bins: Vec<&str> = manifest
        .split("\n[[bin]]\n")
        .skip(1)
        .map(|block| block.split("\n\n").next().unwrap_or(block).trim_end())
        .collect();
    assert_eq!(
        bins,
        [
            "name = \"airs\"\npath = \"src/main.rs\"",
            "name = \"airs-cli-rs\"\npath = \"src/bin/airs-cli-rs.rs\"",
        ]
    );
    assert!(
        !manifest.contains("name = \"airs-cli\"\npath"),
        "no airs-cli binary"
    );
}

/// Runs the binary at `bin` with `args` in a private empty directory, with a cleared
/// environment whose store, HOME and XDG directories lie inside it.
fn help_of(bin: &str, sandbox: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin)
        .args(args)
        .current_dir(sandbox)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", sandbox.join("home"))
        .env("XDG_CONFIG_HOME", sandbox.join("config"))
        .env("XDG_STATE_HOME", sandbox.join("state"))
        .env("XDG_DATA_HOME", sandbox.join("data"))
        .env("AIRS_CLI_CONFIG_DIR", sandbox.join("store"))
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// The subcommand names of a help text's `Commands:` block, `help` left out.
fn subcommands(help: &str) -> Vec<String> {
    help.split_once("\nCommands:\n")
        .map(|(_, rest)| {
            rest.lines()
                .take_while(|line| line.starts_with("  "))
                .filter_map(|line| line.split_whitespace().next())
                .filter(|name| *name != "help")
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Every command's help, from the root down (DESIGN §21.4 families 1, 3 and 4): the
/// usage line is `Usage: airs <path> …`, every example starts `  $ airs ` (or `  $ printf `
/// piping into `airs`), and nothing names `airs-cli-rs`. The compatibility binary
/// prints the same root and leaf help.
#[test]
fn every_help_text_names_airs() {
    let sandbox = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("program-name-help-{}", std::process::id()));
    let _ = fs::remove_dir_all(&sandbox);
    fs::create_dir_all(&sandbox).unwrap();
    let bin = env!("CARGO_BIN_EXE_airs");
    let mut pending: Vec<Vec<String>> = vec![Vec::new()];
    let mut seen = 0;
    let mut examples = 0;
    let mut problems = Vec::new();
    let mut top_level = BTreeSet::new();
    while let Some(path) = pending.pop() {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.push("--help");
        let (code, stdout, stderr) = help_of(bin, &sandbox, &args);
        seen += 1;
        if path.is_empty() {
            top_level.extend(subcommands(&stdout));
        }
        if code != 0 || !stderr.is_empty() {
            problems.push(format!("{args:?}: exit {code}, stderr {stderr:?}"));
            continue;
        }
        let usage = if path.is_empty() {
            "Usage: airs [".to_owned()
        } else {
            format!("Usage: airs {} ", path.join(" "))
        };
        if !(stdout.starts_with(&usage) || stdout.contains(&format!("\n{usage}"))) {
            problems.push(format!("{args:?}: no `{usage}` line"));
        }
        if stdout.contains(OLD) {
            problems.push(format!("{args:?}: names {OLD}"));
        }
        for line in stdout.lines().filter(|line| line.starts_with("  $ ")) {
            examples += 1;
            let piped = line.starts_with("  $ printf ") && line.contains("| airs ");
            if !(line.starts_with("  $ airs ") || piped) {
                problems.push(format!("{args:?}: example {line:?}"));
            }
        }
        for name in subcommands(&stdout) {
            let mut next = path.clone();
            next.push(name);
            pending.push(next);
        }
    }
    let compat = env!("CARGO_BIN_EXE_airs-cli-rs");
    for args in [&["--help"][..], &["gateway", "report", "--help"]] {
        assert_eq!(
            help_of(compat, &sandbox, args),
            help_of(bin, &sandbox, args),
            "{args:?}"
        );
    }
    let _ = fs::remove_dir_all(&sandbox);
    assert!(
        problems.is_empty(),
        "help texts that do not name `airs`:\n{}",
        problems.join("\n")
    );
    assert!(seen > 150, "every command was walked: {seen}");
    // The normaliser's command words are the root's commands and `help`: a new top-level
    // command must join PROGRAM_NEXT, or its hints would compare unnormalised.
    let mut commands: BTreeSet<String> = top_level;
    commands.insert("help".to_owned());
    let words: BTreeSet<String> = PROGRAM_NEXT
        .iter()
        .filter(|word| !word.starts_with('-'))
        .map(|word| (*word).to_owned())
        .collect();
    assert_eq!(
        words, commands,
        "PROGRAM_NEXT's words are the root's commands"
    );
    assert!(examples >= 80, "the examples were checked: {examples}");
}
