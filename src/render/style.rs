//! Colour (DESIGN §2.8): the per-stream decision and chalk-compatible styling.
//!
//! The decision is clap's own `anstream` auto rule (via the same `anstyle-query`
//! reads), made once per process for stdout and, independently, for stderr (D58).
//! The escape codes are chalk's basic styles, including its line-break handling.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::sync::OnceLock;

/// A chalk basic style.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Bold,
    Dim,
    Red,
    Green,
    Yellow,
    Cyan,
    /// chalk `blue` (the red team `RUNNING` status, DESIGN §2.8, §15.3).
    Blue,
    /// chalk `magenta` (the red team `HIGH` severity of the scan reports, §15.16).
    Magenta,
    /// chalk `white` (other red team statuses).
    White,
}

impl Style {
    fn codes(self) -> (&'static str, &'static str) {
        match self {
            Self::Bold => ("\u{1b}[1m", "\u{1b}[22m"),
            Self::Dim => ("\u{1b}[2m", "\u{1b}[22m"),
            Self::Red => ("\u{1b}[31m", "\u{1b}[39m"),
            Self::Green => ("\u{1b}[32m", "\u{1b}[39m"),
            Self::Yellow => ("\u{1b}[33m", "\u{1b}[39m"),
            Self::Cyan => ("\u{1b}[36m", "\u{1b}[39m"),
            Self::Blue => ("\u{1b}[34m", "\u{1b}[39m"),
            Self::Magenta => ("\u{1b}[35m", "\u{1b}[39m"),
            Self::White => ("\u{1b}[37m", "\u{1b}[39m"),
        }
    }
}

/// `chalk.<style>(text)` when `enabled`, else `text`. An empty string gets no codes;
/// the style is closed before every line break and reopened after it (chalk
/// `applyStyle`), so a leading newline yields `open close "\n" open …`.
pub fn paint(style: Style, text: &str, enabled: bool) -> String {
    if !enabled || text.is_empty() {
        return text.to_owned();
    }
    let (open, close) = style.codes();
    let mut out = String::with_capacity(text.len() + 10);
    out.push_str(open);
    let mut rest = text;
    while let Some(index) = rest.find('\n') {
        let (line, break_len) = match rest[..index].strip_suffix('\r') {
            Some(line) => (line, 2),
            None => (&rest[..index], 1),
        };
        out.push_str(line);
        out.push_str(close);
        out.push_str(if break_len == 2 { "\r\n" } else { "\n" });
        out.push_str(open);
        rest = &rest[index + 1..];
    }
    out.push_str(rest);
    out.push_str(close);
    out
}

/// The §2.8 decision for one stream, from an environment lookup and whether the stream
/// is a terminal (`anstream::AutoStream` auto choice).
pub fn decide(var: &dyn Fn(&str) -> Option<OsString>, is_terminal: bool) -> bool {
    let non_empty = |name: &str| var(name).is_some_and(|value| !value.is_empty());
    let clicolor = var("CLICOLOR").map(|value| value != "0");
    if non_empty("NO_COLOR") {
        false
    } else if non_empty("CLICOLOR_FORCE") {
        true
    } else if clicolor == Some(false) {
        false
    } else {
        let term = var("TERM").is_some_and(|term| term != "dumb");
        is_terminal && (term || clicolor == Some(true) || var("CI").is_some())
    }
}

fn process_decision(is_terminal: bool) -> bool {
    decide(&|name| std::env::var_os(name), is_terminal)
}

/// Whether stdout is coloured in this process (decided once).
pub fn stdout_color() -> bool {
    static DECISION: OnceLock<bool> = OnceLock::new();
    *DECISION.get_or_init(|| process_decision(std::io::stdout().is_terminal()))
}

/// Whether stderr is coloured in this process (decided once).
pub fn stderr_color() -> bool {
    static DECISION: OnceLock<bool> = OnceLock::new();
    *DECISION.get_or_init(|| process_decision(std::io::stderr().is_terminal()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chalk_codes_and_line_breaks() {
        assert_eq!(paint(Style::Bold, "t", true), "\u{1b}[1mt\u{1b}[22m");
        assert_eq!(paint(Style::Dim, "t", true), "\u{1b}[2mt\u{1b}[22m");
        assert_eq!(paint(Style::Red, "t", true), "\u{1b}[31mt\u{1b}[39m");
        assert_eq!(paint(Style::Green, "t", true), "\u{1b}[32mt\u{1b}[39m");
        assert_eq!(paint(Style::Yellow, "t", true), "\u{1b}[33mt\u{1b}[39m");
        assert_eq!(paint(Style::Cyan, "t", true), "\u{1b}[36mt\u{1b}[39m");
        assert_eq!(paint(Style::Blue, "t", true), "\u{1b}[34mt\u{1b}[39m");
        assert_eq!(paint(Style::Magenta, "t", true), "\u{1b}[35mt\u{1b}[39m");
        assert_eq!(paint(Style::White, "t", true), "\u{1b}[37mt\u{1b}[39m");
        assert_eq!(paint(Style::Red, "", true), "");
        assert_eq!(paint(Style::Red, "t", false), "t");
        // chalk.red("\n  ✗ Error: x")
        assert_eq!(
            paint(Style::Red, "\n  ✗ Error: x", true),
            "\u{1b}[31m\u{1b}[39m\n\u{1b}[31m  ✗ Error: x\u{1b}[39m"
        );
        // chalk.red("\n  ✗ m\n")
        assert_eq!(
            paint(Style::Red, "\n  ✗ m\n", true),
            "\u{1b}[31m\u{1b}[39m\n\u{1b}[31m  ✗ m\u{1b}[39m\n\u{1b}[31m\u{1b}[39m"
        );
        assert_eq!(
            paint(Style::Dim, "a\r\nb", true),
            "\u{1b}[2ma\u{1b}[22m\r\n\u{1b}[2mb\u{1b}[22m"
        );
    }

    fn with(vars: &[(&str, &str)], tty: bool) -> bool {
        let vars: Vec<(String, OsString)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        decide(
            &|name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()),
            tty,
        )
    }

    #[test]
    fn decision_matches_the_clap_rule() {
        // A terminal needs TERM (not dumb), CLICOLOR or CI.
        assert!(with(&[("TERM", "xterm-256color")], true));
        assert!(!with(&[("TERM", "xterm-256color")], false));
        assert!(!with(&[], true));
        assert!(!with(&[("TERM", "dumb")], true));
        assert!(with(&[("CLICOLOR", "1")], true));
        assert!(with(&[("CI", "")], true));
        assert!(!with(&[("CI", "1")], false));
        // NO_COLOR (non-empty) wins over everything.
        assert!(!with(
            &[
                ("NO_COLOR", "1"),
                ("CLICOLOR_FORCE", "1"),
                ("TERM", "xterm")
            ],
            true
        ));
        assert!(with(&[("NO_COLOR", ""), ("TERM", "xterm")], true));
        // CLICOLOR_FORCE (any non-empty value, 0 included) forces colour on a pipe.
        assert!(with(&[("CLICOLOR_FORCE", "1")], false));
        assert!(with(&[("CLICOLOR_FORCE", "0")], false));
        assert!(!with(&[("CLICOLOR_FORCE", "")], false));
        // CLICOLOR=0 disables on a terminal.
        assert!(!with(&[("CLICOLOR", "0"), ("TERM", "xterm")], true));
        // FORCE_COLOR is not read (D58).
        assert!(!with(&[("FORCE_COLOR", "1")], false));
        assert!(!with(&[("FORCE_COLOR", "3")], true));
    }
}
