//! The TypeScript `ui.ts` primitives (R§2.2), writing data or decoration into
//! [`Output`] with the stdout colour decision (DESIGN §2.7, §2.8).

use super::style::Style;
use crate::output::Output;

const INDENT: &str = "  ";

/// A `ui.bullet` kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bullet {
    Neutral,
    Pass,
    Fail,
    Warn,
    Skip,
    Flag,
}

impl Bullet {
    fn glyph(self) -> &'static str {
        match self {
            Self::Neutral => "•",
            Self::Pass => "✓",
            Self::Fail => "✗",
            Self::Warn => "⚠",
            Self::Skip => "○",
            Self::Flag => "●",
        }
    }

    fn style(self) -> Style {
        match self {
            Self::Neutral => Style::Dim,
            Self::Pass => Style::Green,
            Self::Fail => Style::Red,
            Self::Warn | Self::Skip | Self::Flag => Style::Yellow,
        }
    }
}

/// `ui.header(title, subtitle)`: decoration.
pub fn banner(out: &mut Output, title: &str, subtitle: Option<&str>) {
    let mut text = format!("\n{INDENT}{}\n", out.paint(Style::Bold, title));
    if let Some(subtitle) = subtitle {
        text.push_str(&format!("{INDENT}{}\n", out.paint(Style::Dim, subtitle)));
    }
    text.push('\n');
    out.decoration(&text);
}

/// `ui.section(label)`: decoration.
pub fn section(out: &mut Output, label: &str) {
    let text = format!("\n{INDENT}{}\n\n", out.paint(Style::Bold, label));
    out.decoration(&text);
}

/// `ui.keyValue(pairs)`: data. The key width is the longest key of this block; the
/// padded key is dim. Values arrive terminal-safe (and styled where §2.8 says so).
pub fn key_value(out: &mut Output, pairs: &[(&str, String)]) {
    let width = pairs.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    for (key, value) in pairs {
        let key = out.paint(Style::Dim, &format!("{key:<width$}"));
        out.data_line(&format!("{INDENT}{key}{INDENT}{value}"));
    }
}

/// `ui.bullet(text, kind)`: data; only the glyph is coloured.
pub fn bullet(out: &mut Output, text: &str, kind: Bullet) {
    let glyph = out.paint(kind.style(), kind.glyph());
    out.data_line(&format!("{INDENT}{glyph} {text}"));
}

/// `ui.emptyList(resource)`: data, dim.
pub fn empty_list(out: &mut Output, resource: &str) {
    let text = out.paint(Style::Dim, &format!("No {resource} found"));
    out.data_line(&format!("{INDENT}{text}"));
}

/// `ui.dim(text)`: an indented dim line, decoration.
pub fn dim(out: &mut Output, text: &str) {
    let text = out.paint(Style::Dim, text);
    out.decoration(&format!("{INDENT}{text}\n"));
}

/// `ui.success(text)` on stdout: data, glyph and text green as one span.
pub fn success(out: &mut Output, text: &str) {
    let text = out.paint(Style::Green, &format!("✓ {text}"));
    out.data_line(&format!("{INDENT}{text}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::{capture, capture_colored};

    #[test]
    fn plain_bytes() {
        let (mut out, stdout, _) = capture(false);
        banner(
            &mut out,
            "Prisma AIRS — Runtime Configuration",
            Some("Security profile and topic management"),
        );
        section(&mut out, "Profile Detail:");
        key_value(
            &mut out,
            &[
                ("ID", "x".into()),
                ("Revision", "2".into()),
                ("Name", String::new()),
            ],
        );
        bullet(&mut out, "fin example", Bullet::Neutral);
        empty_list(&mut out, "topics");
        success(&mut out, "All checks passed");
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  Prisma AIRS — Runtime Configuration\n  Security profile and topic management\n\n\n  Profile Detail:\n\n  ID        x\n  Revision  2\n  Name      \n  • fin example\n  No topics found\n  ✓ All checks passed\n"
        );
    }

    #[test]
    fn quiet_keeps_data_only() {
        let (mut out, stdout, _) = capture(true);
        banner(&mut out, "T", Some("S"));
        section(&mut out, "L");
        dim(&mut out, "    hint");
        key_value(&mut out, &[("K", "v".into())]);
        bullet(&mut out, "b", Bullet::Flag);
        empty_list(&mut out, "profiles");
        out.commit().unwrap();
        assert_eq!(stdout.text(), "  K  v\n  ● b\n  No profiles found\n");
    }

    /// R§3.2 / R§3.4 TTY captures (chalk spans).
    #[test]
    fn coloured_bytes_match_chalk() {
        let (mut out, stdout, _) = capture_colored(false);
        banner(&mut out, "Doctor", Some("Prisma AIRS CLI preflight checks"));
        section(&mut out, "Topic Detail:");
        key_value(
            &mut out,
            &[("ID", "x".into()), ("Description", "new".into())],
        );
        bullet(&mut out, "fin example", Bullet::Neutral);
        bullet(&mut out, "injection", Bullet::Flag);
        empty_list(&mut out, "topics");
        dim(&mut out, "    hint");
        success(&mut out, "All checks passed");
        out.commit().unwrap();
        assert_eq!(
            stdout.text(),
            "\n  \u{1b}[1mDoctor\u{1b}[22m\n  \u{1b}[2mPrisma AIRS CLI preflight checks\u{1b}[22m\n\n\n  \u{1b}[1mTopic Detail:\u{1b}[22m\n\n  \u{1b}[2mID         \u{1b}[22m  x\n  \u{1b}[2mDescription\u{1b}[22m  new\n  \u{1b}[2m•\u{1b}[22m fin example\n  \u{1b}[33m●\u{1b}[39m injection\n  \u{1b}[2mNo topics found\u{1b}[22m\n  \u{1b}[2m    hint\u{1b}[22m\n  \u{1b}[32m✓ All checks passed\u{1b}[39m\n"
        );
    }
}
