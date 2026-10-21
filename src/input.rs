//! Input channels of the tenant write commands (DESIGN §3.10): the terminal gates,
//! piped stdin, prompts (hidden input with the terminal mode saved for the signal
//! thread) and the delete confirmation.
//!
//! Nothing read here is ever echoed into a message: prompts re-ask with fixed reasons
//! and every refusal has a fixed text.

use crate::error::CliError;
use crate::output::Output;
use crate::signals::Phase;
use crate::tenant::config::{INVALID_VALUE, js_trim};
use std::io::{BufRead, IsTerminal, Read};

/// The most bytes one stdin value or prompt line may have (its newline included).
pub const INPUT_LIMIT: usize = 65_536;

/// `--stdin requires piped input` (TypeScript text, also for `--client-secret-stdin`).
pub const NEEDS_PIPE: &str = "--stdin requires piped input";
/// The prompt gate's refusal (the TypeScript text without `--config`, D84).
pub const INTERACTIVE_SETUP: &str = "Interactive setup requires a terminal. Use --tsg-id and --client-id with --client-secret-stdin. For tenant set, pass a value or use --stdin.";
/// A refused stdin value (TypeScript text).
pub const ONE_VALUE: &str = "Provide one nonempty configuration value on stdin";
/// Too much stdin, or a prompt line that is too long (TypeScript text).
pub const TOO_LARGE: &str = "Configuration input exceeds 64 KiB";
/// The re-ask reason for a blank answer (TypeScript text).
pub const NONEMPTY: &str = "A nonempty value is required";

/// Which of the streams the gates look at are terminals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terminals {
    pub stdin: bool,
    pub stderr: bool,
}

impl Terminals {
    pub fn detect() -> Self {
        Self {
            stdin: std::io::stdin().is_terminal(),
            stderr: std::io::stderr().is_terminal(),
        }
    }

    /// The prompt and confirmation gate: stdin **and** stderr are terminals.
    pub fn interactive(self) -> bool {
        self.stdin && self.stderr
    }
}

/// One piped stdin value from its raw bytes (§3.10 steps 2–5; at most
/// [`INPUT_LIMIT`] + 1 bytes are passed in).
pub fn piped_value(bytes: &[u8]) -> Result<String, CliError> {
    if bytes.len() > INPUT_LIMIT {
        return Err(CliError::usage(TOO_LARGE));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CliError::usage(ONE_VALUE))?;
    let text = strip_newline(text);
    if js_trim(text).is_empty() || text.contains(['\r', '\n', '\0']) {
        return Err(CliError::usage(ONE_VALUE));
    }
    Ok(text.to_owned())
}

/// Read piped stdin to EOF (stopping at byte [`INPUT_LIMIT`] + 1) and validate it. The
/// caller marks the wait for the signal thread.
pub fn read_piped(reader: &mut dyn Read) -> Result<String, CliError> {
    let mut bytes = Vec::new();
    reader
        .take(INPUT_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::usage(ONE_VALUE))?;
    piped_value(&bytes)
}

/// Read the process stdin as one piped value, with the wait marked for the signal
/// thread (a signal ends the process: `Interrupted; no configuration was changed`).
pub fn read_piped_stdin(output: &Output) -> Result<String, CliError> {
    let signals = output.signals();
    let _waiting = signals.as_deref().map(|state| state.enter(Phase::Waiting));
    read_piped(&mut std::io::stdin().lock())
}

/// Strip exactly one trailing `\n` or `\r\n`.
fn strip_newline(text: &str) -> &str {
    text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text)
}

/// One line of terminal input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// The bytes before the line break (or before EOF after some input).
    Text(Vec<u8>),
    /// More than [`INPUT_LIMIT`] bytes; the rest of the line was discarded.
    TooLong,
    /// End of input with nothing typed (Ctrl-D on an empty line).
    Eof,
}

/// Read one line of at most [`INPUT_LIMIT`] bytes, its line break included.
pub fn read_line(input: &mut dyn BufRead) -> std::io::Result<Line> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buffer = match input.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if buffer.is_empty() {
            return Ok(match (too_long, line.is_empty()) {
                (true, _) => Line::TooLong,
                (false, true) => Line::Eof,
                (false, false) => Line::Text(line),
            });
        }
        let (chunk, done) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(index) => (&buffer[..=index], true),
            None => (buffer, false),
        };
        let used = chunk.len();
        if !too_long {
            if line.len() + used > INPUT_LIMIT {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        input.consume(used);
        if done {
            if too_long {
                return Ok(Line::TooLong);
            }
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Line::Text(line));
        }
    }
}

/// A prompt the user cancelled with EOF (Ctrl-D on an empty line); the caller prints
/// [`crate::signals::CANCELLED`] and exits 130.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cancelled;

/// Prompts on stderr reading lines from stdin (§3.10).
pub struct Prompter<'a> {
    input: &'a mut dyn BufRead,
    output: &'a mut Output,
    /// Whether stdin is the terminal whose echo a hidden prompt turns off.
    terminal: bool,
}

impl<'a> Prompter<'a> {
    pub fn new(input: &'a mut dyn BufRead, output: &'a mut Output, terminal: bool) -> Self {
        Self {
            input,
            output,
            terminal,
        }
    }

    /// Turn terminal echo off (`ECHO` cleared; `ICANON` and `ISIG` kept), saving the
    /// old mode with the signal thread first. `None` when stdin is not a terminal.
    fn echo_off(&self) -> Option<rustix::termios::Termios> {
        if !self.terminal {
            return None;
        }
        let saved = rustix::termios::tcgetattr(std::io::stdin()).ok()?;
        let mut silent = saved.clone();
        silent.local_modes.remove(rustix::termios::LocalModes::ECHO);
        if let Some(signals) = self.output.signals() {
            signals.save_termios(Some(saved.clone()));
        }
        let _ = rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &silent,
        );
        Some(saved)
    }

    fn echo_restore(&self, saved: Option<rustix::termios::Termios>) {
        if let Some(saved) = saved {
            let _ = rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                &saved,
            );
            if let Some(signals) = self.output.signals() {
                signals.save_termios(None);
            }
        }
    }

    /// Ask until `validate` accepts a nonblank answer (`? <message> `; hidden:
    /// `? <message> [input is masked] ` with echo off). Answers are returned untrimmed.
    pub fn ask<T>(
        &mut self,
        message: &str,
        hidden: bool,
        validate: impl Fn(&str) -> Result<T, String>,
    ) -> Result<T, Cancelled> {
        loop {
            // The prompt phase covers the echo change, the prompt and the read, so a
            // signal at any point of it restores the terminal and cancels the prompt.
            let signals = self.output.signals();
            let prompt_phase = signals.as_deref().map(|state| state.enter(Phase::Prompt));
            let saved = if hidden { self.echo_off() } else { None };
            let prompt = if hidden {
                format!("? {message} [input is masked] ")
            } else {
                format!("? {message} ")
            };
            self.output.write_stderr(&prompt);
            let line = read_line(self.input).unwrap_or(Line::Eof);
            self.echo_restore(saved);
            if hidden && line != Line::Eof {
                // The Enter was not echoed.
                self.output.write_stderr("\n");
            }
            drop(prompt_phase);
            let reason = match line {
                Line::Eof => return Err(Cancelled),
                Line::TooLong => TOO_LARGE.to_owned(),
                Line::Text(bytes) => match String::from_utf8(bytes) {
                    Err(_) => INVALID_VALUE.to_owned(),
                    Ok(answer) if js_trim(&answer).is_empty() => NONEMPTY.to_owned(),
                    Ok(answer) => match validate(&answer) {
                        Ok(value) => return Ok(value),
                        Err(reason) => reason,
                    },
                },
            };
            self.output.write_stderr(&format!("> {reason}\n"));
        }
    }

    /// `? <message> (y/N) `: only `y` or `yes` (trimmed, ASCII case-insensitive)
    /// confirm; anything else, an empty line and EOF decline.
    pub fn confirm(&mut self, message: &str) -> bool {
        let signals = self.output.signals();
        let _prompt = signals.as_deref().map(|state| state.enter(Phase::Prompt));
        self.output.write_stderr(&format!("? {message} (y/N) "));
        match read_line(self.input).unwrap_or(Line::Eof) {
            Line::Text(bytes) => {
                let answer = String::from_utf8_lossy(&bytes);
                let answer = answer.trim();
                answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
            }
            Line::TooLong => false,
            Line::Eof => {
                self.output.write_stderr("\n");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::capture;
    use std::io::Cursor;

    #[test]
    fn piped_values_follow_the_typescript_rules() {
        assert_eq!(piped_value(b"FAKE-SECRET").unwrap(), "FAKE-SECRET");
        assert_eq!(piped_value(b"FAKE-SECRET\n").unwrap(), "FAKE-SECRET");
        assert_eq!(piped_value(b"FAKE-SECRET\r\n").unwrap(), "FAKE-SECRET");
        assert_eq!(
            piped_value(b"  FAKE SECRET  \n").unwrap(),
            "  FAKE SECRET  ",
            "untrimmed"
        );
        for bytes in [
            &b""[..],
            b"\n",
            b"   \n",
            b"FAKE\nsecond",
            b"FAKE\n\n",
            b"FAKE\0SECRET",
            b"FAKE\r",
            b"\xff\xfe",
        ] {
            assert_eq!(
                piped_value(bytes),
                Err(CliError::usage(ONE_VALUE)),
                "{bytes:?}"
            );
        }
        let exact = vec![b'x'; INPUT_LIMIT];
        assert_eq!(piped_value(&exact).unwrap().len(), INPUT_LIMIT);
        let mut over = exact.clone();
        over.push(b'\n');
        assert_eq!(piped_value(&over), Err(CliError::usage(TOO_LARGE)));
        let mut huge = Cursor::new(vec![b'x'; 10 * INPUT_LIMIT]);
        assert_eq!(read_piped(&mut huge), Err(CliError::usage(TOO_LARGE)));
        assert_eq!(
            huge.position(),
            INPUT_LIMIT as u64 + 1,
            "reading stops at byte 65,537"
        );
        assert_eq!(read_piped(&mut Cursor::new(b"v\n".to_vec())).unwrap(), "v");
    }

    #[test]
    fn lines_strip_one_break_and_bound_their_length() {
        let mut input = Cursor::new(b"one\r\ntwo\n\nlast".to_vec());
        assert_eq!(read_line(&mut input).unwrap(), Line::Text(b"one".to_vec()));
        assert_eq!(read_line(&mut input).unwrap(), Line::Text(b"two".to_vec()));
        assert_eq!(read_line(&mut input).unwrap(), Line::Text(Vec::new()));
        assert_eq!(read_line(&mut input).unwrap(), Line::Text(b"last".to_vec()));
        assert_eq!(read_line(&mut input).unwrap(), Line::Eof);
        let mut long = vec![b'x'; INPUT_LIMIT];
        long.extend_from_slice(b"\nok\n");
        let mut input = std::io::BufReader::with_capacity(1000, Cursor::new(long));
        assert_eq!(read_line(&mut input).unwrap(), Line::TooLong);
        assert_eq!(read_line(&mut input).unwrap(), Line::Text(b"ok".to_vec()));
        let mut fits = vec![b'y'; INPUT_LIMIT - 1];
        fits.push(b'\n');
        let mut input = Cursor::new(fits);
        assert!(
            matches!(read_line(&mut input).unwrap(), Line::Text(t) if t.len() == INPUT_LIMIT - 1)
        );
    }

    #[test]
    fn prompts_re_ask_with_the_reason_and_never_echo_answers() {
        let (mut output, stdout, stderr) = capture(true);
        let mut input = Cursor::new(b"  \nbad\xff\nnope\n 42 \n".to_vec());
        let answer = Prompter::new(&mut input, &mut output, false)
            .ask("Value (k):", false, |value| {
                if value.trim() == "42" {
                    Ok(value.to_owned())
                } else {
                    Err(INVALID_VALUE.to_owned())
                }
            })
            .unwrap();
        assert_eq!(answer, " 42 ", "stored untrimmed");
        assert_eq!(
            stderr.text(),
            "? Value (k): > A nonempty value is required\n? Value (k): > Invalid value for configuration setting\n? Value (k): > Invalid value for configuration setting\n? Value (k): ",
            "prompts are never quiet-suppressed"
        );
        assert_eq!(stdout.text(), "");
        let (mut output, _, stderr) = capture(false);
        let mut input = Cursor::new(b"FAKE-SECRET\n".to_vec());
        let secret = Prompter::new(&mut input, &mut output, false)
            .ask("Secret (s):", true, |value| Ok(value.to_owned()))
            .unwrap();
        assert_eq!(secret, "FAKE-SECRET");
        assert_eq!(stderr.text(), "? Secret (s): [input is masked] \n");
        let (mut output, _, stderr) = capture(false);
        let mut input = Cursor::new(Vec::new());
        assert_eq!(
            Prompter::new(&mut input, &mut output, false).ask("x:", true, |v| Ok(v.to_owned())),
            Err(Cancelled)
        );
        assert_eq!(stderr.text(), "? x: [input is masked] ");
    }

    /// The prompt phase is entered before the echo change and the prompt are written,
    /// so no signal can arrive between them and the read unseen by the signal thread.
    #[test]
    fn prompts_are_written_inside_the_prompt_phase() {
        use crate::signals::SignalState;
        use std::sync::{Arc, Mutex};
        struct Probe {
            state: Arc<SignalState>,
            seen: Arc<Mutex<Vec<(String, Phase)>>>,
        }
        impl std::io::Write for Probe {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.seen.lock().unwrap().push((
                    String::from_utf8_lossy(bytes).into_owned(),
                    self.state.phase(),
                ));
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let state = Arc::new(SignalState::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let probe = Probe {
            state: Arc::clone(&state),
            seen: Arc::clone(&seen),
        };
        let mut output = Output::with_sinks(false, Box::new(std::io::sink()), Box::new(probe));
        output.attach_signals(Arc::clone(&state));
        let mut input = Cursor::new(b"FAKE-SECRET\ny\n".to_vec());
        Prompter::new(&mut input, &mut output, false)
            .ask("Secret (s):", true, |value| Ok(value.to_owned()))
            .unwrap();
        assert!(Prompter::new(&mut input, &mut output, false).confirm("Delete tenant dev?"));
        assert_eq!(state.phase(), Phase::Normal, "left again afterwards");
        let seen = seen.lock().unwrap().clone();
        let phase_of = |text: &str| {
            seen.iter()
                .find(|(written, _)| written.contains(text))
                .map(|(_, phase)| *phase)
        };
        assert_eq!(
            phase_of("? Secret (s): [input is masked] "),
            Some(Phase::Prompt)
        );
        assert_eq!(phase_of("? Delete tenant dev? (y/N) "), Some(Phase::Prompt));
    }

    #[test]
    fn confirmation_accepts_only_y_and_yes() {
        for (answer, confirmed) in [
            (&b"y\n"[..], true),
            (b"yes\n", true),
            (b"Y\n", true),
            (b" YeS \n", true),
            (b"\n", false),
            (b"n\n", false),
            (b"yolo\n", false),
            (b"", false),
        ] {
            let (mut output, _, stderr) = capture(false);
            let mut input = Cursor::new(answer.to_vec());
            assert_eq!(
                Prompter::new(&mut input, &mut output, false).confirm("Delete tenant dev?"),
                confirmed,
                "{answer:?}"
            );
            assert!(stderr.text().starts_with("? Delete tenant dev? (y/N) "));
        }
        assert!(
            Terminals {
                stdin: true,
                stderr: true
            }
            .interactive()
        );
        assert!(
            !Terminals {
                stdin: true,
                stderr: false
            }
            .interactive()
        );
        assert!(
            !Terminals {
                stdin: false,
                stderr: true
            }
            .interactive()
        );
    }
}
