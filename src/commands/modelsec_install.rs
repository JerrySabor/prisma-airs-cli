//! `model-security pypi-auth` and `model-security install` (DESIGN §17.12–§17.14,
//! D194–D201).
//!
//! The PyPI index URL carries a credential: it joins the invocation's `SecretSet` as soon
//! as the response is decoded, it is printed only in its withheld form, and the only
//! channel for the full URL is a new 0600 `--url-file`. `install` hands the credential to
//! `uv add` through its environment only, never through argv.

use super::Invocation;
use crate::bulk::StateDir;
use crate::clients::SINGLE_REQUEST_BUDGET;
use crate::error::{CliError, Failure, InterruptContext};
use crate::files::{self, Published, shown};
use crate::modelsec::fetch::{self, Managed, Source, UV_VERSION};
use crate::modelsec::pypi;
use crate::modelsec::uv::{self, Ended};
use crate::modelsec::{self, views};
use crate::output::{Format, terminal_safe};
use crate::render::{pretty, table};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A validated `install` (§17.13 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPlan {
    pub extras: String,
    pub dir: OsString,
    pub dry_run: bool,
    pub fetch_uv: bool,
    /// The debug-build `--fetch-uv` test hook (choice 36), checked during planning.
    pub hook: Option<(String, String)>,
}

/// Interrupted errors take `context` (the phase the command is in).
fn within(context: &InterruptContext) -> impl Fn(CliError) -> CliError + '_ {
    move |error| match error {
        CliError::Interrupted(_) => CliError::Interrupted(context.clone()),
        other => other,
    }
}

fn context(text: String) -> InterruptContext {
    InterruptContext::Context(text)
}

/// The `--url-file` checks before the tenant (§17.12 "Arguments"): nothing may exist at
/// the path (`lstat`), and its directory must exist.
fn check_url_file(path: &Path) -> Result<(), CliError> {
    files::check_new(path, "--url-file")
}

/// `GET <mgmt>/v1/pypi/authenticate` (a read with the SDK read retries, choice 24), the
/// credential registered before anything else uses the answer.
async fn pypi_url(invocation: &mut Invocation) -> Result<(String, String), CliError> {
    let options = modelsec::options(SINGLE_REQUEST_BUDGET)?;
    let connected = invocation.connect_model_security(None).await?;
    let auth = connected
        .client
        .get_pypi_auth(Some(&options))
        .await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    pypi::register(&auth.url, &invocation.secrets);
    Ok((auth.url, auth.expires_at))
}

/// `model-security pypi-auth [--url-file <path>]` (§17.12, D194).
pub async fn pypi_auth(
    invocation: &mut Invocation,
    url_file: Option<&OsString>,
    format: Option<Format>,
) -> Result<(), CliError> {
    let url_file = url_file.map(PathBuf::from);
    if let Some(path) = &url_file {
        check_url_file(path)?;
    }
    let (url, expires) = pypi_url(invocation).await?;
    let format = format.unwrap_or(Format::Pretty);
    if let Some(path) = &url_file {
        if pypi::check(&url).is_none() {
            return Err(CliError::operational(pypi::UNUSABLE_FOR_FILE));
        }
        if invocation.output.pending_signal().is_some() {
            return Err(CliError::Interrupted(InterruptContext::NoDataWritten));
        }
        let published = files::publish_new(path, format!("{url}\n").as_bytes(), "--url-file")?;
        let typed = terminal_safe(&shown(path.as_os_str())).into_owned();
        invocation.interrupt = Some(context(format!("{typed} was written")));
        if published == Published::DirectoryNotSynced {
            invocation
                .output
                .warning(&crate::store::atomic::dir_sync_warning(path));
        }
        invocation.output.success(&format!(
            "Wrote the PyPI index URL, credential included, to {typed} (mode 0600)."
        ));
    }
    let form = pypi::withheld_form(&url, &invocation.secrets);
    let expires = if invocation.secrets.carried_by(&expires) {
        crate::error::WITHHELD.to_owned()
    } else {
        terminal_safe(&expires).into_owned()
    };
    let out = &mut invocation.output;
    match format {
        Format::Json => out.json(&serde_json::json!({"url": form, "expiresAt": expires}))?,
        Format::Table => out.data_line(&table::key_value_table(vec![
            ("url".to_owned(), form),
            ("expiresAt".to_owned(), expires),
        ])),
        Format::Pretty => {
            views::banner(out);
            pretty::section(out, "PyPI Authentication");
            pretty::key_value(out, &[("URL", form), ("Expires", expires)]);
        }
    }
    if url_file.is_none() {
        out.status(
            "The index credential is withheld; pass --url-file <path> to save the full URL in a new private file.",
        );
    }
    Ok(())
}

/// The uv to run, resolved before the tenant (§17.13 step 4, §17.14).
struct Resolved {
    uv: PathBuf,
    /// `# would download …` for a dry run whose managed copy is not there yet.
    download_note: Option<String>,
}

fn tools_dir() -> Result<PathBuf, CliError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(std::env::home_dir);
    fetch::tools_dir_path(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        home.as_deref(),
    )
}

/// The `--fetch-uv` copy: verified, or downloaded and installed (not on a dry run).
async fn managed_uv(invocation: &mut Invocation, plan: &InstallPlan) -> Result<Resolved, CliError> {
    let source = Source::for_host(plan.hook.as_ref())?;
    let tools_path = tools_dir()?;
    let exists = !matches!(
        std::fs::symlink_metadata(&tools_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    let tools = if exists {
        Some(StateDir::open(&tools_path)?)
    } else if plan.dry_run {
        None
    } else {
        Some(StateDir::ensure(&tools_path)?)
    };
    let managed = match &tools {
        Some(tools) => fetch::verify_managed(tools, &source)?,
        None => Managed::Absent,
    };
    let nothing = uv::nothing_installed();
    if let Managed::Verified(path) = managed {
        let version = uv::check_version(
            &path,
            Some(fetch::UV_VERSION_PARTS),
            &invocation.output,
            &nothing,
        )?;
        invocation
            .output
            .status(&format!("Using uv {version} ({})", shown(path.as_os_str())));
        return Ok(Resolved {
            uv: path,
            download_note: None,
        });
    }
    let base = tools
        .as_ref()
        .map_or_else(|| tools_path.clone(), |tools| tools.path().to_path_buf());
    let managed_dir = base.join(fetch::managed_name(source.target));
    if plan.dry_run {
        return Ok(Resolved {
            uv: managed_dir.join("uv"),
            download_note: Some(
                terminal_safe(&format!(
                    "  # would download uv {UV_VERSION} ({}, sha256 {}) into {}",
                    fetch::archive_name(source.target),
                    source.sha256,
                    shown(base.as_os_str())
                ))
                .into_owned(),
            ),
        });
    }
    let Some(tools) = tools else {
        return Err(CliError::Interrupted(nothing));
    };
    let not_installed = fetch::not_installed();
    invocation.interrupt = Some(not_installed.clone());
    invocation.output.status(&format!(
        "→ Downloading uv {UV_VERSION} ({})",
        source.target
    ));
    let session = invocation.session.clone();
    let body = tokio::select! {
        body = fetch::download(&source) => body?,
        () = session.cancelled() => return Err(CliError::Interrupted(not_installed)),
    };
    fetch::verify_archive(&body, &source.sha256)?;
    let tar = fetch::gunzip(&body)?;
    let binary = fetch::extract_uv(&tar, source.target)?;
    let signals = invocation.output.signals();
    let interrupted = || {
        signals
            .as_ref()
            .is_some_and(|signals| signals.code().is_some())
    };
    let path = fetch::install(&tools, &source, &binary, &interrupted)?;
    let shown_dir = terminal_safe(&shown(managed_dir.as_os_str())).into_owned();
    let installed = context(format!(
        "uv {UV_VERSION} was installed in {shown_dir}; nothing else was installed"
    ));
    invocation.interrupt = Some(installed.clone());
    let version = uv::check_version(
        &path,
        Some(fetch::UV_VERSION_PARTS),
        &invocation.output,
        &installed,
    )?;
    invocation
        .output
        .success(&format!("Installed uv {UV_VERSION} in {shown_dir}"));
    invocation
        .output
        .status(&format!("Using uv {version} ({})", shown(path.as_os_str())));
    Ok(Resolved {
        uv: path,
        download_note: None,
    })
}

/// The first uv on `PATH` (the managed copy is not used without `--fetch-uv`, choice 28).
fn path_uv(invocation: &mut Invocation) -> Result<Resolved, CliError> {
    let Some(path) = uv::find_on_path(std::env::var_os("PATH").as_deref()) else {
        let tools = tools_dir().unwrap_or_else(|_| PathBuf::from("the airs-cli tools directory"));
        return Err(uv::not_found(&tools));
    };
    let version = uv::check_version(&path, None, &invocation.output, &uv::nothing_installed())?;
    invocation
        .output
        .status(&format!("Using uv {version} ({})", shown(path.as_os_str())));
    Ok(Resolved {
        uv: path,
        download_note: None,
    })
}

/// `model-security install` (§17.13).
pub async fn install(invocation: &mut Invocation, plan: &InstallPlan) -> Result<(), CliError> {
    let typed = terminal_safe(&shown(&plan.dir)).into_owned();
    // Step 3: --dir (D198).
    let dir = uv::preflight_dir(&plan.dir, invocation.env.cwd.as_deref())?;
    // Step 4: uv (D195).
    let resolved = if plan.fetch_uv {
        managed_uv(invocation, plan).await?
    } else {
        path_uv(invocation)?
    };
    let nothing = invocation
        .interrupt
        .clone()
        .unwrap_or_else(uv::nothing_installed);
    // Step 5: the tenant and the PyPI auth URL (a dry run sends it too, choice 31).
    let (url, _) = pypi_url(invocation).await.map_err(within(&nothing))?;
    // Step 6: the index check (D201).
    let index =
        pypi::check(&url).ok_or_else(|| CliError::operational(pypi::UNUSABLE_FOR_INSTALL))?;
    let quiet = invocation.output.quiet();
    let steps = uv::steps(&dir, &index.index, &plan.extras, quiet);
    // Step 7: the dry run (D197): shell text in every format, data under --quiet.
    if plan.dry_run {
        let out = &mut invocation.output;
        views::banner(out);
        pretty::section(out, "Commands that would be executed");
        if let Some(note) = &resolved.download_note {
            out.data_line(note);
        }
        for step in &steps {
            out.data_line(&uv::plan_line(&resolved.uv, step));
        }
        return Ok(());
    }
    if invocation.output.pending_signal().is_some() {
        return Err(CliError::Interrupted(nothing));
    }
    // Step 8: the directory, created exclusively.
    match std::fs::DirBuilder::new().create(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(CliError::operational(format!(
                "{typed} already exists; choose another --dir"
            )));
        }
        Err(_) => {
            return Err(CliError::operational(format!(
                "Cannot create {typed}; check the permissions of its parent directory"
            )));
        }
    }
    // Steps 9 and 10: the children (D196, D199, D200).
    for step in &steps {
        let name = step.label.trim_start_matches("uv ");
        let stopped = context(format!("uv {name} was stopped; {typed} may be incomplete"));
        invocation.interrupt = Some(stopped.clone());
        invocation.output.status(&format!("→ {}", step.label));
        let ended = uv::run_step(
            &mut invocation.output,
            &resolved.uv,
            step,
            &index,
            &invocation.secrets,
        )?;
        let failure = match ended {
            Ended::Exited(0) => continue,
            Ended::Interrupted => return Err(CliError::Interrupted(stopped)),
            Ended::Exited(code) => format!("{} failed with exit code {code}", step.label),
            Ended::Signalled(signal) => {
                format!("{} was terminated by signal {signal}", step.label)
            }
        };
        let details = if step.credential {
            vec![
                format!(
                    "{typed} was created, but model-security-client was not added. Remove {typed} and re-run, or add it with uv yourself."
                ),
                uv::NO_BUILD_HINT.to_owned(),
            ]
        } else {
            Vec::new()
        };
        return Err(CliError::Operational(Failure {
            message: failure,
            status: None,
            details,
        }));
    }
    // Step 11: the persistence check (D196).
    invocation.interrupt = Some(context(format!(
        "model-security-client was installed in {typed}"
    )));
    uv::persistence_check(&dir, &index)?;
    // Step 12: success (D199: stderr, quiet-suppressed; stdout stays empty).
    let out = &mut invocation.output;
    out.success("model-security-client installed successfully.");
    out.status(&format!(
        "Activate:  cd {}",
        terminal_safe(&uv::shell_word(&dir.to_string_lossy()))
    ));
    out.status(
        "Later uv commands that use the AIRS index need the credential again: set UV_INDEX_AIRS_MODEL_SECURITY_USERNAME and UV_INDEX_AIRS_MODEL_SECURITY_PASSWORD from the URL that 'airs model-security pypi-auth --url-file <file>' saves.",
    );
    Ok(())
}
