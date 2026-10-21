//! `runtime deployment-profiles list|ls` (DESIGN §18.10) and the `runtime scan-logs query`
//! stub (§18.11).

use super::Invocation;
use crate::clients::{Planes, SINGLE_REQUEST_BUDGET, TOKEN_BUDGET};
use crate::error::CliError;
use crate::output::Format;
use crate::render::style::Style;
use crate::runtime::list::{rows_of, sanitize_all};
use crate::runtime::{self, views};
use scm::airs::management::DeploymentProfileListOptions;

/// `runtime deployment-profiles list|ls [--unactivated]`: one GET, no paging, no status
/// line (TS); `?unactivated=true` only with the flag.
pub async fn deployment_profiles(
    invocation: &mut Invocation,
    unactivated: bool,
    format: Option<Format>,
) -> Result<(), CliError> {
    let connected = invocation.connect_runtime(Planes::default())?;
    let format = connected.format(format);
    connected.clients.authenticate(None, TOKEN_BUDGET).await?;
    let mut query = DeploymentProfileListOptions::default();
    query.unactivated = unactivated.then_some(true);
    let response = connected
        .clients
        .management
        .deployment_profiles()
        .list(query, Some(&runtime::options(SINGLE_REQUEST_BUDGET)?))
        .await
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    let mut rows = rows_of(&response.deployment_profiles)
        .map_err(|error| invocation.management_error(&error, SINGLE_REQUEST_BUDGET))?;
    sanitize_all(&mut rows, &invocation.secrets);
    views::render_deployment_profiles(&mut invocation.output, &rows, format)
}

/// The TypeScript stub's line (`rt.ts:1089-1094`), naming the running program (D73).
pub const SCAN_LOGS_BROKEN: &str = "✗ Legacy scan-logs retrieval is broken and under refactor. Empty results do not mean no activity. Use airs runtime sessions list --interval 1 --unit day --output json, or airs runtime report.";

/// `runtime scan-logs query` (§18.11): the tenant selection is read (TS resolves the
/// format from it), no credential check, no request, the fixed line, exit 1.
pub fn scan_logs(invocation: &mut Invocation) -> Result<(), CliError> {
    invocation.load_tenant()?;
    let line = invocation.output.paint_err(Style::Red, SCAN_LOGS_BROKEN);
    invocation.output.write_stderr(&format!("  {line}\n"));
    Err(CliError::Reported(crate::error::EXIT_OPERATIONAL))
}
