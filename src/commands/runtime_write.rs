//! The M6d wrapper of the shared write machinery (DESIGN §18.3): the tenant and client of
//! a write without any request (a confirmation may follow), the token, the format a write
//! prints its record in (D223) and the one-attempt send with the plain contexts (D95). The
//! D81 gate and prompt (D206) and the request-body validation (D116) are
//! `write_common`'s, re-exported here; every attempt's options are
//! `runtime::request_options(SINGLE_REQUEST_BUDGET)` (G27).

use super::Invocation;
use super::write_common::{self as wc, Contexts};
pub use super::write_common::{body, confirm, gate_on_terminals as gate};
use crate::clients::{ManagementClients, Planes, TOKEN_BUDGET};
use crate::error::CliError;
use crate::output::Format;
use crate::writes::Change;

/// The tenant, the credential check and the management client of a write, without any
/// request (a confirmation may follow, §18.3). An interruption reports `nothing was
/// changed`.
pub fn prepare(invocation: &mut Invocation) -> Result<ManagementClients, CliError> {
    invocation
        .connect_runtime(Planes::default())
        .map(|connected| connected.clients)
        .map_err(super::nothing_changed)
}

/// The OAuth token of a write (the SDK's token budget); an interruption changed nothing.
pub async fn authenticate(clients: &ManagementClients) -> Result<(), CliError> {
    clients
        .authenticate(None, TOKEN_BUDGET)
        .await
        .map_err(super::nothing_changed)
}

/// The format a write prints its record in: the explicit `--output`, else `pretty` (the
/// tenant's `defaultOutput` does not apply to writes, choice 18).
pub fn format(explicit: Option<Format>) -> Format {
    explicit.unwrap_or(Format::Pretty)
}

/// One M6d write (D95): one attempt with the single 401 replay; an unknown or unreadable
/// outcome adds its outcome line and `hint`; an interruption before the write reports
/// `nothing was changed`, after it `the change may already have been applied (outcome
/// unknown)`.
pub async fn send<T>(
    invocation: &Invocation,
    change: Change,
    hint: &str,
    call: impl AsyncFnMut() -> scm::Result<T>,
) -> Result<T, CliError> {
    wc::send(invocation, change, Some(hint), &Contexts::plain(), call).await
}
