//! `runtime dlp filtering-profiles replace <id>` (DESIGN §16.5): the SDK call (the flow
//! is `dlp_write::body_write`). Never live (§10).

use super::Invocation;
use super::dlp_write::send as send_write;
use super::redteam::value;
use crate::dlp::Kind;
use crate::dlp::body::{self, Write};
use crate::error::CliError;
use crate::json::OValue;
use scm::dlp::DlpClient;
use scm::dlp::models as m;

/// The one `PUT` of a filtering-profile replace.
pub async fn send(
    invocation: &mut Invocation,
    dlp: &DlpClient,
    id: &str,
    request: &serde_json::Value,
) -> Result<OValue, CliError> {
    let kind = Kind::FilteringProfile;
    let text = body::schema_text(kind, Write::Replace.method(), Some(id));
    let request = body::schema(request, m::DataFilteringProfileRequest::parse, &text, false)?;
    let profiles = dlp.data_filtering_profiles();
    let answer = send_write(
        invocation,
        kind.change("replaced"),
        None,
        false,
        async || profiles.replace(id, &request, None).await,
    )
    .await?;
    value(&answer)
}
