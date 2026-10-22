//! Logical batches, SDK chunks within the request-body budget, and receipt grouping
//! (DESIGN §14.5).

use super::CHUNK_SIZE;
use crate::error::CliError;
use scm::airs::scan::Content;
use scm::airs::scan::models::{AiProfile, AsyncScanObject, FiniteNumber, Optional, ScanRequest};

/// The SDK request limit (`Limits::default().max_request_bytes`) minus 64 KiB of
/// headroom: the largest body a chunk may serialise to.
pub fn body_budget() -> usize {
    scm::Limits::default().max_request_bytes - 64 * 1024
}

/// The logical batches over `count` items: `[start, end)` ranges of `batch_size`.
pub fn logical_batches(count: usize, batch_size: u64) -> Vec<(usize, usize)> {
    let size = usize::try_from(batch_size).unwrap_or(usize::MAX).max(1);
    (0..count)
        .step_by(size)
        .map(|start| (start, start.saturating_add(size).min(count)))
        .collect()
}

/// `ceil(count / batch_size)`.
pub fn batch_count(count: usize, batch_size: u64) -> u64 {
    (count as u64).div_ceil(batch_size.max(1))
}

fn local_failure() -> CliError {
    CliError::operational("AISEC_USER_REQUEST_PAYLOAD_ERROR:Validation error")
}

/// One scan object: `{"req_id": index, "scan_req": {"ai_profile": {"profile_name"},
/// "contents": [{"prompt"}], "session_id"?}}` (`session_id` omitted when empty).
pub fn scan_object(
    index: u64,
    prompt: &str,
    profile: &str,
    session: &str,
) -> Result<AsyncScanObject, CliError> {
    let ai_profile = AiProfile::builder()
        .profile_name(Optional::Value(profile.to_owned()))
        .build()
        .map_err(|_| local_failure())?;
    let content = Content::builder()
        .prompt(prompt.to_owned())
        .build()
        .map_err(|_| local_failure())?
        .into_json();
    let mut request = ScanRequest::builder()
        .ai_profile(ai_profile)
        .contents(vec![content]);
    if !session.is_empty() {
        request = request.session_id(Optional::Value(session.to_owned()));
    }
    let request = request.build().map_err(|_| local_failure())?;
    AsyncScanObject::builder()
        .req_id(FiniteNumber::from(index))
        .scan_req(request)
        .build()
        .map_err(|_| local_failure())
}

/// The serialised size of one object.
fn object_size(object: &AsyncScanObject) -> Result<usize, CliError> {
    serde_json::to_vec(object)
        .map(|bytes| bytes.len())
        .map_err(|_| local_failure())
}

/// `AISEC_USER_REQUEST_PAYLOAD_ERROR:prompt exceeds the request size limit of <budget>
/// bytes once JSON-encoded` with the detail line `Prompt index <i>` (D132).
fn encoded_too_large(index: u64, budget: usize) -> CliError {
    CliError::Operational(crate::error::Failure {
        message: format!(
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:prompt exceeds the request size limit of {budget} bytes once JSON-encoded"
        ),
        status: None,
        details: vec![format!("Prompt index {index}")],
    })
}

/// The planning check of D132: every prompt's scan object, alone in a request body
/// (`[` + object + `]`), must fit `budget`. A prompt within the 2 MiB content limit can
/// still serialise to about 12 MiB (serde escapes each C0 control other than `\t`,
/// `\n`, `\r`, `\b` and `\f` as `\u00XX`), which the SDK would refuse on every attempt.
/// The first such prompt is reported.
pub fn check_encoded(
    prompts: &[String],
    profile: &str,
    session: &str,
    budget: usize,
) -> Result<(), CliError> {
    for (index, prompt) in prompts.iter().enumerate() {
        let index = index as u64;
        let object = object_size(&scan_object(index, prompt, profile, session)?)?;
        if object.saturating_add(2) > budget {
            return Err(encoded_too_large(index, budget));
        }
    }
    Ok(())
}

/// Cut `items` (input index and prompt, in submission order) into chunks of at most
/// [`CHUNK_SIZE`] whose serialised array stays within `budget` bytes. A chunk always
/// holds at least one item; an item that cannot fit a body on its own is refused (the
/// D132 error), so no chunk is ever built that the SDK would refuse.
pub fn chunks(
    items: &[(u64, &str)],
    profile: &str,
    session: &str,
    budget: usize,
) -> Result<Vec<Vec<u64>>, CliError> {
    let mut chunks: Vec<Vec<u64>> = Vec::new();
    let mut current: Vec<u64> = Vec::new();
    // `[` + `]`, plus one comma between objects.
    let mut size = 2usize;
    for (index, prompt) in items {
        let object = object_size(&scan_object(*index, prompt, profile, session)?)?;
        if object.saturating_add(2) > budget {
            return Err(encoded_too_large(*index, budget));
        }
        let added = object + usize::from(!current.is_empty());
        if !current.is_empty() && (current.len() == CHUNK_SIZE || size + added > budget) {
            chunks.push(std::mem::take(&mut current));
            size = 2;
        }
        size += object + usize::from(!current.is_empty());
        current.push(*index);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
}

/// The receipts of `items` (index, status, scan id) to poll: the `submitted` items
/// grouped by scan id, in the order of each scan id's lowest index (TS
/// `submittedBatches`).
pub fn receipts(items: &[(u64, super::ItemStatus, Option<&str>)]) -> Vec<String> {
    let mut order: Vec<(u64, String)> = Vec::new();
    for (index, status, scan_id) in items {
        let (super::ItemStatus::Submitted, Some(scan_id)) = (status, scan_id) else {
            continue;
        };
        match order.iter_mut().find(|(_, id)| id == scan_id) {
            Some((lowest, _)) => *lowest = (*lowest).min(*index),
            None => order.push((*index, (*scan_id).to_owned())),
        }
    }
    order.sort_by_key(|(lowest, _)| *lowest);
    order.into_iter().map(|(_, id)| id).collect()
}

#[cfg(test)]
mod tests {
    use super::super::ItemStatus;
    use super::*;

    fn indexed(prompts: &[String]) -> Vec<(u64, &str)> {
        prompts
            .iter()
            .enumerate()
            .map(|(index, prompt)| (index as u64, prompt.as_str()))
            .collect()
    }

    #[test]
    fn batches_and_chunks_follow_the_typescript_sequences() {
        // 45 prompts, size 25 → P[0..19] P[20..24] | P[25..44].
        assert_eq!(logical_batches(45, 25), [(0, 25), (25, 45)]);
        assert_eq!(batch_count(45, 25), 2);
        let prompts: Vec<String> = (0..45).map(|n| format!("p{n}")).collect();
        let first = chunks(&indexed(&prompts[..25]), "p", "s", body_budget()).unwrap();
        assert_eq!(first, [(0..20).collect::<Vec<u64>>(), (20..25).collect()]);
        assert_eq!(logical_batches(3, 2), [(0, 2), (2, 3)]);
        assert_eq!(logical_batches(7, 5), [(0, 5), (5, 7)]);
        assert_eq!(batch_count(7, 5), 2);
        assert_eq!(logical_batches(1, u64::MAX >> 11), [(0, 1)]);
        assert_eq!(batch_count(1, (1 << 53) - 1), 1);
    }

    #[test]
    fn chunks_split_to_fit_the_body_budget() {
        // Four 1 MiB prompts with a 2.5 MiB budget: two per chunk.
        let prompts: Vec<String> = (0..4)
            .map(|n| format!("{n}{}", "x".repeat(1 << 20)))
            .collect();
        let budget = (5 << 20) / 2;
        assert_eq!(
            chunks(&indexed(&prompts), "p", "s", budget).unwrap(),
            [vec![0, 1], vec![2, 3]]
        );
        // One prompt that cannot fit a body on its own is refused (D132), never sent.
        let refused = chunks(&indexed(&prompts[..1]), "p", "", 10).unwrap_err();
        let CliError::Operational(failure) = refused else {
            panic!("operational")
        };
        assert_eq!(
            failure.message,
            "AISEC_USER_REQUEST_PAYLOAD_ERROR:prompt exceeds the request size limit of 10 bytes once JSON-encoded"
        );
        assert_eq!(failure.details, ["Prompt index 0"]);
        // The exact serialised size is the limit: a body of exactly `budget` fits.
        let small: Vec<String> = vec!["a".into(), "b".into()];
        let objects: Vec<AsyncScanObject> = small
            .iter()
            .enumerate()
            .map(|(i, p)| scan_object(i as u64, p, "p", "s").unwrap())
            .collect();
        let exact = serde_json::to_vec(&objects).unwrap().len();
        assert_eq!(
            chunks(&indexed(&small), "p", "s", exact).unwrap(),
            [vec![0, 1]]
        );
        assert_eq!(
            chunks(&indexed(&small), "p", "s", exact - 1).unwrap(),
            [vec![0], vec![1]]
        );
    }

    /// 20 prompts of 2 MiB (the most the input checks allow) with the default
    /// budget: every chunk the planner builds is accepted by the SDK's request limit.
    #[test]
    fn the_sdk_accepts_every_planned_chunk() {
        let prompts: Vec<String> = (0..20)
            .map(|n| format!("{n:02}{}", "y".repeat((2 << 20) - 2)))
            .collect();
        let planned = chunks(
            &indexed(&prompts),
            "Prisma AIRS Harness",
            "s",
            body_budget(),
        )
        .unwrap();
        assert!(planned.len() > 1, "{} chunks", planned.len());
        for chunk in &planned {
            let objects: Vec<AsyncScanObject> = chunk
                .iter()
                .map(|i| {
                    scan_object(*i, &prompts[*i as usize], "Prisma AIRS Harness", "s").unwrap()
                })
                .collect();
            let size = serde_json::to_vec(&objects).unwrap().len();
            assert!(size <= scm::Limits::default().max_request_bytes, "{size}");
        }
        assert_eq!(planned.concat(), (0..20).collect::<Vec<u64>>());
    }

    /// D132: a prompt within the 2 MiB content limit whose control characters serialise
    /// as `\u00XX` (6 bytes each) is refused at planning, with its index; the escaped
    /// size, not the raw size, is what counts.
    #[test]
    fn prompts_that_cannot_fit_once_encoded_are_refused() {
        let ordinary = "a".repeat(2_000_000);
        let controls = format!("a{}b", "\u{1}".repeat(2_000_000));
        assert!(controls.len() <= 2 << 20, "within the raw content limit");
        let prompts = vec![ordinary.clone(), controls.clone()];
        let CliError::Operational(failure) =
            check_encoded(&prompts, "p", "s", body_budget()).unwrap_err()
        else {
            panic!("operational")
        };
        assert_eq!(
            failure.message,
            format!(
                "AISEC_USER_REQUEST_PAYLOAD_ERROR:prompt exceeds the request size limit of {} bytes once JSON-encoded",
                body_budget()
            )
        );
        assert_eq!(failure.details, ["Prompt index 1"]);
        check_encoded(&[ordinary], "p", "s", body_budget()).unwrap();
        // The planner refuses it too, so no chunk the SDK would refuse is ever built.
        assert!(chunks(&[(0, controls.as_str())], "p", "s", body_budget()).is_err());
    }

    #[test]
    fn the_body_omits_an_empty_session() {
        let with = serde_json::to_value(scan_object(3, "hi", "Prof", "s1").unwrap()).unwrap();
        assert_eq!(
            with,
            serde_json::json!({"req_id": 3, "scan_req": {"ai_profile": {"profile_name": "Prof"}, "contents": [{"prompt": "hi"}], "session_id": "s1"}})
        );
        let without = serde_json::to_value(scan_object(0, "hi", "Prof", "").unwrap()).unwrap();
        assert_eq!(
            without,
            serde_json::json!({"req_id": 0, "scan_req": {"ai_profile": {"profile_name": "Prof"}, "contents": [{"prompt": "hi"}]}})
        );
    }

    #[test]
    fn receipts_group_by_scan_id_in_lowest_index_order() {
        let items = [
            (0, ItemStatus::Complete, Some("a")),
            (1, ItemStatus::Submitted, Some("b")),
            (2, ItemStatus::Submitted, Some("c")),
            (3, ItemStatus::Submitted, Some("b")),
            (4, ItemStatus::Pending, None),
            (5, ItemStatus::Submitted, Some("a")),
        ];
        assert_eq!(receipts(&items), ["b", "c", "a"]);
    }
}
