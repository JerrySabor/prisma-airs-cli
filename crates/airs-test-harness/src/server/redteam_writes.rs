//! The red team write routes (DESIGN §10 M6a, step 2): every non-GET red team request,
//! answered over the per-server [`RedTeamData`] so a later read sees the change. Each
//! route validates the body it needs (`400` for a malformed one) and answers the shape
//! both SDKs' response schemas accept. Tests count the requests per route
//! (`FixtureServer::rt_requests`) to prove a write was sent exactly once.

use serde_json::{Map, Value, json};

use super::plan::Planned;
use super::record::RecordedRequest;
use super::redteam::{RedTeamData, Rt, plane_of, segments};
use crate::fixtures::{redteam as fx, uuid};

/// The token `registry-credentials` mints (not a fixture marker: json prints it, D139).
pub const REGISTRY_TOKEN: &str = "FAKE-REGISTRY-TOKEN-0123456789abcdefghij";
/// Its expiry.
pub const REGISTRY_EXPIRY: &str = "2026-10-18T00:00:00Z";
/// The token preview `targets validate-auth` answers (a marker: never printed, D140).
pub fn validate_auth_token_preview() -> String {
    fx::secret(30)
}

fn bad_request(what: &str) -> Planned {
    Planned::json(
        422,
        &json!({"detail": [{"msg": format!("invalid {what}")}]}),
    )
}

fn not_found(what: &str) -> Planned {
    Planned::json(404, &json!({"message": format!("{what} not found")}))
}

fn ok(message: &str) -> Value {
    json!({"message": message, "status": 200})
}

/// The `GET` of a scan the write route created: the next queued patch, else completed.
pub(crate) fn poll_created(data: &mut RedTeamData, id: &str) -> Planned {
    let patch = data.scan_polls.pop_front();
    let Some(job) = data
        .scans
        .iter_mut()
        .find(|job| job.get("uuid").and_then(Value::as_str) == Some(id))
    else {
        return not_found("Job");
    };
    let aborted = job.get("status").and_then(Value::as_str) == Some("ABORTED");
    match patch {
        // An aborted scan stays aborted.
        Some(Value::Object(_)) if aborted => {}
        Some(Value::Object(patch)) => {
            if let Value::Object(map) = job {
                for (key, value) in patch {
                    map.insert(key, value);
                }
            }
        }
        _ => {
            if job.get("status").and_then(Value::as_str) != Some("ABORTED") {
                job["status"] = json!("COMPLETED");
                job["completed"] = job.get("total").cloned().unwrap_or(json!(40));
            }
        }
    }
    Planned::json(200, job)
}

fn object(body: &Value) -> Map<String, Value> {
    body.as_object().cloned().unwrap_or_default()
}

fn string<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str)
}

fn position(rows: &[Value], key: &str, id: &str) -> Option<usize> {
    rows.iter()
        .position(|row| row.get(key).and_then(Value::as_str) == Some(id))
}

/// The served adapter variables: a `SECRET` value is masked (`is_redacted`; a `null`
/// keeps the stored secret upstream, which is served masked too).
fn served_variables(variables: &Value) -> Value {
    let items = variables
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|variable| {
            let key = string(&variable, "key").unwrap_or_default().to_owned();
            let kind = string(&variable, "type").unwrap_or("VAR").to_owned();
            if kind == "SECRET" {
                json!({"key": key, "value": "**********", "type": "SECRET", "is_redacted": true})
            } else {
                json!({"key": key, "value": variable.get("value").cloned().unwrap_or(Value::Null), "type": kind})
            }
        })
        .collect();
    Value::Array(items)
}

pub(crate) fn answer(data: &mut RedTeamData, route: Rt, request: &RecordedRequest) -> Planned {
    let body: Value = if request.body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) if route == Rt::PromptUpload => Value::Null,
            Err(_) => return bad_request("JSON body"),
        }
    };
    let segments = plane_of(&request.path)
        .map(|(_, rest)| segments(rest))
        .unwrap_or_default();
    let segment = |index: usize| segments.get(index).cloned().unwrap_or_default();
    match route {
        Rt::ScanCreate => {
            let (Some(name), Some(target), Some(kind)) = (
                string(&body, "name"),
                body.get("target").and_then(|t| string(t, "uuid")),
                string(&body, "job_type"),
            ) else {
                return bad_request("scan");
            };
            data.created += 1;
            let id = uuid(180 + data.created);
            let mut reference = fx::target_reference();
            reference["uuid"] = json!(target);
            let job = json!({
                "uuid": id,
                "tsg_id": fx::TSG,
                "name": name,
                "target": reference,
                "job_type": kind,
                "job_metadata": body.get("job_metadata").cloned().unwrap_or(json!({})),
                "target_id": target,
                "target_type": "APPLICATION",
                "total": 40,
                "completed": 0,
                "status": "QUEUED",
                "created_at": "2026-10-17T12:00:00Z"
            });
            data.scans.insert(0, job.clone());
            data.created_scans.push(id);
            Planned::json(200, &job)
        }
        Rt::ScanAbort => {
            let id = segment(2);
            match position(&data.scans, "uuid", &id) {
                Some(index) => {
                    data.scans[index]["status"] = json!("ABORTED");
                    Planned::json(200, &json!({"job_id": id, "message": "Job aborted"}))
                }
                None => not_found("Job"),
            }
        }
        Rt::EulaAccept => {
            let current = string(&data.eula_content, "content").unwrap_or_default();
            if string(&body, "eula_content") != Some(current) {
                return bad_request("EULA content");
            }
            let status = json!({
                "uuid": uuid(700),
                "is_accepted": true,
                // A fixed time, so two runs print the same bytes (the request carries the
                // client's clock).
                "accepted_at": "2026-10-17T12:00:00.000Z",
                "accepted_by_user_id": "u@example.com"
            });
            data.eula_status = status.clone();
            Planned::json(200, &status)
        }
        Rt::RegistryCredentials => Planned::json(
            200,
            &json!({"token": REGISTRY_TOKEN, "expiry": REGISTRY_EXPIRY}),
        ),
        Rt::InstanceCreate | Rt::InstanceUpdate => {
            let Some(tenant) = string(&body, "tenant_id").map(str::to_owned) else {
                return bad_request("instance");
            };
            let instance = json!({
                "tsg_id": string(&body, "tsg_id").unwrap_or_default(),
                "tenant_id": tenant,
                "app_id": string(&body, "app_id").unwrap_or_default(),
                "region": string(&body, "region").unwrap_or_default(),
            });
            if route == Rt::InstanceUpdate {
                let Some(index) = position(&data.instances, "tenant_id", &segment(2)) else {
                    return not_found("Instance");
                };
                data.instances[index] = instance.clone();
            } else {
                data.instances.push(instance.clone());
            }
            Planned::json(
                200,
                &json!({
                    "tsg_id": instance["tsg_id"], "tenant_id": instance["tenant_id"],
                    "app_id": instance["app_id"], "is_success": true
                }),
            )
        }
        Rt::InstanceDelete => {
            let id = segment(2);
            let Some(index) = position(&data.instances, "tenant_id", &id) else {
                return not_found("Instance");
            };
            let removed = data.instances.remove(index);
            Planned::json(
                200,
                &json!({"tsg_id": removed["tsg_id"], "tenant_id": id, "is_success": true}),
            )
        }
        Rt::DevicesCreate | Rt::DevicesUpdate | Rt::DevicesDelete => {
            if position(&data.instances, "tenant_id", &segment(2)).is_none() {
                return not_found("Instance");
            }
            let serials: Vec<String> = if route == Rt::DevicesDelete {
                request
                    .query_value("serial_numbers")
                    .unwrap_or_default()
                    .split(',')
                    .map(str::to_owned)
                    .collect()
            } else {
                body.get("devices")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|device| string(device, "serial_number").map(str::to_owned))
                    .collect()
            };
            let devices: Vec<Value> = serials
                .iter()
                .map(|serial| json!({"status": "SUCCESS", "serial_number": serial}))
                .collect();
            Planned::json(200, &json!({"devices": devices, "status": "SUCCESS"}))
        }
        Rt::PromptSetCreate => {
            let Some(name) = string(&body, "name") else {
                return bad_request("prompt set");
            };
            data.created += 1;
            let mut set = fx::prompt_set(80 + data.created, name, true);
            set["uuid"] = json!(uuid(380 + data.created));
            match body.get("description") {
                Some(description) => set["description"] = description.clone(),
                None => {
                    if let Value::Object(map) = &mut set {
                        map.remove("description");
                    }
                }
            }
            data.prompt_sets.push(set.clone());
            Planned::json(200, &set)
        }
        Rt::PromptSetUpdate | Rt::PromptSetArchive => {
            let Some(index) = position(&data.prompt_sets, "uuid", &segment(3)) else {
                return not_found("Prompt set");
            };
            let set = &mut data.prompt_sets[index];
            for (key, value) in object(&body) {
                set[key.as_str()] = value;
            }
            Planned::json(200, set)
        }
        Rt::PromptUpload => {
            let id = request.query_value("prompt_set_uuid").unwrap_or_default();
            if position(&data.prompt_sets, "uuid", id).is_none() {
                return not_found("Prompt set");
            }
            let content_type = request.header("content-type").unwrap_or_default();
            if !content_type.starts_with("multipart/form-data") {
                return bad_request("upload");
            }
            Planned::json(200, &ok("Prompts uploaded successfully"))
        }
        Rt::PromptCreate => {
            let (Some(text), Some(set)) = (string(&body, "prompt"), string(&body, "prompt_set_id"))
            else {
                return bad_request("prompt");
            };
            if position(&data.prompt_sets, "uuid", set).is_none() {
                return not_found("Prompt set");
            }
            data.created += 1;
            let mut prompt = fx::prompt(80 + data.created, 1, text, string(&body, "goal"), true);
            prompt["uuid"] = json!(uuid(480 + data.created));
            prompt["prompt_set_id"] = json!(set);
            data.prompts.push(prompt.clone());
            Planned::json(200, &prompt)
        }
        Rt::PromptUpdate | Rt::PromptDelete => {
            let (set, id) = (segment(3), segment(5));
            let Some(index) = data.prompts.iter().position(|prompt| {
                string(prompt, "uuid") == Some(id.as_str())
                    && string(prompt, "prompt_set_id") == Some(set.as_str())
            }) else {
                return not_found("Prompt");
            };
            if route == Rt::PromptDelete {
                data.prompts.remove(index);
                return Planned::json(200, &ok("Prompt deleted"));
            }
            let prompt = &mut data.prompts[index];
            for (key, value) in object(&body) {
                prompt[key.as_str()] = value;
            }
            Planned::json(200, prompt)
        }
        Rt::PropertyCreate => {
            let Some(name) = string(&body, "name") else {
                return bad_request("property");
            };
            if let Some(Value::Array(names)) = data.property_names.get_mut("data") {
                names.push(json!(name));
            }
            if data.empty_property_create {
                return Planned::status(200);
            }
            Planned::json(200, &ok("Property name created successfully"))
        }
        Rt::PropertyValueCreate => {
            let (Some(name), Some(value)) = (
                string(&body, "property_name"),
                string(&body, "property_value"),
            ) else {
                return bad_request("property value");
            };
            data.property_values
                .entry(name.to_owned())
                .or_default()
                .push(value.to_owned());
            Planned::json(200, &ok("Property value created successfully"))
        }
        Rt::TargetCreate | Rt::TargetProbe => {
            let Some(name) = string(&body, "name") else {
                return bad_request("target");
            };
            let validate = request.query_value("validate") == Some("true");
            let id = if route == Rt::TargetCreate {
                data.created += 1;
                uuid(280 + data.created)
            } else {
                uuid(299)
            };
            let mut target = json!({
                "uuid": id,
                "tsg_id": fx::TSG,
                "name": name,
                "status": "ACTIVE",
                "active": true,
                "validated": validate,
                "created_at": fx::CREATED,
                "updated_at": fx::UPDATED,
            });
            for (key, value) in object(&body) {
                target[key.as_str()] = value;
            }
            if route == Rt::TargetProbe {
                target["target_metadata"] = json!({"multi_turn": false, "multi_turn_error_message": "noise", "rate_limit": 10});
                return Planned::json(200, &target);
            }
            data.targets.push(target.clone());
            Planned::json(200, &target)
        }
        Rt::TargetUpdate | Rt::TargetProfileUpdate => {
            let Some(index) = position(&data.targets, "uuid", &segment(2)) else {
                return not_found("Target");
            };
            if route == Rt::TargetUpdate && string(&body, "name").is_none() {
                return bad_request("target");
            }
            let target = &mut data.targets[index];
            for (key, value) in object(&body) {
                target[key.as_str()] = value;
            }
            if route == Rt::TargetUpdate {
                target["validated"] = json!(request.query_value("validate") == Some("true"));
            }
            Planned::json(200, target)
        }
        Rt::TargetDelete => {
            let Some(index) = position(&data.targets, "uuid", &segment(2)) else {
                return not_found("Target");
            };
            data.targets.remove(index);
            Planned::json(200, &ok("Target deleted"))
        }
        Rt::TargetValidateAuth => {
            if string(&body, "auth_type").is_none()
                || !body.get("auth_config").is_some_and(Value::is_object)
            {
                return bad_request("auth validation");
            }
            Planned::json(
                200,
                &json!({"validated": true, "token_preview": validate_auth_token_preview(), "expires_in": 3600}),
            )
        }
        Rt::AdapterCreate => {
            let (Some(name), Some(script)) = (string(&body, "name"), string(&body, "script_b64"))
            else {
                return bad_request("adapter");
            };
            if string(&body, "prompt").is_none() {
                return bad_request("adapter");
            }
            let validate = request.query_value("validate") != Some("false");
            data.created += 1;
            let mut adapter = json!({
                "uuid": uuid(580 + data.created),
                "tsg_id": fx::TSG,
                "name": name,
                "script_b64": script,
                "status": if validate { "ACTIVE" } else { "DRAFT" },
                "variables": served_variables(body.get("variables").unwrap_or(&json!([]))),
                "target_count": 0,
                "created_at": fx::CREATED,
                "updated_at": fx::UPDATED,
            });
            for key in ["description", "network_broker_channel_uuid"] {
                if let Some(value) = body.get(key) {
                    adapter[key] = value.clone();
                }
            }
            data.adapters.push(adapter.clone());
            Planned::json(200, &adapter)
        }
        Rt::AdapterUpdate => {
            let Some(index) = position(&data.adapters, "uuid", &segment(2)) else {
                return not_found("Adapter");
            };
            let (Some(name), Some(script)) = (string(&body, "name"), string(&body, "script_b64"))
            else {
                return bad_request("adapter");
            };
            let adapter = &mut data.adapters[index];
            adapter["name"] = json!(name);
            adapter["script_b64"] = json!(script);
            adapter["variables"] = served_variables(body.get("variables").unwrap_or(&json!([])));
            for key in ["description", "network_broker_channel_uuid"] {
                match body.get(key) {
                    Some(value) => adapter[key] = value.clone(),
                    None => {
                        if let Value::Object(map) = adapter {
                            map.remove(key);
                        }
                    }
                }
            }
            Planned::json(200, adapter)
        }
        Rt::AdapterDelete => {
            let Some(index) = position(&data.adapters, "uuid", &segment(2)) else {
                return not_found("Adapter");
            };
            data.adapters.remove(index);
            Planned::json(200, &ok("Adapter deleted"))
        }
        Rt::AdapterValidate => {
            if string(&body, "script_b64").is_none() || string(&body, "prompt").is_none() {
                return bad_request("adapter validation");
            }
            // The script echoes every variable value it was given (a script that
            // prints its secrets).
            let echoed: Vec<String> = body
                .get("variables")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|variable| {
                    format!(
                        "{}={}",
                        string(variable, "key").unwrap_or_default(),
                        string(variable, "value").unwrap_or("null")
                    )
                })
                .collect();
            let validated = !data.adapter_validation_fails;
            Planned::json(
                200,
                &json!({
                    "validated": validated,
                    "stdout": format!("prompt={}\nvars: {}", string(&body, "prompt").unwrap_or_default(), echoed.join(",")),
                    "stderr": if validated { Value::Null } else { json!("boom") },
                    "traceback": if validated { Value::Null } else { json!("Traceback (most recent call last):\n  KeyError") },
                }),
            )
        }
        Rt::ChannelCreate => {
            let Some(name) = string(&body, "name") else {
                return bad_request("channel");
            };
            data.created += 1;
            let mut channel = fx::channel(80 + data.created, name, "DRAFT", 0);
            channel["uuid"] = json!(uuid(680 + data.created));
            match body.get("description") {
                Some(description) => channel["description"] = description.clone(),
                None => channel["description"] = Value::Null,
            }
            data.channels.push(channel.clone());
            Planned::json(200, &channel)
        }
        Rt::ChannelUpdate => {
            let Some(index) = position(&data.channels, "uuid", &segment(2)) else {
                return not_found("Channel");
            };
            let channel = &mut data.channels[index];
            for (key, value) in object(&body) {
                channel[key.as_str()] = value;
            }
            Planned::json(200, channel)
        }
        _ => Planned::empty_json(404),
    }
}
