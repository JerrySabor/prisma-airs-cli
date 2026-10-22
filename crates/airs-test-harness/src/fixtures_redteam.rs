//! Red team wire bodies (DESIGN §10 M6a). Every body validates against the TypeScript
//! SDK's zod schemas and the Rust SDK models; keys are in schema order, so both SDKs
//! re-serialise them in the same order.
//!
//! Credential-bearing paths carry the markers of [`secret`]: the runner's leak check
//! treats every marker as a secret for airs-cli-rs runs, so a marker on stdout, stderr
//! or in a debug log fails the test (the TypeScript CLI prints them, D140).

use serde_json::{Value, json};

use super::uuid;

/// The TSG every red team fixture belongs to.
pub const TSG: &str = "100";
/// The highest marker number the datasets use.
pub const MARKER_COUNT: u32 = 41;
/// Creation and update times of the fixtures.
pub const CREATED: &str = "2026-10-01T00:00:00Z";
pub const UPDATED: &str = "2026-10-02T00:00:00Z";

/// `FAKE-TARGET-SECRET-<n>`: a credential value in a fixture.
pub fn secret(n: u32) -> String {
    format!("FAKE-TARGET-SECRET-{n:02}")
}

/// Every marker the datasets can use.
pub fn markers() -> Vec<String> {
    (1..=MARKER_COUNT).map(secret).collect()
}

/// The id of fixture job `n`.
pub fn job_id(n: u64) -> String {
    uuid(100 + n)
}

/// The id of fixture target `n`.
pub fn target_id(n: u64) -> String {
    uuid(200 + n)
}

/// The id of fixture prompt set `n`.
pub fn prompt_set_id(n: u64) -> String {
    uuid(300 + n)
}

/// The id of fixture prompt `n`.
pub fn prompt_id(n: u64) -> String {
    uuid(400 + n)
}

/// The id of fixture adapter `n`.
pub fn adapter_id(n: u64) -> String {
    uuid(500 + n)
}

/// The id of fixture channel `n`.
pub fn channel_id(n: u64) -> String {
    uuid(600 + n)
}

/// The `target` reference of a job (target 1, `fixture-target`).
pub fn target_reference() -> Value {
    json!({
        "uuid": target_id(1),
        "tsg_id": TSG,
        "name": "fixture-target",
        "status": "ACTIVE",
        "active": true,
        "validated": true,
        "created_at": CREATED,
        "updated_at": UPDATED
    })
}

/// A scan job: `job_type` STATIC, DYNAMIC or CUSTOM, with the metadata of its type.
pub fn job(n: u64, name: &str, status: &str, job_type: &str) -> Value {
    let metadata = match job_type {
        "CUSTOM" => json!({"custom_prompt_sets": [prompt_set_id(1)]}),
        "DYNAMIC" => json!({"stream_breadth": 6, "stream_depth": 10}),
        _ => json!({"categories": {"SECURITY": ["JAILBREAK"]}}),
    };
    json!({
        "uuid": job_id(n),
        "tsg_id": TSG,
        "name": name,
        "target": target_reference(),
        "job_type": job_type,
        "job_metadata": metadata,
        "target_id": target_id(1),
        "target_type": "APPLICATION",
        "total": 40,
        "completed": 40,
        "status": status,
        "score": 7.5,
        "asr": 12.345,
        "created_at": "2026-10-17T10:00:00Z"
    })
}

/// A job without counts, score, ASR or creation time (a queued job).
pub fn bare_job(n: u64, name: &str, status: &str, job_type: &str) -> Value {
    let mut job = job(n, name, status, job_type);
    if let Value::Object(map) = &mut job {
        for key in ["total", "completed", "score", "asr", "created_at"] {
            map.remove(key);
        }
        map.insert("score".into(), Value::Null);
        map.insert("created_at".into(), Value::Null);
    }
    job
}

/// The attack categories: SECURITY (three sub-categories, `MULTI_TURN` among them) and
/// SAFETY (one, no category description).
pub fn categories() -> Value {
    json!([
        {
            "id": "SECURITY",
            "display_name": "Security",
            "description": "Security attacks",
            "sub_categories": [
                {"id": "JAILBREAK", "display_name": "Jailbreak", "description": "Bypass guardrails"},
                {"id": "MULTI_TURN", "display_name": "Multi turn", "description": "Multi-turn attacks"},
                {"id": "PROMPT_INJECTION", "display_name": "Prompt injection", "description": ""}
            ]
        },
        {
            "id": "SAFETY",
            "display_name": "Safety",
            "description": "",
            "sub_categories": [
                {"id": "TOXIC", "display_name": "Toxic content", "description": "Toxicity"}
            ]
        }
    ])
}

/// The tenant languages of a plane (the management answer is distinguishable).
pub fn languages(management: bool) -> Value {
    if management {
        json!({
            "multilingual_enabled": true,
            "supported_job_types": ["STATIC"],
            "languages": [{"code": "de", "name": "German"}]
        })
    } else {
        json!({
            "multilingual_enabled": false,
            "supported_job_types": ["STATIC", "DYNAMIC"],
            "languages": [{"code": "en", "name": "English"}, {"code": "fr", "name": "French"}]
        })
    }
}

/// The EULA status.
pub fn eula_status(accepted: bool) -> Value {
    if accepted {
        json!({
            "uuid": uuid(700),
            "is_accepted": true,
            "accepted_at": "2026-10-01T00:00:00Z",
            "accepted_by_user_id": "u@example.com"
        })
    } else {
        json!({"is_accepted": false})
    }
}

/// The EULA content.
pub fn eula_content(text: &str) -> Value {
    json!({"content": text})
}

/// A Red Team instance.
pub fn instance(tenant_id: &str) -> Value {
    json!({
        "tsg_id": TSG,
        "tenant_id": tenant_id,
        "app_id": "app-1",
        "region": "us"
    })
}

/// A custom prompt set.
pub fn prompt_set(n: u64, name: &str, active: bool) -> Value {
    json!({
        "uuid": prompt_set_id(n),
        "name": name,
        "active": active,
        "archive": false,
        "status": if active { "active" } else { "inactive" },
        "created_at": "2026-10-17T10:00:00Z",
        "updated_at": "2026-10-17T10:00:00Z",
        "description": "Fixture prompts"
    })
}

/// The version info of prompt set `n`.
pub fn version_info(n: u64) -> Value {
    json!({
        "uuid": prompt_set_id(n),
        "status": "active",
        "is_latest": true,
        "version": "3",
        "stats": {"total_prompts": 4, "active_prompts": 3, "inactive_prompts": 1}
    })
}

/// A prompt of set `set` (the get shape, with `prompt_set_id`).
pub fn prompt(n: u64, set: u64, text: &str, goal: Option<&str>, active: bool) -> Value {
    let mut prompt = json!({
        "uuid": prompt_id(n),
        "prompt": text,
        "user_defined_goal": goal.is_some(),
        "status": if active { "active" } else { "inactive" },
        "active": active,
        "prompt_set_id": prompt_set_id(set),
        "created_at": CREATED,
        "updated_at": UPDATED,
        "goal": goal
    });
    if goal.is_none()
        && let Value::Object(map) = &mut prompt
    {
        map.insert("goal".into(), Value::Null);
    }
    prompt
}

/// The default download template.
pub const TEMPLATE_CSV: &str = "prompt,goal\n\"example prompt\",\"example goal\"\n";

/// Target 1: a REST target with header authentication. Credentials: the `apikey`
/// request header, `curl`, the bearer of `auth_config`, a query in `api_endpoint`.
pub fn rest_target(n: u64, name: &str) -> Value {
    json!({
        "uuid": target_id(n),
        "tsg_id": TSG,
        "name": name,
        "status": "ACTIVE",
        "active": true,
        "validated": true,
        "created_at": CREATED,
        "updated_at": UPDATED,
        "connection_params": {
            "api_endpoint": format!("https://target.invalid/v1/chat?key={}", secret(1)),
            "request_headers": {"Content-Type": "application/json", "apikey": secret(2)},
            "request_json": {"messages": [{"role": "user", "content": "{INPUT}"}]},
            "response_json": {"choices": [{"message": {"content": "{RESPONSE}"}}]},
            "response_key": "choices.0.message.content",
            // As the service builds it: the endpoint, the headers (an `Authorization`
            // credential among them) and a request body naming the model and the target's
            // own name and description (§15.4 rule 3: only the credentials register).
            "curl": format!(
                "curl -X POST https://target.invalid/v1/chat -H 'apikey: {}' -H 'Authorization: Bearer {}' -H 'Content-Type: application/json' -d '{{\"model\":\"gpt-4o-mini\",\"messages\":[{{\"role\":\"system\",\"content\":\"You are {name}. Fixture REST target\"}}]}}'",
                secret(3),
                secret(32)
            )
        },
        "auth_config": {"auth_header": {"Authorization": format!("Bearer {}", secret(4))}},
        "description": "Fixture REST target",
        "target_type": "APPLICATION",
        "connection_type": "CUSTOM",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "session_supported": false,
        "extra_info": {"owner": "fixture", "token": secret(5)},
        "target_metadata": {"multi_turn": false, "multi_turn_error_message": "noise", "rate_limit": 50},
        "target_background": {"industry": "Generic", "use_case": "Chatbot", "competitors": ["A", "B"]},
        "additional_context": {"system_prompt": "You are a helpful assistant"},
        "auth_type": "HEADERS"
    })
}

/// A native OpenAI model target with OAuth2 settings (inactive, an unusual name).
pub fn openai_target(n: u64, name: &str) -> Value {
    json!({
        "uuid": target_id(n),
        "tsg_id": TSG,
        "name": name,
        "status": "INACTIVE",
        "active": false,
        "validated": true,
        "created_at": CREATED,
        "updated_at": UPDATED,
        "connection_params": {
            "target_connection_config": {"api_key": secret(6), "model_name": "gpt-4o"}
        },
        "auth_config": {
            "oauth2_token_url": format!("https://auth.invalid/token?client_secret={}", secret(7)),
            "oauth2_expiry_minutes": 60,
            "oauth2_headers": {"X-Client": secret(8)},
            "oauth2_body_params": {"client_id": "cid", "client_secret": secret(9)},
            "oauth2_token_response_key": "access_token",
            "oauth2_inject_header": {"Authorization": format!("Bearer {}", secret(10))}
        },
        "target_type": "MODEL",
        "connection_type": "OPENAI",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "target_metadata": {"multi_turn": true, "multi_turn_error_message": "kept"},
        "auth_type": "OAUTH2"
    })
}

/// A native Bedrock target with basic authentication.
pub fn bedrock_target(n: u64, name: &str) -> Value {
    json!({
        "uuid": target_id(n),
        "tsg_id": TSG,
        "name": name,
        "status": "ACTIVE",
        "active": true,
        "validated": false,
        "created_at": CREATED,
        "updated_at": UPDATED,
        "connection_params": {
            "target_connection_config": {
                "access_id": secret(11),
                "access_secret": secret(12),
                "session_token": secret(13),
                "region": "us-east-1",
                "model_id": "anthropic.claude"
            }
        },
        "auth_config": {
            "basic_auth_location": "HEADER",
            "basic_auth_header": {"Authorization": format!("Basic {}", secret(14))}
        },
        "target_type": "MODEL",
        "connection_type": "BEDROCK",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "auth_type": "BASIC_AUTH"
    })
}

/// A custom-adapter target with a SECRET variable override.
pub fn adapter_target(n: u64, name: &str) -> Value {
    json!({
        "uuid": target_id(n),
        "tsg_id": TSG,
        "name": name,
        "status": "ACTIVE",
        "active": true,
        "validated": true,
        "created_at": CREATED,
        "updated_at": UPDATED,
        "adapter_uuid": adapter_id(1),
        "network_broker_channel_uuid": channel_id(1),
        "adapter_variable_overrides": [
            {"key": "endpoint", "value": "http://agent.svc:8080", "type": "VAR"},
            {"key": "api_token", "value": secret(15), "type": "SECRET"}
        ],
        "target_type": "AGENT",
        "connection_type": "CUSTOM_TARGET_ADAPTER",
        "api_endpoint_type": "NETWORK_BROKER",
        "auth_type": "CUSTOM_TARGET_ADAPTER"
    })
}

/// A management 0.86.0 target (scm-sdk 0.2.3, DESIGN §15.24), in the shape of the SDK's
/// `red_team_management` example: `connection_type` `VERTEX_AI`, `response_mode`
/// `REALTIME`, the Vertex AI `target_connection_config`, the `client_session`
/// multi-turn config, the audio templates and basic credentials. Credentials: the basic
/// username and password and the bearer of `audio_curl`. The `api_endpoint` and the
/// description hold the Vertex AI project, location and engine, as a real target's do
/// (they are not markers: rule 4 redacts them in place but never registers them,
/// DESIGN §15.24 choice 12). Not in the default dataset:
/// the TypeScript CLI refuses this answer (D329), so tests seed it where they need it.
pub fn vertex_target(n: u64, name: &str) -> Value {
    json!({
        "uuid": target_id(n),
        "tsg_id": TSG,
        "name": name,
        "status": "ACTIVE",
        "active": true,
        "validated": false,
        "created_at": CREATED,
        "updated_at": UPDATED,
        "connection_type": "VERTEX_AI",
        "response_mode": "REALTIME",
        "connection_params": {
            "api_endpoint": VERTEX_ENDPOINT,
            "target_connection_config": vertex_connection_config(),
            "multi_turn_config": {"type": "client_session"},
            "audio_request_json": {"audio": "{AUDIO}"},
            "audio_curl": format!(
                "curl -X POST https://vertex.invalid/v1/audio -H 'Authorization: Bearer {}' -d '{{\"audio\":\"{{AUDIO}}\"}}'",
                secret(34)
            )
        },
        "auth_config": {"basic_username": secret(35), "basic_password": secret(33)},
        "description": VERTEX_DESCRIPTION,
        "target_type": "AGENT",
        "api_endpoint_type": "PUBLIC",
        "auth_type": "BASIC_AUTH"
    })
}

/// The `api_endpoint` of [`vertex_target`]: the Vertex AI agent engine of
/// [`vertex_connection_config`].
pub const VERTEX_ENDPOINT: &str = "https://us-central1-aiplatform.googleapis.com/v1/projects/example-project/locations/us-central1/reasoningEngines/12345:streamQuery";
/// The description of [`vertex_target`], naming its project, location and engine.
pub const VERTEX_DESCRIPTION: &str =
    "Vertex AI agent engine 12345 of example-project in us-central1";

/// The Vertex AI connection settings of [`vertex_target`] (management 0.86.0
/// `VertexAIConnectionParams`: each value matches its request pattern).
pub fn vertex_connection_config() -> Value {
    json!({
        "project_id": "example-project",
        "location": "us-central1",
        "engine_id": "12345",
        "customer_sa_email": "service@example-project.iam.invalid"
    })
}

/// A REST target with only the management 0.86.0 additions the TypeScript schemas pass
/// through (`audio_request_json`, `audio_curl`, `basic_username`, `basic_password`) and
/// the `N8N` connection type, so both CLIs read it (D327). Credentials: the basic
/// username and password and the API key header of `audio_curl`.
pub fn audio_target(n: u64, name: &str) -> Value {
    json!({
        "uuid": target_id(n),
        "tsg_id": TSG,
        "name": name,
        "status": "ACTIVE",
        "active": true,
        "validated": true,
        "created_at": CREATED,
        "updated_at": UPDATED,
        "connection_type": "N8N",
        "response_mode": "REST",
        "connection_params": {
            "api_endpoint": "https://n8n.invalid/webhook/chat",
            "request_json": {"message": "{INPUT}"},
            "response_json": {"output": "{RESPONSE}"},
            "response_key": "output",
            "audio_request_json": {"audio": "{AUDIO}"},
            "audio_curl": format!(
                "curl -X POST https://n8n.invalid/webhook/audio -H 'X-Api-Key: {}' -d '{{\"audio\":\"{{AUDIO}}\"}}'",
                secret(36)
            )
        },
        "auth_config": {
            "basic_auth_location": "HEADER",
            "basic_username": secret(37),
            "basic_password": secret(38)
        },
        "description": "Fixture n8n target",
        "target_type": "APPLICATION",
        "api_endpoint_type": "PUBLIC",
        "auth_type": "BASIC_AUTH"
    })
}

/// The list row of a target (`GET /v1/target`): the target without its connection,
/// authentication and context fields.
pub fn target_list_item(target: &Value) -> Value {
    let mut row = target.clone();
    if let Value::Object(map) = &mut row {
        for key in [
            "connection_params",
            "auth_config",
            "network_broker_channel_uuid",
            "adapter_variable_overrides",
            "target_metadata",
            "target_background",
            "additional_context",
            "adapter_secret_version",
            "profiling_progress",
        ] {
            map.remove(key);
        }
    }
    row
}

/// The profile of target `n`.
pub fn target_profile(n: u64) -> Value {
    json!({
        "target_id": target_id(n),
        "target_version": 2,
        "status": "COMPLETED",
        "profiling_status": "COMPLETED",
        "target_background": {"industry": "Generic", "use_case": "Chatbot"},
        "additional_context": {"system_prompt": "You are a helpful assistant"},
        "ai_generated_fields": ["industry"],
        "other_details": {"notes": "fixture"}
    })
}

/// The target field metadata (an arbitrary object).
pub fn target_metadata() -> Value {
    json!({
        "connection_types": ["CUSTOM", "OPENAI"],
        "fields": {"api_endpoint": {"required": true, "label": "API endpoint"}}
    })
}

/// The provider templates (every provider the schema requires).
pub fn target_templates() -> Value {
    json!({
        "OPENAI": {"model_name": "gpt-4o"},
        "HUGGING_FACE": {"url": "https://api-inference.huggingface.co/models/x"},
        "DATABRICKS": {"workspace_url": "https://example.cloud.databricks.com"},
        "BEDROCK": {"region": "us-east-1"},
        "REST": {"url": "https://api.example.com/v1/chat", "request_json": {"input": "{INPUT}"}},
        "STREAMING": {"url": "https://api.example.com/v1/stream"},
        "WEBSOCKET": {"url": "wss://api.example.com/v1/ws"}
    })
}

/// A target-profile error log of target `target`; `target_object` is a snapshot of the
/// target with its credentials.
pub fn error_log(n: u64, target: u64, error_type: Option<&str>, message: Option<&str>) -> Value {
    let mut log = json!({
        "created_at": format!("2026-01-{:02}T00:00:00Z", 4 + n),
        "updated_at": format!("2026-01-{:02}T00:00:00Z", 4 + n),
        "job_id": if n == 1 { Value::String(job_id(1)) } else { Value::Null },
        "target_id": target_id(target),
        "target_version": 1,
        "error_type": error_type,
        "error_source": if n == 1 { Value::String("TARGET".into()) } else { Value::Null },
        "error_message": message,
        "target_object": {
            "name": "Rest Target One",
            "auth_config": {"auth_header": {"Authorization": format!("Bearer {}", secret(16))}},
            "connection_params": {"request_headers": {"apikey": secret(17)}}
        },
        "extra_info": {"api_key": secret(18), "attempt": 1},
        "version": 1
    });
    if let Value::Object(map) = &mut log {
        for key in ["error_type", "error_message"] {
            if map.get(key) == Some(&Value::Null) {
                map.remove(key);
            }
        }
    }
    log
}

/// A custom target adapter: a VAR variable and a SECRET the server masks
/// (`is_redacted`).
pub fn adapter(n: u64, name: &str, status: &str) -> Value {
    json!({
        "uuid": adapter_id(n),
        "tsg_id": TSG,
        "name": name,
        "script_b64": "cHJpbnQoJ2hpJykK",
        "status": status,
        "description": "an adapter",
        "network_broker_channel_uuid": channel_id(1),
        "variables": [
            {"key": "endpoint", "value": "http://agent.svc:8080", "type": "VAR"},
            {"key": "api_token", "value": "**********", "type": "SECRET", "is_redacted": true}
        ],
        "target_count": 1,
        "created_at": CREATED,
        "updated_at": UPDATED
    })
}

/// An adapter whose SECRET variable the server returned unmasked (a server defect).
pub fn leaky_adapter(n: u64, name: &str) -> Value {
    let mut adapter = adapter(n, name, "DRAFT");
    adapter["variables"] = json!([
        {"key": "api_token", "value": secret(19), "type": "SECRET"},
        {"key": "region", "value": null, "type": "VAR"}
    ]);
    adapter
}

/// The list row of an adapter.
pub fn adapter_list_item(adapter: &Value) -> Value {
    let mut row = json!({});
    for key in [
        "uuid",
        "name",
        "status",
        "created_at",
        "updated_at",
        "created_by_user_id",
        "target_count",
    ] {
        if let Some(value) = adapter.get(key) {
            row[key] = value.clone();
        }
    }
    row
}

/// A network broker channel.
pub fn channel(n: u64, name: &str, status: &str, clients: u64) -> Value {
    json!({
        "uuid": channel_id(n),
        "name": name,
        "description": "fixture channel",
        "status": status,
        "added_by": "admin@example.com",
        "created_at": CREATED,
        "updated_at": UPDATED,
        "last_online_at": "2026-10-03T00:00:00Z",
        "connected_clients_count": clients,
        "outdated_clients_count": 0,
        "features": {"multi_turn": true}
    })
}

/// The channel statistics.
pub fn channel_stats() -> Value {
    json!({
        "network_channels_server_domain": "broker.example.com",
        "docker_registry": "registry.example.com",
        "helm_chart": "oci://registry.example.com/broker",
        "docker_image": "broker:1.4.0",
        "online_channels": 1,
        "total_channels": 2,
        "client_version": "1.4.0"
    })
}

// ---------------------------------------------------------------------------
// Scan reports and the environment-report sources (step 3)
// ---------------------------------------------------------------------------

/// The static report of job 1 (two severities, two sub-categories, a summary with a
/// known and an unknown placeholder).
pub fn static_report() -> Value {
    json!({
        "severity_report": {
            "stats": [
                {"severity": "HIGH", "successful": 3, "failed": 7},
                {"severity": "LOW", "failed": 5}
            ],
            "successful": 3,
            "failed": 12,
            "total_attacks": 15
        },
        "asr": 20,
        "score": 8.25,
        "security_report": {
            "id": "SECURITY",
            "display_name": "Security",
            "description": "Security attacks",
            "sub_categories": [
                {"id": "JAILBREAK", "display_name": "Jailbreak", "description": "Bypass guardrails", "successful": 3, "failed": 7, "total": 10},
                {"id": "PROMPT_INJECTION", "display_name": "Prompt injection", "description": "", "successful": 0, "failed": 5}
            ],
            "asr": 20,
            "total_prompts": 15,
            "total_attacks": 15,
            "successful": 3,
            "failed": 12
        },
        // Multi-line markdown, as the real service sends it: blank lines, headings,
        // bullets, a CR LF pair and a tab (TS prints them as they are).
        "report_summary": "Overall {{HIGH_RISK}} posture {{UNKNOWN}}\n\n### Summary\n\n- 3 of 15 prompts bypassed the guardrails\n- Jailbreak: {{HIGH_RISK}}\n\n### Recommendations\r\n- Review the jailbreak findings\n-\tRetest after changes"
    })
}

/// The dynamic report of job 2 (ASR as a fraction).
pub fn dynamic_report() -> Value {
    json!({
        "total_goals": 4,
        "total_streams": 24,
        "total_threats": 2,
        "goals_achieved": 1,
        "report_summary": "Dynamic {{LOW_RISK}}\n\n### Summary\n- 1 of 4 goals achieved",
        "score": 6,
        "asr": 0.25
    })
}

/// The custom-attack report of job 3.
pub fn custom_report() -> Value {
    json!({
        "total_prompts": 10,
        "total_attacks": 10,
        "total_threats": 3,
        "failed_attacks": 7,
        "score": 7,
        "asr": 30,
        "custom_attack_reports": [{
            "prompt_set_id": prompt_set_id(1),
            "prompt_set_name": "fixture-set",
            "total_prompts": 10,
            "total_attacks": 10,
            "total_threats": 3,
            "failed_attacks": 7,
            "threat_rate": 30
        }]
    })
}

/// One static attack of job 1 (the attack prompt is a marker: it must never be printed).
pub fn attack(n: u64, severity: Option<&str>, threat: Option<bool>, sub_display: &str) -> Value {
    let mut attack = json!({
        "uuid": uuid(900 + n),
        "tsg_id": TSG,
        "job_id": job_id(1),
        "target_id": target_id(1),
        "prompt": format!("attack prompt {}", secret(31)),
        "prompt_mapping_id": uuid(950 + n),
        "prompt_id": prompt_id(n),
        "category": "SECURITY",
        "sub_category": "JAILBREAK",
        "category_display_name": "Security",
        "sub_category_display_name": sub_display,
        "attack_name": format!("attack-{n}")
    });
    if let Some(severity) = severity {
        attack["severity"] = json!(severity);
    }
    if let Some(threat) = threat {
        attack["threat"] = json!(threat);
    }
    attack
}

/// The attacks of job 1: a HIGH bypass and a HIGH block, then one without a severity.
pub fn attacks() -> Vec<Value> {
    vec![
        attack(1, Some("HIGH"), Some(true), "Jailbreak"),
        attack(2, Some("HIGH"), Some(false), "Prompt injection"),
        attack(3, None, None, "Jailbreak"),
    ]
}

/// The custom attacks of job 3: a threat with a long prompt and a goal, a safe one.
pub fn custom_attacks() -> Vec<Value> {
    vec![
        json!({
            "prompt_id": prompt_id(1),
            "prompt_text": "X".repeat(90),
            "goal": "Leak",
            "threat": true,
            "asr": 50,
            "prompt_set_id": prompt_set_id(1),
            "prompt_set_name": "fixture-set"
        }),
        json!({
            "prompt_id": prompt_id(2),
            "prompt_text": "short prompt",
            "threat": false,
            "prompt_set_id": prompt_set_id(1),
            "prompt_set_name": "fixture-set"
        }),
    ]
}

/// Job 3: a completed CUSTOM job (not in the seeded scan list; tests add it).
pub fn custom_job() -> Value {
    job(3, "custom-scan", "COMPLETED", "CUSTOM")
}

/// The dashboard overview.
pub fn dashboard_overview() -> Value {
    json!({"total_targets": 4})
}

/// The dashboard scan statistics (a HIGH risk rating, so the report needs attention).
pub fn scan_statistics() -> Value {
    json!({
        "total_scans": 4,
        "targets_scanned": 1,
        "risk_profile": [{"risk_rating": "HIGH", "total": 1}, {"risk_rating": "LOW", "total": 2}],
        "scan_status": [{"name": "COMPLETED", "count": 3}, {"name": "RUNNING", "count": 1}]
    })
}

/// The quota summary (static unlimited, the others finite with room).
pub fn quota() -> Value {
    json!({
        "static": {"allocated": 0, "unlimited": true, "consumed": 0},
        "dynamic": {"allocated": 50, "unlimited": false, "consumed": 0},
        "custom": {"allocated": 50, "unlimited": false, "consumed": 5}
    })
}
