//! The gateway datasets (DESIGN §10 M6e): wire bodies that validate against both SDKs'
//! response schemas (TS zod `src/models/ai-gateway*.ts`, scm-sdk 0.2.2 `models::gateway`).
//!
//! Ids are `11111111-1111-4111-8111-<12 digits>` ([`uuid`]). The workspaces are `U(1)`
//! `ws-main-a-349e0e` "Main A" (active, default, visible on the data plane), `U(2)`
//! `ws-produc-985697` "Production" (active, admin plane only) and `U(3)` `ws-old-aaaaaa`
//! "Old" (archived); the scopes `main_airs_workspace_1852583913` and
//! `ws_production_bx7qw0` bind them, `ws_orphan_zzzzzz` is unbound. Nested objects use
//! sorted keys, so both CLIs print them in one order (D35).

use serde_json::{Value, json};

/// A credential marker (`FAKE-GW-SECRET-<n>`): the runner forbids every one of them in
/// every output of an airs-cli-rs gateway run (DESIGN §10 M6e).
pub fn marker(n: u32) -> String {
    format!("FAKE-GW-SECRET-{n}")
}

/// Every credential marker the gateway fixtures use (the chunk-1 tests use 1–9, the
/// inventory datasets 10–29, tests 30–81).
pub fn markers() -> Vec<String> {
    (1..=81).map(marker).collect()
}

/// The fixed timestamp of every record.
pub const AT: &str = "2026-10-01T12:00:00.000Z";

/// The TSG every fixture scope belongs to.
pub const TSG: &str = "100";

/// `11111111-1111-4111-8111-<n, 12 digits>`.
pub fn uuid(n: u64) -> String {
    format!("11111111-1111-4111-8111-{n:012}")
}

/// One workspace list row (`GatewayWorkspaceSchema`).
pub fn workspace(
    n: u64,
    slug: &str,
    name: &str,
    status: &str,
    default: bool,
    scope: &str,
) -> Value {
    json!({
        "id": uuid(n),
        "slug": slug,
        "name": name,
        "icon": null,
        "description": null,
        "created_at": AT,
        "last_updated_at": AT,
        "is_default": i32::from(default),
        "status": status,
        "scope_name": scope,
        "object": "workspace",
    })
}

/// The three workspaces of the dataset.
pub fn workspaces() -> Vec<Value> {
    vec![
        workspace(
            1,
            "ws-main-a-349e0e",
            "Main A",
            "active",
            true,
            "main_airs_workspace_1852583913",
        ),
        workspace(
            2,
            "ws-produc-985697",
            "Production",
            "active",
            false,
            "ws_production_bx7qw0",
        ),
        workspace(
            3,
            "ws-old-aaaaaa",
            "Old",
            "archived",
            false,
            "ws_old_aaaaaa",
        ),
    ]
}

/// The details of `U(1)` and `U(2)` (`GatewayWorkspaceDetailSchema`): the first with every
/// settings block (its `settings` the API-key settings a live tenant sends), the second with TS's observed `status: null` and a legacy one-object
/// `usage_limits`.
pub fn details() -> Vec<Value> {
    vec![
        json!({
            "id": uuid(1),
            "name": "Main A",
            "description": "Default workspace",
            "created_at": AT,
            "last_updated_at": AT,
            "is_default": 1,
            "slug": "ws-main-a-349e0e",
            "icon": null,
            "defaults": {"config_id": "cfg-1", "metadata": {"env": "dev"}},
            "usage_limits": [{"alert_threshold": 80, "credit_limit": 10000, "type": "cost"}],
            "rate_limits": [],
            "security_settings": {"block_pii": true, "log_prompts": false},
            "data_plane_security_settings": {"mode": "strict"},
            // The live tenant's API-key settings (choice 187): counts, lifetimes and an unset
            // rotation period that TypeScript prints and the name rule once withheld.
            "settings": {
                "y": 2,
                "user_api_key_auto_create": false,
                "user_api_key_count": 5,
                "user_api_key_max_ttl": 7_776_000,
                "user_api_key_ttl": 2_592_000,
                "user_api_key_rotation_period": "",
            },
            "status": "active",
        }),
        json!({
            "id": uuid(2),
            "name": "Production",
            "description": null,
            "created_at": AT,
            "last_updated_at": AT,
            "is_default": 0,
            "slug": "ws-produc-985697",
            "icon": null,
            "defaults": null,
            "usage_limits": {"credit_limit": 5, "type": "cost"},
            "rate_limits": [{"type": "requests", "unit": "rpm", "value": 100}],
            "status": null,
        }),
    ]
}

/// The detail of a workspace the dataset has no detail for: its list row in the detail
/// schema (no settings blocks).
pub fn detail_of(row: &Value) -> Value {
    json!({
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "created_at": row["created_at"],
        "last_updated_at": row["last_updated_at"],
        "is_default": row["is_default"],
        "slug": row["slug"],
        "icon": row["icon"],
        "defaults": null,
        "usage_limits": null,
        "rate_limits": null,
        "status": row["status"],
    })
}

/// One IAM scope (`IamScopeSchema`) binding `workspaces` (slugs).
pub fn scope(name: &str, description: &str, workspaces: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "resources": workspaces
            .iter()
            .map(|slug| json!({"resource_type": "workspace", "resource_id": slug, "metadata": []}))
            .collect::<Vec<_>>(),
        "tsg_id": TSG,
        "id": format!("{name}:{TSG}"),
    })
}

/// The three scopes of the dataset.
pub fn scopes() -> Vec<Value> {
    vec![
        scope(
            "main_airs_workspace_1852583913",
            "Main workspace scope",
            &["ws-main-a-349e0e"],
        ),
        scope(
            "ws_production_bx7qw0",
            "All production applications",
            &["ws-produc-985697"],
        ),
        scope("ws_orphan_zzzzzz", "Left over", &[]),
    ]
}

fn envelope(data: Value) -> Value {
    json!({"success": true, "data": data})
}

/// The chart metrics (`/logs/charts/<metric>`) with their bodies.
pub fn charts() -> Vec<(&'static str, Value)> {
    let records = json!([{"x": "2026-09-30", "y": 42}, {"x": "2026-10-01", "y": 7}]);
    let count = envelope(json!({"records": records, "total": 49, "isQuotaExceeded": false}));
    let category = json!({"response_status_code": 446, "count": 3});
    vec![
        ("errors", count.clone()),
        ("users", count.clone()),
        ("requests", count.clone()),
        ("feedback-trend", count.clone()),
        ("feedback-weighted", count),
        (
            "cost",
            envelope(json!({
                "records": [{"x": "2026-09-30", "y": 1234}, {"x": "2026-10-01", "y": 5}],
                "total": 1239,
                "avg": 619.5,
                "isQuotaExceeded": false,
            })),
        ),
        (
            "latency",
            envelope(json!({
                "records": [{"x": "2026-09-30", "y": 120, "p50": 100, "p90": 180, "p99": 240}],
                "total": 120,
                "p50": 100,
                "p90": 180,
                "p99": null,
                "isQuotaExceeded": false,
            })),
        ),
        (
            "tokens",
            envelope(json!({
                "records": [{
                    "x": "2026-09-30",
                    "y": 42,
                    "total_request_units": 20,
                    "total_response_units": 22,
                    "avg": 21,
                }],
                "total": 42,
                "avg": 21,
                "total_request_units": 20,
                "total_response_units": 22,
                "isQuotaExceeded": false,
            })),
        ),
        (
            "error-category-trends",
            envelope(json!({
                "summary": {"totalErrors": 3, "totalUniqueErrorCodes": 1},
                "trend": [category],
                "isQuotaExceeded": false,
            })),
        ),
        (
            "grouped-errors",
            envelope(json!({
                "trend": [{"x": "2026-09-30", "y": [category]}],
                "total": 3,
                "isQuotaExceeded": false,
            })),
        ),
        (
            "rescued-retries",
            envelope(json!({
                "trend": [{"x": "2026-09-30", "y": []}],
                "total": 0,
                "trends": [{"x": "2026-09-30", "retry": [], "fallback": []}],
                "retryTotal": 0,
                "fallbackTotal": 0,
                "isQuotaExceeded": false,
            })),
        ),
        (
            "user-trends",
            envelope(json!({
                "summary": {"total": 5, "unique": 2, "avg": 2.5},
                "trend": [{"x": "2026-09-30", "y": 5}],
                "isQuotaExceeded": false,
            })),
        ),
        (
            "error-trends",
            envelope(json!({
                "summary": {"errorPercent": 6.25},
                "trend": [{"x": "2026-09-30", "y": 3}],
                "isQuotaExceeded": false,
            })),
        ),
        (
            "cache-summary",
            envelope(json!({
                "summary": {
                    "cacheHits": 4,
                    "avgCacheLatency": null,
                    "totalRequests": 49,
                    "cacheSpeedup": 1.5,
                },
                "isQuotaExceeded": false,
            })),
        ),
        (
            "cache-hit-trend",
            envelope(json!({
                "trend": [{
                    "x": "2026-09-30",
                    "simpleHits": 3,
                    "semanticHits": 1,
                    "hitRate": 0.25,
                    "cumulativeSimpleHitSavings": 12,
                    "cumulativeSemanticHitSavings": 4,
                }],
                "total": 4,
                "summary": {"totalCacheHits": 4, "hitRate": 0.25},
                "isQuotaExceeded": false,
            })),
        ),
        (
            "feedback-score-distribution",
            envelope(json!({
                "records": [{"x": 1, "y": 2}, {"x": 5, "y": 9}],
                "total": 11,
                "isQuotaExceeded": false,
            })),
        ),
        (
            "feedback-models",
            envelope(json!({
                "records": [{"x": "openai__gpt-x", "y": {"avgWeightedFeedback": 4.5, "feedbackCount": 2}}],
                "isQuotaExceeded": false,
            })),
        ),
    ]
}

/// A `/logs/groups/<dimension>` answer other than `users` (`GroupListResponseSchema`).
pub fn group() -> Value {
    json!({
        "object": "list",
        "is_quota_exceeded": false,
        "total": 1,
        "data": [{"requests": 1, "cost": 0.125, "total_tokens": 42, "object": "model"}],
    })
}

/// The `/logs/groups/users` answer (`UserGroupResponseSchema`).
pub fn user_group() -> Value {
    envelope(json!({
        "records": [{"_user": "alice", "count": 1, "cost": 0.125}],
        "total": 1,
        "isQuotaExceeded": false,
    }))
}

/// One request log row (`GatewayLogRecordSchema`).
pub fn log(n: u64) -> Value {
    json!({
        "id": format!("log-{n}"),
        "workspace_slug": "ws-main-a-349e0e",
        "ai_model": "gpt-x",
        "_user": "alice",
        "total_units": 42,
        "cost": 0.125,
        "trace_id": format!("trace-{n}"),
        "is_proxy_call": 0,
        "created_at": AT,
        "is_success": 1,
        "cache_status": "MISS",
        "retry_success_count": 0,
        "mode": "single",
        "last_used_option_index": 0,
        "response_status_code": 200,
        "request_url": "https://api.example.test/v1/chat/completions",
        "request_method": "POST",
        "ai_org": "openai",
        "api_key_id": uuid(500 + n),
        "license_id": "lic-1",
        "log_store_file_path_format": "v1",
        "metadataKey": ["env"],
        "metadataValue": ["dev"],
        "prompt_slug": "",
        "feedback": [],
    })
}

/// The `/analytics/filter-boundaries` answer.
pub fn filter_boundaries() -> Value {
    envelope(json!({
        "total_units_max": 42,
        "total_units_min": 0,
        "cost_max": 0.125,
        "cost_min": null,
        "unique_ai_models": [{"ai_model": "gpt-x", "ai_organisation": "openai"}],
        "unique_status_codes": [200, 446],
        "unique_environments": ["dev"],
        "unique_prompt_ids": [],
        "unique_virtual_keys": [],
        "unique_configs": [],
        "unique_api_keys": [uuid(501)],
        "unique_metadata_keys": ["env"],
        "isQuotaExceeded": false,
    }))
}

// ---------------------------------------------------------------------------
// Inventory and admin reads (DESIGN §10 M6e, chunk 2)
// ---------------------------------------------------------------------------
//
// Ids: workspace `U(1)`, service key `U(201)`, user key `U(202)`, config `U(301)`,
// deployment `U(401)`, workspace guardrail `U(601)`, integration `U(701)`, MCP
// integration `U(801)`, plugin `U(901)`, provider `U(1001)`, admin guardrail `U(1101)`,
// catalog provider `U(1201)`, MCP mapping `U(1301)` on MCP server `U(1302)`, the internal
// organisation `U(1401)`, the secret reference of the provider's secret mapping `U(1601)`. Every credential the service can return carries a marker:
// API key material 10 and 11, audit body 12, headers 13 and query 14, deployment password
// 15 and client auth 16, integration AWS secret 17, header 18 and custom-host query 28,
// MCP client secret 19 and header 20, SCIM token 21, SSO client secret 22, plugin
// credential 23, provider key 24 (detail) and 26 (list row), provider model config 25,
// organisation settings 27, a config target's `api_key` inside the `config` text 29.

/// The service-key id, the user-key id and the other inventory ids.
pub const SERVICE_KEY: u64 = 201;
pub const USER_KEY: u64 = 202;
pub const CONFIG: u64 = 301;
pub const DEPLOYMENT: u64 = 401;
pub const GUARDRAIL: u64 = 601;
pub const INTEGRATION: u64 = 701;
pub const MCP_INTEGRATION: u64 = 801;
pub const PLUGIN: u64 = 901;
pub const PROVIDER: u64 = 1001;
pub const ADMIN_GUARDRAIL: u64 = 1101;
pub const CATALOG_PROVIDER: u64 = 1201;
pub const MCP_MAPPING: u64 = 1301;
pub const MCP_SERVER: u64 = 1302;
pub const ORGANISATION: u64 = 1401;
pub const SECRET_REFERENCE: u64 = 1601;

fn list_of(rows: Vec<Value>) -> Value {
    json!({"object": "list", "total": rows.len(), "data": rows})
}

/// One API key (`GatewayApiKeySchema`) of `kind` (`service` or `user`) with `key`.
pub fn api_key(n: u64, kind: &str, key: &str) -> Value {
    json!({
        "alert_emails": null,
        "allow_config_override": 1,
        "api_key_defaults_id": "defaults-1",
        "created_at": AT,
        "created_by": "admin",
        "creation_mode": "api",
        "defaults": {"config_id": null, "metadata": null},
        "description": null,
        "expires_at": null,
        "expiry_enforced": 0,
        "id": uuid(n),
        "key": key,
        "last_reset_at": null,
        "last_updated_at": AT,
        "last_updated_by": "admin",
        "name": format!("{kind}-bot"),
        "object": "api-key",
        "organisation_id": uuid(ORGANISATION),
        "rate_limits": [],
        "reset_usage": null,
        "scopes": ["completions.write", "logs.write"],
        "status": "active",
        "type": kind,
        "usage_limits": null,
        "user_id": if kind == "user" { json!(uuid(1501)) } else { Value::Null },
        "workspace_id": uuid(1),
    })
}

/// `GET <data>/api-keys/service?workspace_id=` (`ListApiKeysResponseSchema`).
pub fn service_keys() -> Value {
    list_of(vec![api_key(SERVICE_KEY, "service", &marker(10))])
}

/// `GET <data>/api-keys/user?workspace_id=`.
pub fn user_keys() -> Value {
    list_of(vec![api_key(USER_KEY, "user", &marker(11))])
}

/// One audit record (`GatewayAuditLogRecordSchema`); `n` 1 carries the credential
/// markers in its request body, headers and query (G44).
pub fn audit_record(n: u64) -> Value {
    let (body, headers, query) = if n == 1 {
        (
            json!({"key": marker(12), "name": "ci-bot"}).to_string(),
            json!({"authorization": format!("Bearer {}", marker(13)), "content-type": "application/json"})
                .to_string(),
            json!({"api_key": marker(14), "page": "1"}).to_string(),
        )
    } else {
        ("plain text body".to_owned(), "{}".to_owned(), String::new())
    };
    json!({
        "action": "create",
        "client_ip": "192.0.2.10",
        "country": "US",
        "method": "POST",
        "organisation_id": uuid(ORGANISATION),
        "query_params": query,
        "request_body": body,
        "request_headers": headers,
        "request_id": format!("req-{n}"),
        "resource_type": "api-key",
        "response_status_code": 200,
        "timestamp": AT,
        "uri": "/v2/api-keys/service",
        "user_id": uuid(1501),
        "user_type": "user",
        "workspace_id": uuid(1),
    })
}

/// `GET <admin>/audit-logs` (`GatewayAuditLogsResponseSchema`).
pub fn audit_logs() -> Value {
    json!({"object": "list", "records": [audit_record(1), audit_record(2)], "total": 2})
}

/// One config row (`GatewayConfigSchema`).
pub fn config_row(n: u64) -> Value {
    json!({
        "created_at": AT,
        "id": uuid(n),
        "is_default": 1,
        "last_updated_at": AT,
        "name": "Default routing",
        "object": "config",
        "organisation_id": uuid(ORGANISATION),
        "owner_id": uuid(1501),
        "slug": "pc-default",
        "status": "active",
        "updated_by": "admin",
        "workspace_id": uuid(1),
    })
}

/// `GET <data>/configs?workspace_id=`.
pub fn configs() -> Value {
    list_of(vec![config_row(CONFIG)])
}

/// `GET <data>/configs/<id>` (`GatewayConfigDetailSchema`).
pub fn config_detail() -> Value {
    let mut detail = config_row(CONFIG);
    let object = detail.as_object_mut().expect("object");
    object.insert(
        "config".into(),
        json!(format!(
            r#"{{"retry":{{"attempts":3}},"targets":[{{"api_key":"{}","provider":"openai"}}]}}"#,
            marker(29)
        )),
    );
    object.insert("format".into(), json!("json"));
    object.insert("type".into(), json!("ROUTING"));
    object.insert("version_id".into(), json!(uuid(302)));
    detail
}

/// `GET <data>/configs/<id>/versions` (`ListConfigVersionsResponseSchema`).
pub fn config_versions() -> Value {
    let mut version = config_detail();
    let object = version.as_object_mut().expect("object");
    object.insert("version_created_at".into(), json!(AT));
    object.insert("version_owner_id".into(), json!(uuid(1501)));
    list_of(vec![version])
}

fn deployment_row() -> Value {
    json!({
        "created_at": AT,
        "created_by": "admin",
        "id": uuid(DEPLOYMENT),
        "is_default": 1,
        "last_resynced_at": null,
        "last_synced_at": AT,
        "last_updated_at": AT,
        "name": "Edge",
        "object": "deployment",
        "slug": "edge",
        "status": "active",
        "type": "production",
    })
}

/// `GET <admin>/deployments` (`ListDeploymentsResponseSchema`).
pub fn deployments() -> Value {
    list_of(vec![deployment_row()])
}

/// `GET <admin>/deployments/<id>` (`GatewayDeploymentDetailSchema`) with its credentials.
pub fn deployment_detail() -> Value {
    let mut detail = deployment_row();
    let object = detail.as_object_mut().expect("object");
    object.insert(
        "auth_settings".into(),
        json!({
            "allow_all_workspaces": 1,
            "disable_portkey_gateway": 0,
            "gateway_base_url": "https://gw.example.test",
            "workspaces_allowed": [],
        }),
    );
    object.insert("client_auth".into(), json!(marker(16)));
    object.insert(
        "credentials".into(),
        json!({"password": marker(15), "username": "edge-agent"}),
    );
    object.insert("deployment_config".into(), json!({"replicas": 2}));
    detail
}

/// `GET <admin>/deployments/<id>/ping` (`GatewayDeploymentPingResponseSchema`).
pub fn deployment_ping() -> Value {
    json!({
        "gateway_base_url": "https://gw.example.test",
        "inbound": {"status": "ok"},
        "object": "deployment.ping",
        "outbound": {"status": "ok", "status_code": 200, "version": "1.2.3"},
        "status": "healthy",
    })
}

fn guardrail_row() -> Value {
    json!({
        "created_at": AT,
        "id": uuid(GUARDRAIL),
        "last_updated_at": AT,
        "name": "Prompt shield",
        "object": "guardrail",
        "organisation_id": uuid(ORGANISATION),
        "owner_id": uuid(1501),
        "slug": "pg-shield",
        "status": "active",
        "target": "llm",
        "updated_by": null,
        "workspace_id": uuid(1),
    })
}

/// `GET <data>/guardrails?workspace_id=` (`ListGuardrailsResponseSchema`).
pub fn guardrails() -> Value {
    list_of(vec![guardrail_row()])
}

/// The checks of a guardrail detail: the AIRS intercept and the required-metadata check, whose
/// `metadataKeys` (`GatewayRequiredMetadataKeysParameters`) lists metadata key names, printed
/// by both CLIs (DESIGN §19.20 choice 188).
pub fn guardrail_checks() -> Value {
    json!([
        {"id": "panw-prisma-airs.intercept", "is_enabled": true, "parameters": {"profile_name": "default"}},
        {"id": "default.requiredMetadataKeys", "is_enabled": true, "parameters": {"metadataKeys": ["user_id", "team"], "operator": "all"}},
    ])
}

/// `GET <data>/guardrails/<id>` (`GatewayGuardrailDetailSchema`).
pub fn guardrail_detail() -> Value {
    let mut detail = guardrail_row();
    let object = detail.as_object_mut().expect("object");
    object.insert(
        "actions".into(),
        json!({"async": false, "deny": true, "sequential": false}),
    );
    object.insert("checks".into(), guardrail_checks());
    object.insert("version_id".into(), json!(uuid(602)));
    detail
}

/// `GET <admin>/utils/static-resources/schema?resource=guardrails`
/// (`GatewayGuardrailCatalogResponseSchema`), shaped like the service's catalog (the
/// Portkey plugin manifests): `evals[]` whose `description` is a list of `{type, text}`
/// paragraphs and whose `parameters.properties` hold JSON Schema objects, several under
/// credential names (`credentials.apiKey`, `token`, `client_secret`, `headers`), nested
/// `properties` and `items`, the guardrail settings whose names carry a credential word
/// (Acuvity's `secrets_categories`, the JWT `maxTokenAge`, with their defaults; choice 165),
/// an empty `default` under the credential-named `client_secret` and the required-metadata
/// check's `metadataKeys` with its empty `default` and its `examples` (choice 188), and the
/// top-level `object: "list"`. It carries no credential: both CLIs print it whole
/// (DESIGN §19.3 rule 3e, choice 146). The fixture server sends it
/// in a non-alphabetical member order ([`service_order`]), as the service does.
pub fn guardrail_catalog() -> Value {
    let paragraph = |text: &str| json!([{"text": text, "type": "subHeading"}]);
    json!({
        "evals": [
            {
                "deny": false,
                "description": paragraph("Checks prompts and responses with Prisma AIRS"),
                "guardrailCategory": "security",
                "id": "panw-prisma-airs.intercept",
                "name": "Prisma AIRS intercept",
                "parameters": {
                    "properties": {
                        "credentials": {
                            "description": paragraph("The scan credentials"),
                            "properties": {
                                "apiKey": {"description": paragraph("The AIRS scan API key"), "encrypted": true, "label": "API Key", "type": "string"},
                                "region": {"default": "us", "enum": ["us", "eu"], "label": "Region", "type": "string"},
                            },
                            "required": ["apiKey"],
                            "type": "object",
                        },
                        "profile_name": {"description": paragraph("The AIRS security profile"), "label": "Profile name", "type": "string"},
                        "timeout": {"default": 5000, "description": paragraph("Scan timeout in milliseconds"), "type": "number"},
                        "token": {"description": paragraph("An optional session token"), "type": ["string", "null"]},
                    },
                    "required": ["profile_name"],
                    "type": "object",
                },
                "source": {"description": "Palo Alto Networks AI Runtime Security", "id": "panw-prisma-airs", "name": "Prisma AIRS"},
                "supportedHooks": ["beforeRequestHook", "afterRequestHook"],
                "targets": ["llm"],
                "type": "guardrail",
            },
            {
                "description": paragraph("Calls a webhook with the request"),
                "guardrailCategory": "custom",
                "id": "default.webhook",
                "name": "Webhook",
                "parameters": {
                    "properties": {
                        "client_secret": {"default": "", "description": paragraph("The OAuth client secret"), "label": "Client secret", "type": "string"},
                        "headers": {"description": paragraph("Extra request headers, as an object"), "type": "object"},
                        "methods": {"items": {"enum": ["POST", "PUT"], "type": "string"}, "type": "array"},
                        "webhookURL": {"description": paragraph("The webhook to call"), "format": "uri", "type": "string"},
                    },
                    "required": ["webhookURL"],
                    "type": "object",
                },
                "supportedHooks": ["beforeRequestHook"],
                "type": "guardrail",
            },
            {
                "description": paragraph("Scans with Acuvity and checks the caller's JWT"),
                "guardrailCategory": "partner",
                "id": "acuvity.scan",
                "name": "Acuvity scan",
                "parameters": {
                    "properties": {
                        "maxTokenAge": {"default": "1d", "description": paragraph("The oldest JWT accepted"), "label": "Max token age", "type": "string"},
                        "secrets": {"default": true, "description": paragraph("Detect secrets"), "type": "boolean"},
                        "secrets_categories": {"default": ["aws", "github"], "items": {"enum": ["aws", "github", "slack"], "type": "string"}, "type": "array"},
                    },
                    "type": "object",
                },
                "supportedHooks": ["beforeRequestHook"],
                "type": "guardrail",
            },
            {
                "description": paragraph("Requires metadata keys on every request"),
                "guardrailCategory": "basic",
                "id": "default.requiredMetadataKeys",
                "name": "Required metadata keys",
                "parameters": {
                    "properties": {
                        "metadataKeys": {"default": [], "description": paragraph("The metadata keys to require"), "examples": [["user_id", "team"]], "items": {"type": "string"}, "label": "Metadata keys", "type": "array"},
                        "operator": {"default": "all", "enum": ["all", "any", "none"], "type": "string"},
                    },
                    "required": ["metadataKeys"],
                    "type": "object",
                },
                "supportedHooks": ["beforeRequestHook"],
                "type": "guardrail",
            },
        ],
        "object": "list",
    })
}

/// `value` as JSON text with every object's members in reverse alphabetical order (the
/// guardrail catalog's answer, [`guardrail_catalog`]): the service sends its catalog in its
/// own order (`{"type": …, "text": …}`), which TypeScript prints as received and airs-cli-rs
/// sorts (DESIGN §12 D35), so the parity tests compare a non-alphabetical answer.
/// `serde_json` sorts a `Value`'s members, hence the hand-written order.
pub fn service_order(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let members: Vec<String> = map
                .iter()
                .rev()
                .map(|(name, member)| {
                    format!("{}:{}", Value::from(name.as_str()), service_order(member))
                })
                .collect();
            format!("{{{}}}", members.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(service_order).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}

/// `GET <admin>/integrations` (`ListIntegrationsResponseSchema`) and its detail
/// (`GatewayIntegrationSchema`): `detail` adds the credential-bearing configuration.
pub fn integration(detail: bool) -> Value {
    let mut row = json!({
        "ai_provider_id": uuid(CATALOG_PROVIDER),
        "created_at": AT,
        "description": null,
        "id": uuid(INTEGRATION),
        "last_updated_at": AT,
        "name": "OpenAI prod",
        "object": "integration",
        "organisation_id": uuid(ORGANISATION),
        "owner_id": uuid(1501),
        "slug": "openai-prod",
        "status": "active",
        "tags": null,
        "type": "ai_provider",
        "workspace_id": null,
        "workspaces_count": 1,
    });
    if detail {
        let object = row.as_object_mut().expect("object");
        object.insert(
            "configurations".into(),
            json!({
                "aws_secret_access_key": marker(17),
                "custom_headers": {"x-tenant": marker(18)},
                "custom_host": format!("https://llm.example.test/v1?key={}", marker(28)),
                "provider_auth_type": "apiKey",
            }),
        );
        object.insert("masked_key".into(), json!("sk-...abcd"));
    }
    row
}

/// `GET <admin>/integrations`: the one integration row.
pub fn list_of_integrations() -> Value {
    list_of(vec![integration(false)])
}

/// `GET <admin>/utils/static-resources/ai-providers` (`ListCatalogProvidersResponseSchema`).
pub fn catalog_providers() -> Value {
    json!({
        "data": [{"id": uuid(CATALOG_PROVIDER), "name": "OpenAI", "slug": "openai", "status": "active"}],
        "success": true,
    })
}

/// `GET <admin>/integrations/<id>/models` (`GatewayIntegrationModelsResponseSchema`): a
/// model with its pricing (`pay_as_you_go.request_token` and `response_token`, members whose
/// names carry `token` and hold only prices: printed by both CLIs, DESIGN §19.20 choice 165).
pub fn integration_models() -> Value {
    json!({
        "allow_all_models": false,
        "models": [{
            "base_model_slug": null,
            "created_at": AT,
            "description": null,
            "enabled": true,
            "is_custom": false,
            "is_finetune": false,
            "last_updated_at": null,
            "pricing_config": {
                "currency": "USD",
                "pay_as_you_go": {
                    "request_token": {"price": 0.5},
                    "response_token": {"price": 1.5},
                },
            },
            "slug": "gpt-4o",
        }],
        "object": "list",
        "total": 1,
    })
}

/// `GET <admin>/integrations/<id>/workspaces` (`GatewayIntegrationWorkspacesResponseSchema`).
pub fn integration_workspaces() -> Value {
    json!({
        "global_workspace_access": {"enabled": false},
        "object": "list",
        "total": 1,
        "workspaces": [{
            "created_at": AT,
            "enabled": true,
            "id": uuid(1),
            "last_reset_at": null,
            "last_updated_at": null,
            "rate_limits": null,
            "status": "active",
            "usage_limits": null,
        }],
    })
}

/// `GET <admin>/mcp-integrations` (`ListMcpIntegrationsResponseSchema`).
pub fn mcp_integrations() -> Value {
    json!({
        "data": [{
            "auth_type": "oauth",
            "configurations": "configured",
            "created_at": AT,
            "description": null,
            "id": uuid(MCP_INTEGRATION),
            "last_updated_at": AT,
            "name": "Search",
            "object": "mcp-integration",
            "organisation_id": uuid(ORGANISATION),
            "owner_id": uuid(1501),
            "slug": "search",
            "status": "active",
            "transport": "sse",
            "type": "remote",
            "url": "https://mcp.example.test/sse",
            "workspace_id": null,
            "workspaces_count": 1,
        }],
        "has_more": false,
        "object": "list",
        "total": 1,
    })
}

/// `GET <admin>/mcp-integrations/<id>` (`McpIntegrationDetailSchema`) with its secrets.
pub fn mcp_detail() -> Value {
    json!({
        "auth_type": "oauth",
        "configurations": {
            "client_id": "mcp-client",
            "client_secret": marker(19),
            "custom_headers": {"x-api-key": marker(20)},
        },
        "created_at": AT,
        "description": null,
        "global_workspace_access": {"enabled": false},
        "id": uuid(MCP_INTEGRATION),
        "last_updated_at": AT,
        "name": "Search",
        "object": "mcp-integration",
        "owner_id": uuid(1501),
        "secret_mappings": null,
        "slug": "search",
        "status": "active",
        "transport": "sse",
        "type": "remote",
        "url": "https://mcp.example.test/sse",
        "workspace_id": null,
    })
}

/// `GET <admin>/mcp-integrations/<id>/capabilities`
/// (`McpIntegrationCapabilitiesResponseSchema`).
pub fn mcp_capabilities() -> Value {
    json!({
        "counts": {"tools": {"enabled": 1, "total": 1}},
        "data": [{
            "annotations": null,
            "created_at": AT,
            "description": "Search the web",
            "enabled": true,
            "execution": null,
            "icons": null,
            "input_schema": {"type": "object"},
            "last_updated_at": AT,
            "name": "search",
            "object": "mcp-capability",
            "output_schema": null,
            "title": null,
            "type": "tool",
        }],
        "has_more": false,
        "object": "list",
        "total": 1,
    })
}

/// `GET <admin>/mcp-integrations/<id>/metadata` (`McpIntegrationMetadataSchema`).
pub fn mcp_metadata() -> Value {
    json!({
        "capability_flags": {"tools": true},
        "description": null,
        "icons": null,
        "instructions": null,
        "last_synced_at": AT,
        "object": "mcp-metadata",
        "protocol_version": "2025-06-18",
        "server_name": "search",
        "server_version": "1.0.0",
        "sync_error": null,
        "sync_status": "synced",
        "title": "Search",
        "website_url": null,
    })
}

/// `GET <admin>/organisations/<tsg>/info` (`GatewayOrganisationInfoSchema`).
pub fn organisation_info() -> Value {
    json!({
        "benefits": {"featureFlags": {"guardrails": 1}, "limits": {"workspaces": 10}},
        "created_at": AT,
        "disable_portkey_gateway": 0,
        "id": uuid(ORGANISATION),
        "is_first_generation_done": 1,
        "last_updated_at": AT,
        "name": "Example Org",
        "object": "organisation",
        "settings": {
            "dashboard_gateway_url": format!("https://gw.example.test/{}", marker(27)),
            "dashboard_mcp_gateway_url": "https://mcp.example.test",
            "debug_log": 0,
            "default_workspace_user_api_key_auto_create": false,
            "user_api_key_auto_create": false,
            "user_api_key_count": 1,
            "user_api_key_max_ttl": 30,
            "user_api_key_rotation_period": null,
            "user_api_key_ttl": 7,
            "user_key_metadata": 0,
            "user_key_metadata_override": 0,
        },
        "subscription": {"name": "Enterprise", "type": "paid"},
    })
}

/// `GET <admin>/organisations/self` (`OrganisationSelfResponseSchema`).
pub fn organisation_self() -> Value {
    json!({"data": {"id": uuid(ORGANISATION), "name": "Example Org", "tsg_id": TSG}, "success": true})
}

/// `GET <admin>/organisations/<tsg>/auth-settings` (`AuthSettingsResponseSchema`).
pub fn auth_settings() -> Value {
    json!({
        "data": {
            "auth_settings": {"client_id": "sso-client", "client_secret": marker(22), "issuer": "https://idp.example.test"},
            "auth_type": "scim",
            "domains": ["example.test"],
            "scim_token": marker(21),
        },
        "success": true,
    })
}

/// `GET <admin>/plugins` (`ListPluginsResponseSchema`).
pub fn plugins() -> Value {
    list_of(vec![json!({
        "created_at": AT,
        "credentials": {"api_key": marker(23), "region": "us-east-1"},
        "id": uuid(PLUGIN),
        "integration_id": uuid(INTEGRATION),
        "integration_slug": "openai-us-east-1",
        "last_updated_at": AT,
        "object": "plugin",
        "owner_id": uuid(1501),
        "plugin_provider_id": uuid(902),
        "plugin_provider_slug": "airs",
        "status": "active",
    })])
}

/// `GET <data>/providers?workspace_id=` (`ListProvidersResponseSchema`): TS prints the
/// list row's `key` (GW§6.1).
pub fn providers() -> Value {
    list_of(vec![json!({
        "created_at": AT,
        "expires_at": null,
        "id": uuid(PROVIDER),
        "integration_id": uuid(INTEGRATION),
        "key": marker(26),
        "name": "OpenAI",
        "note": null,
        "object": "provider",
        "slug": "openai-ws",
        "status": "active",
    })])
}

/// `GET <data>/providers/<id>` (`GatewayProviderDetailSchema`): its key, model config and a
/// secret mapping whose `secret_key` names the key inside the referenced secret (printed by
/// airs-cli-rs, never registered: DESIGN §19.20 choice 164).
pub fn provider_detail() -> Value {
    json!({
        "ai_provider_name": "openai",
        "created_at": AT,
        "expires_at": null,
        "id": uuid(PROVIDER),
        "integration_id": uuid(INTEGRATION),
        "key": marker(24),
        "last_reset_at": null,
        "masked_api_key": "sk-...abcd",
        "model_config": {"token": marker(25)},
        "name": "OpenAI",
        "note": null,
        "object": "provider",
        "rate_limits": [],
        "secret_mappings": [{
            "secret_key": "api_key",
            "secret_reference_id": uuid(SECRET_REFERENCE),
            "target_field": "api_key",
            "value_format": null,
        }],
        "slug": "openai-ws",
        "status": "active",
        "tags": null,
        "usage_limits": null,
    })
}

fn admin_guardrail_row() -> Value {
    json!({
        "created_at": AT,
        "id": uuid(ADMIN_GUARDRAIL),
        "last_updated_at": AT,
        "name": "Org shield",
        "organisation_id": uuid(ORGANISATION),
        "owner_id": uuid(1501),
        "slug": "org-shield",
        "status": "active",
        "target": "mcp_tools",
        "updated_by": null,
        "workspace_id": null,
    })
}

/// `GET <admin>/guardrails` (`GatewayAdminGuardrailListResponseSchema`).
pub fn admin_guardrails() -> Value {
    json!({"data": [admin_guardrail_row()], "total": 1})
}

/// `GET <admin>/guardrails/<id>` (`GatewayAdminGuardrailDetailSchema`), with the checks of
/// [`guardrail_checks`].
pub fn admin_guardrail_detail() -> Value {
    let mut detail = admin_guardrail_row();
    let object = detail.as_object_mut().expect("object");
    object.insert("checks".into(), guardrail_checks());
    object.insert("mcp_server_mappings".into(), json!([mcp_mapping()]));
    detail
}

/// One MCP mapping (`GatewayMcpServerMappingSchema`).
pub fn mcp_mapping() -> Value {
    json!({
        "capability_ids": [],
        "guardrail_id": uuid(ADMIN_GUARDRAIL),
        "id": uuid(MCP_MAPPING),
        "mcp_server_id": uuid(MCP_SERVER),
        "run_on": ["input"],
    })
}

/// `GET <admin>/guardrails/<id>/mcp-servers` (`GatewayMcpServerMappingsResponseSchema`).
pub fn admin_mcp_mappings() -> Value {
    json!([mcp_mapping()])
}

/// An empty workspace list (the unseeded server's answer; the TS doctor's probe).
pub fn workspaces_empty() -> Value {
    json!({"object": "list", "total": 0, "data": []})
}

// ---------------------------------------------------------------------------
// Chunk 3: the write answers (DESIGN §10 M6e). Each validates against both SDKs' response
// schemas. Markers 30–36 are the one-time credentials and the credentials a write answer
// echoes; 37–39 stay free for tests.
// ---------------------------------------------------------------------------

/// The ids the creates answer with.
pub const NEW_CONFIG: u64 = 302;
pub const NEW_SERVICE_KEY: u64 = 203;
pub const NEW_USER_KEY: u64 = 204;
pub const NEW_DEPLOYMENT: u64 = 402;
pub const NEW_GUARDRAIL: u64 = 602;
pub const NEW_INTEGRATION: u64 = 702;
pub const NEW_MCP_INTEGRATION: u64 = 802;
pub const NEW_PLUGIN: u64 = 902;
pub const NEW_PROVIDER: u64 = 1002;
pub const NEW_ADMIN_GUARDRAIL: u64 = 1102;

/// The answer of a key create of `kind` (`GatewayApiKeyCreateResponseSchema`) with its
/// one-time `key` (marker 30 for service keys, 31 for user keys).
pub fn key_created(kind: &str) -> Value {
    let (n, key) = if kind == "user" {
        (NEW_USER_KEY, marker(31))
    } else {
        (NEW_SERVICE_KEY, marker(30))
    };
    json!({"id": uuid(n), "key": key, "object": "api-key"})
}

/// The answer of a key rotate (`GatewayApiKeyRotateResponseSchema`; key marker 32).
pub fn key_rotated(id: &str) -> Value {
    json!({"id": id, "key": marker(32), "key_transition_expires_at": AT})
}

/// The answer of a deployment create (`GatewayDeploymentCreateResponseSchema`; markers 33
/// and 34).
pub fn deployment_created() -> Value {
    json!({
        "client_auth": marker(33),
        "credentials": {"password": marker(34), "username": "edge-agent"},
        "id": uuid(NEW_DEPLOYMENT),
        "object": "deployment",
        "organisation_id": uuid(ORGANISATION),
    })
}

/// The answer of a rotating deployment update (`GatewayWriteResponseSchema`, passthrough;
/// markers 35 and 36).
pub fn deployment_rotated() -> Value {
    json!({
        "client_auth": marker(35),
        "credentials": {"password": marker(36), "username": "edge-agent"},
        "id": uuid(DEPLOYMENT),
        "success": true,
    })
}

/// The answer of every write route whose dataset does not change.
pub fn write_answers() -> std::collections::BTreeMap<crate::Gw, Value> {
    use crate::Gw;
    let ok = || json!({"success": true});
    std::collections::BTreeMap::from([
        (
            Gw::ConfigCreate,
            json!({"id": uuid(NEW_CONFIG), "object": "config", "slug": "config-new", "version_id": uuid(NEW_CONFIG + 50)}),
        ),
        (
            Gw::ConfigUpdate,
            json!({"data": {"id": uuid(CONFIG), "version_id": uuid(CONFIG + 51)}, "success": true}),
        ),
        (
            Gw::GuardrailCreate,
            json!({"id": uuid(NEW_GUARDRAIL), "object": "guardrail", "slug": "guardrail-new", "version_id": uuid(NEW_GUARDRAIL + 50)}),
        ),
        (Gw::GuardrailUpdate, ok()),
        (
            Gw::ProviderCreate,
            json!({"id": uuid(NEW_PROVIDER), "object": "provider", "slug": "provider-new"}),
        ),
        (Gw::ProviderUpdate, ok()),
        (Gw::KeyUpdate, ok()),
        (
            Gw::DeploymentUpdate,
            json!({"id": uuid(DEPLOYMENT), "success": true}),
        ),
        (
            Gw::IntegrationCreate,
            json!({"id": uuid(NEW_INTEGRATION), "slug": "integration-new"}),
        ),
        (Gw::IntegrationUpdate, ok()),
        (Gw::ModelsSet, ok()),
        (Gw::IntegrationWorkspacesSet, ok()),
        (
            Gw::McpCreate,
            json!({"id": uuid(NEW_MCP_INTEGRATION), "slug": "mcp-new"}),
        ),
        (Gw::McpUpdate, ok()),
        (Gw::CapabilitiesSet, ok()),
        (Gw::McpWorkspacesSet, json!({})),
        (Gw::OrganisationUpdate, ok()),
        (Gw::AuthSettingsUpdate, ok()),
        (
            Gw::PluginCreate,
            json!({"id": uuid(NEW_PLUGIN), "success": true}),
        ),
        (
            Gw::AdminGuardrailCreate,
            json!({"id": uuid(NEW_ADMIN_GUARDRAIL), "slug": "admin-guardrail-new", "version_id": uuid(NEW_ADMIN_GUARDRAIL + 50)}),
        ),
        (
            Gw::AdminGuardrailUpdate,
            json!({"id": uuid(ADMIN_GUARDRAIL), "slug": "admin-guardrail-one"}),
        ),
        (
            Gw::McpSync,
            json!({"added": 1, "changed": true, "removed": 0, "updated": 0}),
        ),
        (Gw::McpUpsert, json!({"map_id": uuid(MCP_MAPPING)})),
    ])
}

// ---------------------------------------------------------------------------
// Chunk 4: the inference runtime (DESIGN §10 M6e). Every answer and event validates
// against both SDKs' schemas. The runtime key is a tenant secret (`aiGwInferenceApiKey`,
// the Rust store's `gatewayInferenceApiKey`), so the runner's leak check forbids it.
// ---------------------------------------------------------------------------

/// The runtime key the inference routes accept (`x-portkey-api-key`).
pub const INFERENCE_KEY: &str = "FAKE-GW-INFERENCE-KEY";
/// The default chat model and embedding model of the inference tests.
pub const INFERENCE_MODEL: &str = "openai__gpt-x";
pub const EMBEDDING_MODEL: &str = "openai__emb-x";

/// A chat completion with `text` (`GatewayInferenceCreateChatCompletionResponseSchema`).
pub fn chat_completion(text: &str) -> Value {
    json!({
        "choices": [{
            "finish_reason": "stop",
            "index": 0,
            "logprobs": null,
            "message": {"content": text, "refusal": null, "role": "assistant"},
        }],
        "created": 1_760_000_000,
        "id": "chatcmpl-1",
        "model": INFERENCE_MODEL,
        "object": "chat.completion",
        "usage": {"completion_tokens": 4, "prompt_tokens": 3, "total_tokens": 7},
    })
}

/// One chat stream chunk carrying `text` (`…CreateChatCompletionStreamResponseSchema`).
pub fn chat_chunk(text: &str) -> Value {
    json!({
        "choices": [{"delta": {"content": text}, "finish_reason": null, "index": 0}],
        "created": 1_760_000_000,
        "id": "chatcmpl-1",
        "model": INFERENCE_MODEL,
        "object": "chat.completion.chunk",
    })
}

/// An embedding answer (`GatewayInferenceCreateEmbeddingResponseSchema`).
pub fn embedding() -> Value {
    json!({
        "data": [{"embedding": [0.5, 0.25], "index": 0, "object": "embedding"}],
        "model": EMBEDDING_MODEL,
        "object": "list",
        "usage": {"prompt_tokens": 1, "total_tokens": 1},
    })
}

/// A Responses answer of `status` with one `output_text` part (`GatewayInferenceResponseSchema`).
pub fn response(status: &str, text: &str) -> Value {
    let output = if text.is_empty() {
        json!([])
    } else {
        json!([{
            "content": [{"annotations": [], "text": text, "type": "output_text"}],
            "id": "msg_1",
            "role": "assistant",
            "status": "completed",
            "type": "message",
        }])
    };
    json!({
        "created_at": 1_760_000_000,
        "error": null,
        "id": "resp_1",
        "incomplete_details": null,
        "instructions": null,
        "metadata": {},
        "model": INFERENCE_MODEL,
        "object": "response",
        "output": output,
        "parallel_tool_calls": true,
        "status": status,
        "temperature": 1,
        "tool_choice": "auto",
        "tools": [],
        "top_p": 1,
    })
}

/// A `response.output_text.delta` event (`GatewayInferenceResponseStreamEventSchema`).
pub fn response_delta(text: &str, sequence: u64) -> Value {
    json!({
        "content_index": 0,
        "delta": text,
        "item_id": "msg_1",
        "output_index": 0,
        "sequence_number": sequence,
        "type": "response.output_text.delta",
    })
}

/// A terminal Responses event: `response.completed`, `response.failed` or
/// `response.incomplete`.
pub fn response_terminal(kind: &str, sequence: u64) -> Value {
    let status = kind.trim_start_matches("response.");
    json!({"response": response(status, ""), "sequence_number": sequence, "type": kind})
}

/// An SSE body: one `data:` event per value (compact JSON), a keepalive comment after the
/// first, and `data: [DONE]` when `done`.
pub fn sse(events: &[Value], done: bool) -> Vec<u8> {
    let mut body = String::new();
    for (index, event) in events.iter().enumerate() {
        body.push_str(&format!("data: {event}\n\n"));
        if index == 0 {
            body.push_str(": keepalive\n\n");
        }
    }
    if done {
        body.push_str("data: [DONE]\n\n");
    }
    body.into_bytes()
}

/// The default chat stream: `Hel`, `lo` and `[DONE]`.
pub fn chat_stream() -> Vec<u8> {
    sse(&[chat_chunk("Hel"), chat_chunk("lo")], true)
}

/// The default Responses stream: `Hi`, ` there`, then `response.completed`.
pub fn response_stream() -> Vec<u8> {
    sse(
        &[
            response_delta("Hi", 1),
            response_delta(" there", 2),
            response_terminal("response.completed", 3),
        ],
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog's answer is the catalog, in a non-alphabetical member order at every
    /// depth (`{"type": …, "text": …}`, as the service sends it).
    #[test]
    fn the_catalog_is_sent_in_the_service_order() {
        let catalog = guardrail_catalog();
        let text = service_order(&catalog);
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), catalog);
        assert_ne!(text, catalog.to_string());
        assert!(text.starts_with(r#"{"object":"list","evals":[{"#), "{text}");
        assert!(text.contains(r#"{"type":"subHeading","text":"#), "{text}");
        assert_eq!(
            service_order(&json!({"a": [1, "x\"y", null], "b": {"d": true, "c": 1.5}})),
            r#"{"b":{"d":true,"c":1.5},"a":[1,"x\"y",null]}"#
        );
    }
}
