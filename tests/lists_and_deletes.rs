//! Runs the built `fabric` binary against a scripted gateway and checks what
//! lists and deletes print on standard output and standard error.

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    thread,
};

use tempfile::TempDir;

struct Reply {
    method: &'static str,
    path: &'static str,
    status: &'static str,
    body: String,
}

fn reply(
    method: &'static str,
    path: &'static str,
    status: &'static str,
    body: impl Into<String>,
) -> Reply {
    Reply {
        method,
        path,
        status,
        body: body.into(),
    }
}

struct Output {
    stdout: String,
    stderr: String,
}

/// Starts a gateway that answers each request from `replies` and runs
/// `fabric agent-gateway <args>` against it with a saved connection.
fn fabric(
    replies: Vec<Reply>,
    args: &[&str],
) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener
        .local_addr()
        .expect("address")
        .port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let text = String::from_utf8_lossy(&request).into_owned();
            let mut line = text
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace();
            let (method, path) = (
                line.next()
                    .unwrap_or_default(),
                line.next()
                    .unwrap_or_default(),
            );
            let answer = replies.iter().find(|reply| {
                reply.method == method
                    && format!("/api{}", reply.path)
                        == path
                            .split('?')
                            .next()
                            .unwrap_or_default()
            });
            let (status, body) = answer.map_or(("404 Not Found", "{}"), |reply| (reply.status, reply.body.as_str()));
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let home = TempDir::new().expect("temp dir");
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"http://127.0.0.1:{port}\"\n");
    for directory in [
        home.path()
            .join("Library/Application Support/fabric"),
        home.path().join("xdg/fabric"),
    ] {
        write_config(&directory, &config);
    }
    let result = Command::new(env!("CARGO_BIN_EXE_fabric"))
        .arg("agent-gateway")
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("xdg"))
        .env("FABRIC_TOKEN", "test-token")
        .env_remove("FABRIC_HOST")
        .env_remove("FABRIC_CONNECTION")
        .output()
        .expect("run fabric");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
    }
}

fn write_config(
    directory: &Path,
    config: &str,
) {
    fs::create_dir_all(directory).expect("config directory");
    fs::write(directory.join("config.toml"), config).expect("config file");
}

const SURFACES: &str = r#"[
  {"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","protocol":"mcp"},
   "target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[{"alias":"gh"}]}},
  {"surface_id":"s-22","name":"Customer support","access_point":{"listen_address":"0.0.0.0:8081","route":"/help","protocol":"a2a"},
   "target":{"endpoint":"http://127.0.0.1:4000"}}
]"#;

const POLICIES: &str = r#"[
  {"id":"p-1","name":"Require header","description":"Blocks requests without it","policy_type":"agent_surface",
   "policy":"x","enabled":true,"created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-30T10:00:00Z","version":2}
]"#;

#[test]
fn surfaces_list_prints_a_header_and_aligned_columns() {
    let out = fabric(vec![reply("GET", "/v1/surfaces", "200 OK", SURFACES)], &["surfaces", "list"]);

    assert_eq!(
        out.stdout,
        "NAME              ID    PROTOCOL  ROUTE   TARGET                 TRANSIT POINTS\n\
         Sales             s-1   mcp       /sales  http://127.0.0.1:3000  gh\n\
         Customer support  s-22  a2a       /help   http://127.0.0.1:4000  -\n"
    );
}

#[test]
fn policies_list_shows_version_and_updated() {
    let out = fabric(vec![reply("GET", "/v1/policy-definitions", "200 OK", POLICIES)], &["policies", "list"]);

    assert_eq!(
        out.stdout,
        "NAME            ID   DESCRIPTION                 ENABLED  VERSION  UPDATED\n\
         Require header  p-1  Blocks requests without it  yes      2        2026-09-30T10:00:00Z\n"
    );
}

#[test]
fn another_resource_uses_its_own_columns() {
    let body = r#"[{"id":"cp-1","name":"GitHub","provider_id":"github","provider_type":"oauth2"}]"#;
    let out = fabric(vec![reply("GET", "/v1/credential-providers", "200 OK", body)], &["credential-providers", "list"]);

    assert_eq!(out.stdout, "NAME    ID    PROVIDER ID  TYPE\nGitHub  cp-1  github       oauth2\n");
}

#[test]
fn lists_with_output_json_print_the_gateways_own_document() {
    let out = fabric(vec![reply("GET", "/v1/surfaces", "200 OK", SURFACES)], &["--output", "json", "surfaces", "list"]);

    let printed: serde_json::Value = serde_json::from_str(&out.stdout).expect("json on standard output");
    let sent: serde_json::Value = serde_json::from_str(SURFACES).expect("json");
    assert_eq!(printed, sent);
}

#[test]
fn an_empty_list_says_there_is_nothing_yet() {
    let out = fabric(vec![reply("GET", "/v1/surfaces", "200 OK", "[]")], &["surfaces", "list"]);

    assert_eq!(out.stdout, "No surfaces yet.\n");
}

#[test]
fn an_empty_list_with_output_json_stays_an_empty_array() {
    let out = fabric(vec![reply("GET", "/v1/surfaces", "200 OK", "[]")], &["-o", "json", "surfaces", "list"]);

    assert_eq!(out.stdout.trim(), "[]");
}

#[test]
fn deleting_with_an_empty_body_prints_one_line_instead_of_null() {
    let out = fabric(
        vec![reply("DELETE", "/v1/credential-providers/cp-1", "200 OK", "")],
        &["credential-providers", "delete", "cp-1"],
    );

    assert_eq!(out.stdout, "Deleted credential provider 'cp-1'\n");
}

#[test]
fn deleting_with_a_204_prints_one_line() {
    let out = fabric(vec![reply("DELETE", "/v1/issuers/i-1", "204 No Content", "")], &["issuers", "delete", "i-1"]);

    assert_eq!(out.stdout, "Deleted issuer 'i-1'\n");
}

#[test]
fn deleting_with_output_json_prints_what_the_gateway_returned() {
    let empty = fabric(
        vec![reply("DELETE", "/v1/issuers/i-1", "204 No Content", "")],
        &["--output", "json", "issuers", "delete", "i-1"],
    );
    let with_body = fabric(
        vec![
            reply("GET", "/v1/surfaces", "200 OK", SURFACES),
            reply("DELETE", "/v1/surfaces/s-1", "200 OK", r#"{"deleted":true}"#),
        ],
        &["--output", "json", "surfaces", "delete", "s-1"],
    );

    assert_eq!(empty.stdout, "null\n");
    let printed: serde_json::Value = serde_json::from_str(&with_body.stdout).expect("json");
    assert_eq!(printed, serde_json::json!({"deleted": true}));
}

#[test]
fn deleting_a_surface_prints_one_line_instead_of_the_gateways_body() {
    let out = fabric(
        vec![
            reply("GET", "/v1/surfaces", "200 OK", SURFACES),
            reply("DELETE", "/v1/surfaces/s-1", "200 OK", r#"{"surface_id":"s-1","name":"Sales","target":{}}"#),
        ],
        &["surfaces", "delete", "s-1"],
    );

    assert_eq!(out.stdout, "Deleted surface 's-1'\n");
}

#[test]
fn deleting_a_surface_by_name_keeps_the_note_on_standard_error() {
    let out = fabric(
        vec![reply("GET", "/v1/surfaces", "200 OK", SURFACES), reply("DELETE", "/v1/surfaces/s-1", "200 OK", "{}")],
        &["surfaces", "delete", "Sales"],
    );

    assert_eq!(out.stdout, "Deleted surface 's-1'\n");
    assert!(
        out.stderr
            .contains("using surface s-1 (Sales)"),
        "{}",
        out.stderr
    );
}

const SECRET_ID: &str = "11111111-2222-4333-8444-555555555555";
const KNOWN_ID_LIST: &str =
    r#"[{"id":"11111111-2222-4333-8444-555555555555","name":"x","secret_id":"s","certificate_id":"c"}]"#;

#[test]
fn certificates_list_shows_the_columns_the_list_endpoint_returns() {
    let body = r#"[{"id":"c-1","name":"Edge","certificate_id":"cid","description":null,"tags":[],"kind":"tls",
        "created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-30T10:00:00Z","active":true}]"#;
    let out = fabric(vec![reply("GET", "/v1/certificates", "200 OK", body)], &["certificates", "list"]);

    assert_eq!(out.stdout, "NAME  ID   KIND  ACTIVE  UPDATED\nEdge  c-1  tls   yes     2026-09-30T10:00:00Z\n");
}

#[test]
fn connection_points_list_shows_enabled_uses_and_expiry() {
    let body = r#"[{"id":"cp-1","gateway_id":"gw-1","mediator_id":"m","connection_point_did":"did:x","name":"Front door",
        "description":"d","oob_id":"o","oob_url":"u","oob_message":{},"use_count":4,"expires_at":null,
        "created_at":"2026-09-01T00:00:00Z","enabled":true}]"#;
    let out = fabric(vec![reply("GET", "/v1/connection-points", "200 OK", body)], &["connection-points", "list"]);

    assert_eq!(
        out.stdout,
        "NAME        ID    CONNECTION  ENABLED  USES  EXPIRES\nFront door  cp-1  gw-1        yes      4     never\n"
    );
}

#[test]
fn identities_list_unwraps_the_envelope_and_shows_did_version_and_state() {
    let body = r#"{"count":1,"identities":[{"id":"7b0f3a52-6d1e-4c8a-9b21-0d5e4f6a7b8c",
        "did":"did:webvh:abc:example.com:agents:sales","version":2,"created_at":"2026-09-01T00:00:00Z",
        "updated_at":"2026-09-30T10:00:00Z","active":true}]}"#;
    let out = fabric(vec![reply("GET", "/v1/identities", "200 OK", body)], &["identities", "list"]);

    assert_eq!(
        out.stdout,
        "DID                                     ID                                    VERSION  ACTIVE  UPDATED\n\
         did:webvh:abc:example.com:agents:sales  7b0f3a52-6d1e-4c8a-9b21-0d5e4f6a7b8c  2        yes     2026-09-30T10:00:00Z\n"
    );
}

#[test]
fn users_connections_and_proxies_use_their_own_columns() {
    let users =
        r#"[{"username":"ana","user_id":"u-1","role":"administrator","status":"approved","email":"ana@example.com"}]"#;
    let connections = r#"[{"id":"g-1","name":"Partner","description":"","did":"did:x","gateway_type":"remote","status":"active",
        "created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-30T10:00:00Z"}]"#;
    let proxies = r#"[{"id":"m-1","name":"Docs","description":"Docs API","base_url":"https://docs.example.com","status":"active"}]"#;

    let users = fabric(vec![reply("GET", "/v1/users", "200 OK", users)], &["users", "list"]);
    let connections = fabric(vec![reply("GET", "/v1/gateways", "200 OK", connections)], &["connections", "list"]);
    let proxies = fabric(vec![reply("GET", "/v1/mcp-proxies", "200 OK", proxies)], &["mcp-proxies", "list"]);

    assert_eq!(
        users.stdout,
        "USERNAME  ID   ROLE           STATUS    EMAIL\nana       u-1  administrator  approved  ana@example.com\n"
    );
    assert_eq!(
        connections.stdout,
        "NAME     ID   TYPE    STATUS  UPDATED\nPartner  g-1  remote  active  2026-09-30T10:00:00Z\n"
    );
    assert_eq!(
        proxies.stdout,
        "NAME  ID   STATUS  BASE URL                  DESCRIPTION\nDocs  m-1  active  https://docs.example.com  Docs API\n"
    );
}

#[test]
fn identifier_columns_are_never_cut_short() {
    let long = "x".repeat(90);
    let body = format!(r#"[{{"id":"cp-1","name":"n","provider_id":"{long}","provider_type":"oauth2"}}]"#);
    let out = fabric(vec![reply("GET", "/v1/credential-providers", "200 OK", body)], &["credential-providers", "list"]);

    assert!(out.stdout.contains(&long), "{}", out.stdout);
}

#[test]
fn grants_list_shows_the_agent_provider_and_expiry() {
    let body = r#"[{"id":"gr-1","agent_did":"did:key:abc","provider_id":"github","token_type":"bearer","scopes":["repo"],
        "expires_at":"2026-12-01T00:00:00Z","is_expired":false,"can_refresh":true}]"#;
    let out = fabric(vec![reply("GET", "/v1/delegation-vault", "200 OK", body)], &["delegation-vault", "list"]);

    assert_eq!(
        out.stdout,
        "ID    AGENT DID    PROVIDER  EXPIRES               EXPIRED\ngr-1  did:key:abc  github    2026-12-01T00:00:00Z  no\n"
    );
}

#[test]
fn secret_certificate_grant_and_payment_deletes_print_the_same_kind_of_line() {
    let secret = fabric(
        vec![
            reply("GET", "/v1/secrets", "200 OK", KNOWN_ID_LIST),
            reply("DELETE", "/v1/secrets/11111111-2222-4333-8444-555555555555", "204 No Content", ""),
        ],
        &["secrets", "delete", SECRET_ID],
    );
    let certificate = fabric(
        vec![
            reply("GET", "/v1/certificates", "200 OK", KNOWN_ID_LIST),
            reply("DELETE", "/v1/certificates/11111111-2222-4333-8444-555555555555", "204 No Content", ""),
        ],
        &["certificates", "delete", SECRET_ID],
    );
    let grant = fabric(
        vec![reply("DELETE", "/v1/delegation-vault/gr-1", "204 No Content", "")],
        &["delegation-vault", "revoke", "gr-1"],
    );
    let payment = fabric(
        vec![reply("DELETE", "/admin/x402/transactions/t-1", "204 No Content", "")],
        &["payments", "delete", "t-1", "--yes"],
    );

    assert_eq!(secret.stdout, format!("Deleted secret '{SECRET_ID}'\n"));
    assert_eq!(certificate.stdout, format!("Deleted certificate '{SECRET_ID}'\n"));
    assert_eq!(grant.stdout, "Revoked grant 'gr-1'\n");
    assert_eq!(payment.stdout, "Deleted x402 payment 't-1'\n");
}

#[test]
fn a_typed_id_with_a_line_break_stays_on_one_line() {
    let out = fabric(vec![reply("DELETE", "/v1/issuers/a%0Ab", "204 No Content", "")], &["issuers", "delete", "a\nb"]);

    assert_eq!(out.stdout, "Deleted issuer 'a b'\n");
}

#[test]
fn a_raw_api_call_that_returns_a_list_prints_the_shared_table() {
    let out = fabric(
        vec![reply("GET", "/v1/issuers", "200 OK", r#"[{"id":"i-1","name":"Acme","description":"Issuer"}]"#)],
        &["api", "get", "/v1/issuers"],
    );

    assert_eq!(out.stdout, "NAME  ID   DESCRIPTION\nAcme  i-1  Issuer\n");
}

#[test]
fn a_raw_api_call_that_returns_an_empty_list_says_there_is_nothing_yet() {
    let out = fabric(vec![reply("GET", "/v1/issuers", "200 OK", "[]")], &["api", "get", "/v1/issuers"]);

    assert_eq!(out.stdout, "No items yet.\n");
}

#[test]
fn revoking_an_access_token_prints_the_quoted_id_like_other_removals() {
    let out = fabric(
        vec![reply("DELETE", "/v1/access-tokens/t-1", "204 No Content", "")],
        &["tokens", "revoke", "t-1", "--yes"],
    );

    assert_eq!(out.stdout, "Revoked access token 't-1'\n");
}

#[test]
fn payments_list_prints_a_header_and_aligned_rows() {
    let body = r#"{"verifications":[{"id":"tx-1","surface_id":"sales","status":"verified","amount":"5","asset":"USDC","created_at":1790000000}]}"#;
    let out = fabric(
        vec![reply("GET", "/admin/x402/transactions", "200 OK", body)],
        &["payments", "list", "--store", "x402"],
    );

    assert_eq!(
        out.stdout,
        "ID    STORE  SURFACE  STATUS    AMOUNT  CURRENCY  CREATED\ntx-1  x402   sales    verified  5       USDC      1790000000\n"
    );
}

#[test]
fn audit_list_prints_a_header_and_aligned_rows() {
    let body = r#"{"events":[{"timestamp":"2026-09-21T10:00:00Z","event":{"policy_decision":{"scope":"surface","decision":"deny","surface_id":"sales"}}},{"timestamp":"2026-09-21T10:05:00Z","event":"user_tokens_revoked","detail":"0 tokens revoked"}],"total":2}"#;
    let out = fabric(vec![reply("GET", "/v1/audit", "200 OK", body)], &["audit", "list"]);

    assert_eq!(
        out.stdout,
        "TIMESTAMP             EVENT                SURFACE  DECISION  DETAIL\n2026-09-21T10:00:00Z  policy_decision      sales    deny      -\n2026-09-21T10:05:00Z  user_tokens_revoked  -        -         0 tokens revoked\n"
    );
    assert_eq!(out.stderr, "");
}

#[test]
fn an_empty_audit_list_says_so_and_keeps_the_notes_on_standard_error() {
    let out = fabric(vec![reply("GET", "/v1/audit", "200 OK", r#"{"events":[],"total":0}"#)], &["audit", "list"]);

    assert_eq!(out.stdout, "No audit events yet.\n");
    assert!(
        out.stderr
            .contains("admin API calls such as creating an identity are not audited"),
        "got: {}",
        out.stderr
    );
}

#[test]
fn audit_list_with_output_json_prints_the_gateways_own_document() {
    let body = r#"{"events":[{"timestamp":"t1","event":"consent_granted"}],"total":1}"#;
    let out = fabric(vec![reply("GET", "/v1/audit", "200 OK", body)], &["audit", "list", "--output", "json"]);
    let printed: serde_json::Value = serde_json::from_str(&out.stdout).expect("JSON");

    assert_eq!(printed, serde_json::from_str::<serde_json::Value>(body).unwrap());
}

#[test]
fn api_keys_list_prints_a_header_and_aligned_rows() {
    let body = r#"[{"key_id":"k-1","agent_id":"s-1","client_id":"client-a","status":"active","created_at":"2026-09-01T00:00:00Z","issuer":{}}]"#;
    let out = fabric(vec![reply("GET", "/v1/api-keys", "200 OK", body)], &["api-keys", "list"]);

    assert_eq!(out.stdout, "KEY ID  SURFACE  CLIENT ID  STATUS\nk-1     s-1      client-a   active\n");
}

#[test]
fn config_list_prints_the_saved_connections_with_the_current_one_marked() {
    let out = fabric(vec![], &["config", "list"]);

    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", out.stdout);
    assert!(lines[0].starts_with("NAME  HOST") && lines[0].ends_with("CURRENT"), "{}", out.stdout);
    assert!(lines[1].starts_with("test  http://127.0.0.1:") && lines[1].ends_with("yes"), "{}", out.stdout);
}

#[test]
fn tokens_list_uses_the_shared_table_with_status_and_a_scope_summary() {
    let body = r#"{"access_tokens":[
        {"id":"t-1","name":"ci","scopes":["surfaces.view","policies.view"],"created_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z"},
        {"id":"t-2","name":"old\nbot","scopes":[],"created_at":"2026-08-01T00:00:00Z","revoked_at":"2026-08-02T00:00:00Z"}]}"#;
    let out = fabric(vec![reply("GET", "/v1/access-tokens", "200 OK", body)], &["tokens", "list"]);

    assert_eq!(
        out.stdout,
        "NAME     ID   STATUS   SCOPES                       CREATED               EXPIRES\n\
         ci       t-1  ACTIVE   surfaces.view,policies.view  2026-09-01T00:00:00Z  2026-12-01T00:00:00Z\n\
         old bot  t-2  REVOKED  -                            2026-08-01T00:00:00Z  never\n"
    );
}

#[test]
fn an_empty_tokens_list_says_there_are_none_yet() {
    let out = fabric(vec![reply("GET", "/v1/access-tokens", "200 OK", r#"{"access_tokens":[]}"#)], &["tokens", "list"]);

    assert_eq!(out.stdout, "No access tokens yet.\n");
}

#[test]
fn an_empty_payments_list_says_there_are_none_yet() {
    let out = fabric(
        vec![reply("GET", "/admin/x402/transactions", "200 OK", r#"{"verifications":[]}"#)],
        &["payments", "list", "--store", "x402"],
    );

    assert_eq!(out.stdout, "No payments yet.\n");
}

#[test]
fn revoking_a_users_grants_with_an_empty_answer_prints_one_line() {
    let reply_for = || vec![reply("DELETE", "/v1/delegation-vault/by-user/sha256%3Aabc", "204 No Content", "")];

    let table = fabric(reply_for(), &["delegation-vault", "revoke-user", "sha256:abc"]);
    let json = fabric(reply_for(), &["-o", "json", "delegation-vault", "revoke-user", "sha256:abc"]);

    assert_eq!(table.stdout, "Revoked grants for user 'sha256:abc'\n");
    assert_eq!(json.stdout, "null\n");
}

#[test]
fn revoking_a_users_grants_says_how_many_went_and_json_keeps_the_answer() {
    let reply_for = |count: u32| {
        vec![reply(
            "DELETE",
            "/v1/delegation-vault/by-user/sha256%3Aabc",
            "200 OK",
            format!(r#"{{"revoked":{count}}}"#),
        )]
    };

    let many = fabric(reply_for(2), &["delegation-vault", "revoke-user", "sha256:abc"]);
    let one = fabric(reply_for(1), &["delegation-vault", "revoke-user", "sha256:abc"]);
    let json = fabric(reply_for(2), &["-o", "json", "delegation-vault", "revoke-user", "sha256:abc"]);

    assert_eq!(many.stdout, "Revoked 2 grants for user 'sha256:abc'\n");
    assert_eq!(one.stdout, "Revoked 1 grant for user 'sha256:abc'\n");
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed, serde_json::json!({"revoked": 2}));
}

#[test]
fn deactivating_an_identity_prints_one_line_even_when_the_gateway_sends_a_body() {
    let body = r#"{"id":"i-1","did":"did:webvh:x","active":false}"#;
    let table =
        fabric(vec![reply("DELETE", "/v1/identities/i-1", "200 OK", body)], &["identities", "deactivate", "i-1"]);
    let json = fabric(
        vec![reply("DELETE", "/v1/identities/i-1", "200 OK", body)],
        &["-o", "json", "identities", "deactivate", "i-1"],
    );

    assert_eq!(table.stdout, "Deactivated identity 'i-1'\n");
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed["did"], "did:webvh:x");
}

#[test]
fn json_output_for_tokens_payments_api_keys_and_config_lists_is_the_gateways_document() {
    let tokens = r#"{"access_tokens":[{"id":"t-1","name":"ci","scopes":["a"]}]}"#;
    let payments = r#"{"verifications":[{"id":"tx-1","surface_id":"s","status":"verified","amount":"5","asset":"USDC","created_at":1}]}"#;
    let keys = r#"[{"key_id":"k-1","agent_id":"s-1","client_id":"c","status":"active"}]"#;

    let tokens_out =
        fabric(vec![reply("GET", "/v1/access-tokens", "200 OK", tokens)], &["-o", "json", "tokens", "list"]);
    let payments_out = fabric(
        vec![reply("GET", "/admin/x402/transactions", "200 OK", payments)],
        &["-o", "json", "payments", "list", "--store", "x402"],
    );
    let keys_out = fabric(vec![reply("GET", "/v1/api-keys", "200 OK", keys)], &["-o", "json", "api-keys", "list"]);
    let config_out = fabric(vec![], &["-o", "json", "config", "list"]);

    let parse = |text: &str| -> serde_json::Value { serde_json::from_str(text).expect("json on standard output") };
    assert_eq!(parse(&tokens_out.stdout), parse(tokens));
    assert_eq!(parse(&payments_out.stdout)[0]["id"], "tx-1");
    assert_eq!(parse(&payments_out.stdout)[0]["currency"], "USDC");
    assert_eq!(parse(&keys_out.stdout), parse(keys));
    let config = parse(&config_out.stdout);
    assert_eq!(config[0]["name"], "test");
    assert_eq!(config[0]["current"], true);
}

#[test]
fn policy_versions_print_their_own_columns() {
    let body = r#"[{"version":2,"policy":"x","content_hash":"abc123","created_at":"2026-09-30T10:00:00Z","created_by":"ana","note":"tighten"},
        {"version":1,"policy":"y","content_hash":"def456","created_at":"2026-09-01T00:00:00Z"}]"#;
    let out = fabric(
        vec![reply("GET", "/v1/policy-definitions/p-1/versions", "200 OK", body)],
        &["policies", "versions", "p-1"],
    );

    assert_eq!(
        out.stdout,
        "VERSION  HASH    CREATED               BY   NOTE\n\
         2        abc123  2026-09-30T10:00:00Z  ana  tighten\n\
         1        def456  2026-09-01T00:00:00Z  -    -\n"
    );
}

#[test]
fn an_identity_history_is_still_printed_as_the_gateways_document() {
    let body = r#"{"did":"did:webvh:x","versions":[{"version_id":"1-abc","version_number":1}],"total_versions":1}"#;
    let out =
        fabric(vec![reply("GET", "/v1/identities/i-1/history", "200 OK", body)], &["identities", "history", "i-1"]);

    assert!(out.stdout.starts_with("{\n"), "{}", out.stdout);
    assert!(
        out.stdout
            .contains("\"total_versions\": 1"),
        "{}",
        out.stdout
    );
}
