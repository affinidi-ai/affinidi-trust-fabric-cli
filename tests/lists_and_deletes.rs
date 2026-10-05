//! Runs the built `fabric` binary against a scripted gateway and checks what
//! lists and deletes print on standard output and standard error.

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
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
    /// The request line of every request the gateway received.
    requests: Vec<String>,
    success: bool,
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
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let recorder = Arc::clone(&seen);
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
            // Read the whole request body before answering, so a reply never
            // races a client that is still sending.
            let head_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map_or(request.len(), |position| position + 4);
            let wanted = String::from_utf8_lossy(&request[..head_end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| {
                            value
                                .trim()
                                .parse::<usize>()
                                .ok()
                        })
                        .flatten()
                })
                .unwrap_or(0);
            while request.len() < head_end + wanted {
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
            recorder
                .lock()
                .expect("recorder")
                .push(format!("{method} {path}"));
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
        requests: seen
            .lock()
            .expect("recorder")
            .clone(),
        success: result.status.success(),
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
            .contains("note: using surface s-1 (Sales)"),
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
        "ID    STORE  SURFACE  STATUS    AMOUNT  CURRENCY  CREATED\ntx-1  x402   sales    verified  5       USDC      2026-09-21T14:13:20Z\n"
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
            .lines()
            .all(|line| line.starts_with("note: ")),
        "got: {}",
        out.stderr
    );
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
         old bot  t-2  REVOKED  full role                    2026-08-01T00:00:00Z  never\n"
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
    assert_eq!(parse(&payments_out.stdout)[0]["created_at"], 1);
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

/// Writes a JSON request document into a new temporary directory. Keep the
/// directory alive for as long as the command runs.
fn request_file(contents: &str) -> (TempDir, String) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir
        .path()
        .join("request.json");
    fs::write(&path, contents).expect("request file");
    (
        dir,
        path.to_string_lossy()
            .into_owned(),
    )
}

#[test]
fn creating_a_shared_resource_prints_one_line_and_json_keeps_the_answer() {
    let (_dir, file) = request_file(r#"{"name":"Acme"}"#);
    let answer = r#"{"id":"i-1","name":"Acme","did":"did:web:x","created_at":"x","updated_at":"y"}"#;
    let routes = || vec![reply("POST", "/v1/issuers", "200 OK", answer)];

    let table = fabric(routes(), &["issuers", "create", "--file", &file]);
    let json = fabric(routes(), &["-o", "json", "issuers", "create", "--file", &file]);

    assert_eq!(table.stdout, "Created issuer 'i-1'\n");
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed["did"], "did:web:x");
}

#[test]
fn creating_an_access_token_prints_the_token_alone_and_the_confirmation_on_standard_error() {
    let answer = r#"{"id":"t-1","name":"ci","token":"agpat_secret"}"#;
    let routes = || vec![reply("POST", "/v1/access-tokens", "200 OK", answer)];

    let table = fabric(routes(), &["tokens", "create", "--name", "ci", "--scope", "surfaces.view"]);
    let json = fabric(routes(), &["-o", "json", "tokens", "create", "--name", "ci", "--scope", "surfaces.view"]);

    assert_eq!(table.stdout, "agpat_secret\n");
    assert!(
        table
            .stderr
            .contains("Created access token 't-1'"),
        "{}",
        table.stderr
    );
    assert!(
        table
            .stderr
            .contains("note: this is the only time the access token secret is shown, so store it securely now."),
        "{}",
        table.stderr
    );
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed["token"], "agpat_secret");
}

#[test]
fn rotating_an_access_token_names_it_and_prints_the_new_token() {
    let answer = r#"{"token":"agpat_new"}"#;
    let table = fabric(
        vec![reply("POST", "/v1/access-tokens/t-1/rotate", "200 OK", answer)],
        &["tokens", "rotate", "t-1", "--yes"],
    );

    assert_eq!(table.stdout, "agpat_new\n");
    assert!(
        table
            .stderr
            .contains("Rotated access token 't-1'"),
        "{}",
        table.stderr
    );
}

#[test]
fn creating_and_rotating_an_api_key_print_the_secret_alone_and_the_confirmation_on_standard_error() {
    let created = r#"{"key_id":"k-1","secret":"sk_live","status":"active"}"#;
    let create_routes = || vec![reply("POST", "/v1/api-keys/s-1", "200 OK", created)];
    let rotate_routes = || vec![reply("POST", "/v1/api-keys/s-1/k-1/rotate", "200 OK", created)];

    let create = fabric(create_routes(), &["api-keys", "create", "s-1", "--client-id", "billing"]);
    let rotate = fabric(rotate_routes(), &["api-keys", "rotate", "k-1", "--agent-id", "s-1", "--yes"]);
    let json = fabric(create_routes(), &["-o", "json", "api-keys", "create", "s-1", "--client-id", "billing"]);

    assert_eq!(create.stdout, "sk_live\n");
    assert_eq!(rotate.stdout, "sk_live\n");
    assert!(
        create
            .stderr
            .contains("Created API key 'k-1'"),
        "{}",
        create.stderr
    );
    assert!(
        rotate
            .stderr
            .contains("Rotated API key 'k-1'"),
        "{}",
        rotate.stderr
    );
    assert!(
        create
            .stderr
            .contains("note: this is the only time the API key secret is shown, so store it securely now."),
        "{}",
        create.stderr
    );
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed["secret"], "sk_live");
}

#[test]
fn updating_a_shared_resource_prints_one_line_and_json_keeps_the_answer() {
    let (_dir, file) = request_file(r#"{"name":"Acme"}"#);
    let answer = r#"{"id":"i-1","name":"Acme"}"#;
    let routes = || vec![reply("PUT", "/v1/issuers/i-1", "200 OK", answer)];

    let table = fabric(routes(), &["issuers", "update", "i-1", "--file", &file]);
    let json = fabric(routes(), &["-o", "json", "issuers", "update", "i-1", "--file", &file]);

    assert_eq!(table.stdout, "Updated issuer 'i-1'\n");
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed["name"], "Acme");
}

#[test]
fn updating_a_user_a_policy_and_a_secret_print_one_line_each() {
    let (_dir, file) = request_file(r#"{"name":"x"}"#);
    let user = fabric(
        vec![reply("PUT", "/v1/users/u-1", "200 OK", r#"{"user_id":"u-1"}"#)],
        &["users", "update", "u-1", "--file", &file],
    );
    let policy = fabric(
        vec![reply("PUT", "/v1/policy-definitions/p-1", "200 OK", r#"{"id":"p-1"}"#)],
        &["policies", "update", "p-1", "--file", &file],
    );
    let secret = fabric(
        vec![
            reply("GET", "/v1/secrets", "200 OK", KNOWN_ID_LIST),
            reply("PUT", "/v1/secrets/11111111-2222-4333-8444-555555555555", "200 OK", r#"{"id":"x","value":"v"}"#),
        ],
        &["secrets", "update", SECRET_ID, "--file", &file],
    );

    assert_eq!(user.stdout, "Updated user 'u-1'\n");
    assert_eq!(policy.stdout, "Updated policy 'p-1'\n");
    assert_eq!(secret.stdout, format!("Updated secret '{SECRET_ID}'\n"));
}

#[test]
fn updating_a_surface_from_a_file_prints_one_line_and_json_keeps_the_surface() {
    let surface = r#"{"name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;
    let (_dir, file) = request_file(surface);
    let routes = || {
        vec![
            reply("GET", "/v1/surfaces", "200 OK", SURFACES),
            reply("PUT", "/v1/surfaces/s-1", "200 OK", r#"{"surface_id":"s-1","name":"Sales"}"#),
        ]
    };

    let table = fabric(routes(), &["surfaces", "update", "s-1", "--file", &file]);
    let json = fabric(routes(), &["-o", "json", "surfaces", "update", "s-1", "--file", &file]);

    assert_eq!(table.stdout, "Updated surface 's-1'\n");
    let printed: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(printed["surface_id"], "s-1");
}

#[test]
fn notes_and_warnings_on_standard_error_carry_a_prefix() {
    let body = r#"{"verifications":[{"id":"tx-1","created_at":1}]}"#;
    let payments = fabric(
        vec![reply("GET", "/admin/x402/transactions", "200 OK", body)],
        &["payments", "list", "--store", "x402"],
    );
    let identity = fabric(
        vec![reply("GET", "/v1/identities/i-1", "200 OK", r#"{"id":"i-1","key_pair":{"private_key":{"d":"k"}}}"#)],
        &["identities", "get", "i-1"],
    );

    assert!(
        payments
            .stderr
            .contains("note: x402: 1 record(s)"),
        "{}",
        payments.stderr
    );
    assert!(
        identity
            .stderr
            .contains("note: hid 'key_pair'"),
        "{}",
        identity.stderr
    );
}

#[test]
fn updating_a_certificate_by_name_prints_the_resolved_id() {
    let (_dir, file) = request_file(r#"{"name":"Edge"}"#);
    let list = r#"[{"id":"11111111-2222-4333-8444-555555555555","name":"Edge","certificate_id":"c"}]"#;
    let routes = || {
        vec![
            reply("GET", "/v1/certificates", "200 OK", list),
            reply("PUT", "/v1/certificates/11111111-2222-4333-8444-555555555555", "200 OK", r#"{"id":"x"}"#),
        ]
    };

    let table = fabric(routes(), &["certificates", "update", "Edge", "--file", &file]);
    let json = fabric(routes(), &["-o", "json", "certificates", "update", "Edge", "--file", &file]);

    assert_eq!(table.stdout, format!("Updated certificate '{SECRET_ID}'\n"));
    assert!(
        json.stdout
            .contains("\"id\": \"x\""),
        "{}",
        json.stdout
    );
}

#[test]
fn updating_a_secret_by_name_prints_the_resolved_id() {
    let (_dir, file) = request_file(r#"{"name":"Stripe"}"#);
    let list = r#"[{"id":"11111111-2222-4333-8444-555555555555","name":"Stripe","secret_id":"stripe"}]"#;
    let out = fabric(
        vec![
            reply("GET", "/v1/secrets", "200 OK", list),
            reply("PUT", "/v1/secrets/11111111-2222-4333-8444-555555555555", "200 OK", r#"{"id":"x"}"#),
        ],
        &["secrets", "update", "Stripe", "--file", &file],
    );

    assert_eq!(out.stdout, format!("Updated secret '{SECRET_ID}'\n"));
}

#[test]
fn a_surface_dry_run_prints_no_updated_line() {
    let surface = SURFACES;
    let patched = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;
    let out = fabric(
        vec![
            reply("GET", "/v1/surfaces", "200 OK", surface),
            reply("GET", "/v1/surfaces/s-1", "200 OK", patched),
            reply("PATCH", "/v1/surfaces/s-1", "200 OK", patched),
        ],
        &["surfaces", "update", "s-1", "--set", "name=Renamed", "--dry-run"],
    );

    assert!(
        !out.stdout
            .contains("Updated surface"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("Dry run"), "{} / {}", out.stdout, out.stderr);
}

#[test]
fn a_gateway_error_on_create_or_update_prints_no_confirmation_line() {
    let (_dir, file) = request_file(r#"{"name":"Acme"}"#);
    let failing =
        |method: &'static str, path: &'static str| vec![reply(method, path, "400 Bad Request", r#"{"error":"nope"}"#)];

    let create = fabric(failing("POST", "/v1/issuers"), &["issuers", "create", "--file", &file]);
    let update = fabric(failing("PUT", "/v1/issuers/i-1"), &["issuers", "update", "i-1", "--file", &file]);

    for out in [create, update] {
        assert_eq!(out.stdout, "");
        assert!(out.stderr.contains("error:"), "{}", out.stderr);
    }
}

#[test]
fn a_token_note_is_printed_in_json_mode_too_without_changing_standard_output() {
    let answer = r#"{"id":"t-1","token":"agpat_secret"}"#;
    let out = fabric(
        vec![reply("POST", "/v1/access-tokens", "200 OK", answer)],
        &["-o", "json", "tokens", "create", "--name", "ci", "--scope", "surfaces.view"],
    );

    assert!(
        out.stderr
            .contains("note: this is the only time the access token secret is shown"),
        "{}",
        out.stderr
    );
    let printed: serde_json::Value = serde_json::from_str(&out.stdout).expect("json only on standard output");
    assert_eq!(printed["token"], "agpat_secret");
}

#[test]
fn creating_a_connection_point_prints_its_own_id_not_the_gateways() {
    let (_dir, file) = request_file(r#"{"name":"Door"}"#);
    let answer = r#"{"connection_point":{"id":"cp-1","gateway_id":"gw-9","name":"Door","use_count":0}}"#;
    let table = fabric(
        vec![reply("POST", "/v1/connection-points", "200 OK", answer)],
        &["connection-points", "create", "--file", &file],
    );

    assert_eq!(table.stdout, "Created connection point 'cp-1'\n");
}

#[test]
fn a_payment_record_shows_an_iso_time_in_table_mode_and_seconds_in_json() {
    let record = r#"{"id":"tx-1","surface_id":"sales","status":"verified","created_at":1790000000}"#;
    let routes = || vec![reply("GET", "/admin/x402/transactions/tx-1", "200 OK", record)];

    let table = fabric(routes(), &["payments", "get", "tx-1", "--store", "x402"]);
    let json = fabric(routes(), &["-o", "json", "payments", "get", "tx-1", "--store", "x402"]);

    assert!(
        table
            .stdout
            .contains("\"created_at\": \"2026-09-21T14:13:20Z\""),
        "{}",
        table.stdout
    );
    assert!(
        json.stdout
            .contains("\"created_at\": 1790000000"),
        "{}",
        json.stdout
    );
}

#[test]
fn updating_a_surface_by_name_prints_the_resolved_id() {
    let surface = r#"{"name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;
    let (_dir, file) = request_file(surface);
    let out = fabric(
        vec![
            reply("GET", "/v1/surfaces", "200 OK", SURFACES),
            reply("PUT", "/v1/surfaces/s-1", "200 OK", r#"{"surface_id":"s-1"}"#),
        ],
        &["surfaces", "update", "Sales", "--file", &file],
    );

    assert_eq!(out.stdout, "Updated surface 's-1'\n");
    assert!(
        out.stderr
            .contains("note: using surface s-1 (Sales)"),
        "{}",
        out.stderr
    );
}

#[test]
fn an_api_key_line_names_the_key_even_when_the_answer_has_other_ids_inside() {
    let created = r#"{"labels":{"id":"label-1"},"issuer":{"id":"issuer-1"},"key_id":"k-1","secret":"sk_live"}"#;
    let create = fabric(
        vec![reply("POST", "/v1/api-keys/s-1", "200 OK", created)],
        &["api-keys", "create", "s-1", "--client-id", "billing"],
    );
    let rotate = fabric(
        vec![reply("POST", "/v1/api-keys/s-1/k-1/rotate", "200 OK", created)],
        &["api-keys", "rotate", "k-1", "--agent-id", "s-1", "--yes"],
    );
    let token = fabric(
        vec![reply(
            "POST",
            "/v1/access-tokens/t-1/rotate",
            "200 OK",
            r#"{"issuer":{"id":"issuer-1"},"token":"agpat_new"}"#,
        )],
        &["tokens", "rotate", "t-1", "--yes"],
    );

    assert!(
        create
            .stderr
            .contains("Created API key 'k-1'"),
        "{}",
        create.stderr
    );
    assert!(
        rotate
            .stderr
            .contains("Rotated API key 'k-1'"),
        "{}",
        rotate.stderr
    );
    assert!(
        token
            .stderr
            .contains("Rotated access token 't-1'"),
        "{}",
        token.stderr
    );
}

#[test]
fn a_secret_with_control_characters_is_refused_with_the_id_and_a_way_out() {
    let created = |secret: &str| {
        vec![reply("POST", "/v1/access-tokens", "200 OK", format!(r#"{{"id":"t-1","token":"{secret}"}}"#))]
    };
    let escape =
        fabric(created("agpat_\\u001b[31mred"), &["tokens", "create", "--name", "ci", "--scope", "surfaces.view"]);
    let bidi =
        fabric(created("agpat_\\u202ereversed"), &["tokens", "create", "--name", "ci", "--scope", "surfaces.view"]);
    let json = fabric(
        created("agpat_\\u001b[31mred"),
        &["-o", "json", "tokens", "create", "--name", "ci", "--scope", "surfaces.view"],
    );
    let rotated = fabric(
        vec![reply("POST", "/v1/access-tokens/t-1/rotate", "200 OK", r#"{"token":"agpat_\u001bred"}"#)],
        &["tokens", "rotate", "t-1", "--yes"],
    );

    for out in [&escape, &bidi] {
        assert_eq!(out.stdout, "");
        assert!(
            out.stderr
                .contains("Created access token 't-1' but its secret contains control characters and was not printed"),
            "{}",
            out.stderr
        );
        assert!(
            out.stderr
                .contains("Revoke it, or rotate it with --output json"),
            "{}",
            out.stderr
        );
    }
    assert_eq!(rotated.stdout, "");
    assert!(
        rotated
            .stderr
            .contains("Rotated access token 't-1' but its secret contains control characters"),
        "{}",
        rotated.stderr
    );
    assert!(
        rotated
            .stderr
            .contains("Run the rotate command again with --output json"),
        "{}",
        rotated.stderr
    );
    assert!(json.stdout.contains("agpat_"), "{}", json.stdout);
}

#[test]
fn an_empty_list_names_why_it_is_empty() {
    let secrets =
        fabric(vec![reply("GET", "/v1/secrets/tag/prod", "200 OK", "[]")], &["secrets", "list", "--tag", "prod"]);
    let all_secrets = fabric(vec![reply("GET", "/v1/secrets", "200 OK", "[]")], &["secrets", "list"]);
    let audit = fabric(
        vec![reply("GET", "/v1/audit", "200 OK", r#"{"events":[],"total":0}"#)],
        &["audit", "list", "--decision", "deny"],
    );
    let payments = fabric(
        vec![reply("GET", "/admin/x402/transactions", "200 OK", r#"{"verifications":[]}"#)],
        &["payments", "list", "--store", "x402", "--status", "failed"],
    );
    let keys =
        fabric(vec![reply("GET", "/v1/api-keys/s-1", "200 OK", "[]")], &["api-keys", "list", "--agent-id", "s-1"]);

    assert_eq!(secrets.stdout, "No matching secrets.\n");
    assert_eq!(all_secrets.stdout, "No secrets yet.\n");
    assert_eq!(audit.stdout, "No matching audit events.\n");
    assert_eq!(payments.stdout, "No matching payments.\n");
    assert_eq!(keys.stdout, "No matching API keys.\n");
}

#[test]
fn payments_with_a_failing_store_say_none_were_returned() {
    let out = fabric(
        vec![
            reply("GET", "/admin/x402/transactions", "200 OK", r#"{"verifications":[]}"#),
            reply("GET", "/admin/mpp/transactions", "500 Internal Server Error", r#"{"error":"down"}"#),
        ],
        &["payments", "list"],
    );

    assert_eq!(out.stdout, "No payments returned.\n");
    assert!(
        out.stderr
            .contains("warning:"),
        "{}",
        out.stderr
    );
}

#[test]
fn adding_and_removing_a_feature_or_transit_point_print_one_line_in_table_mode() {
    let bare = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;
    let limited = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales","rate_limit":{"requests":10,"window_secs":60}},"target":{"endpoint":"http://127.0.0.1:3000"}}"#;
    let routes = |current: &'static str| {
        vec![
            reply("GET", "/v1/surfaces", "200 OK", SURFACES),
            reply("GET", "/v1/surfaces/s-1", "200 OK", current),
            reply("PATCH", "/v1/surfaces/s-1", "200 OK", current),
        ]
    };

    let added = fabric(
        routes(bare),
        &["surfaces", "add-feature", "s-1", "rate-limit", "--json", r#"{"requests":10,"window_secs":60}"#],
    );
    let removed = fabric(routes(limited), &["surfaces", "remove-feature", "s-1", "rate-limit"]);
    let json = fabric(routes(limited), &["-o", "json", "surfaces", "remove-feature", "s-1", "rate-limit"]);

    let with_point = r#"{"surface_id":"s-1","name":"Sales","access_point":{"listen_address":"0.0.0.0:8080","route":"/sales"},"target":{"endpoint":"http://127.0.0.1:3000"},"transit":{"points":[{"id":"tp-1","alias":"billing","target_endpoint":"http://billing:3000"}]}}"#;
    let point_added = fabric(
        routes(bare),
        &["surfaces", "add-transit-point", "s-1", "--alias", "billing", "--endpoint", "http://billing:3000"],
    );
    let point_removed = fabric(routes(with_point), &["surfaces", "remove-transit-point", "s-1", "billing"]);

    assert_eq!(added.stdout, "Updated surface 's-1'\n", "{}", added.stderr);
    assert_eq!(removed.stdout, "Updated surface 's-1'\n", "{}", removed.stderr);
    assert_eq!(point_added.stdout, "Updated surface 's-1'\n", "{}", point_added.stderr);
    assert_eq!(point_removed.stdout, "Updated surface 's-1'\n", "{}", point_removed.stderr);
    assert!(
        json.stdout
            .contains("\"surface_id\": \"s-1\""),
        "{}",
        json.stdout
    );
}

#[test]
fn a_payments_store_that_is_not_set_up_does_not_change_the_empty_line() {
    let out = fabric(
        vec![reply("GET", "/admin/x402/transactions", "200 OK", r#"{"verifications":[]}"#)],
        &["payments", "list"],
    );

    assert_eq!(out.stdout, "No payments yet.\n");
}

#[test]
fn an_audit_page_past_the_first_is_worded_as_a_filtered_result() {
    let out = fabric(
        vec![reply("GET", "/v1/audit", "200 OK", r#"{"events":[],"total":0}"#)],
        &["audit", "list", "--page", "3"],
    );

    assert_eq!(out.stdout, "No matching audit events.\n");
}

/// Standard input is not a terminal here, so a destructive command without
/// `--yes` can never be answered and must refuse instead of acting.
#[test]
fn deleting_an_api_key_without_yes_refuses_and_sends_nothing_when_stdin_is_not_a_terminal() {
    let out = fabric(
        vec![reply("DELETE", "/v1/api-keys/s-1/k-1", "204 No Content", "")],
        &["api-keys", "delete", "k-1", "--agent-id", "s-1"],
    );

    assert!(!out.success);
    assert!(
        out.stderr
            .contains("refusing to delete 'k-1' without confirmation in a non-interactive session; pass --yes"),
        "{}",
        out.stderr
    );
    assert!(out.stdout.is_empty(), "{}", out.stdout);
    assert!(
        out.requests
            .iter()
            .all(|request| !request.starts_with("DELETE")),
        "{:?}",
        out.requests
    );
}

#[test]
fn revoking_or_rotating_an_access_token_without_yes_refuses_and_sends_nothing_when_stdin_is_not_a_terminal() {
    for verb in ["revoke", "rotate"] {
        let out = fabric(
            vec![
                reply("DELETE", "/v1/access-tokens/t-1", "204 No Content", ""),
                reply("POST", "/v1/access-tokens/t-1/rotate", "200 OK", r#"{"token":"agpat_new"}"#),
            ],
            &["tokens", verb, "t-1"],
        );

        assert!(!out.success, "{verb}");
        assert!(
            out.stderr
                .contains(&format!("refusing to {verb} 't-1' without confirmation in a non-interactive session")),
            "{verb}: {}",
            out.stderr
        );
        assert!(
            !out.stdout
                .contains("agpat_new"),
            "{verb}: {}",
            out.stdout
        );
        assert!(out.requests.is_empty(), "{verb}: {:?}", out.requests);
    }
}

#[test]
fn a_raw_api_call_with_a_control_character_in_a_dot_segment_is_refused_before_it_is_sent() {
    for path in ["/v1/.\t./admin", "/v1/.\n./admin"] {
        let out = fabric(vec![reply("GET", "/admin", "200 OK", "{}")], &["api", "get", path]);

        assert!(!out.success, "{path:?}");
        assert!(
            out.stderr
                .contains("API path must start with '/'"),
            "{path:?}: {}",
            out.stderr
        );
        assert!(out.requests.is_empty(), "{path:?}: {:?}", out.requests);
    }
}

#[test]
fn revoking_or_rotating_an_api_key_without_yes_refuses_and_sends_nothing_when_stdin_is_not_a_terminal() {
    for verb in ["revoke", "rotate"] {
        let out = fabric(
            vec![
                reply("POST", "/v1/api-keys/s-1/k-1/revoke", "204 No Content", ""),
                reply("POST", "/v1/api-keys/s-1/k-1/rotate", "200 OK", r#"{"key_id":"k-1","secret":"sk_new"}"#),
            ],
            &["api-keys", verb, "k-1", "--agent-id", "s-1"],
        );

        assert!(!out.success, "{verb}");
        assert!(
            out.stderr
                .contains(&format!("refusing to {verb} 'k-1' without confirmation in a non-interactive session")),
            "{verb}: {}",
            out.stderr
        );
        assert!(!out.stdout.contains("sk_new"), "{verb}: {}", out.stdout);
        assert!(out.requests.is_empty(), "{verb}: {:?}", out.requests);
    }
}

/// Without `--agent-id` the CLI would look the key up first, so the refusal
/// has to come before that lookup for nothing to be sent.
#[test]
fn an_api_key_command_without_yes_or_agent_id_refuses_before_any_lookup() {
    for verb in ["revoke", "rotate", "delete"] {
        let out = fabric(
            vec![reply("GET", "/v1/api-keys", "200 OK", r#"[{"key_id":"k-1","agent_id":"s-1"}]"#)],
            &["api-keys", verb, "k-1"],
        );

        assert!(!out.success, "{verb}");
        assert!(
            out.stderr
                .contains(&format!("refusing to {verb} 'k-1' without confirmation in a non-interactive session")),
            "{verb}: {}",
            out.stderr
        );
        assert!(out.requests.is_empty(), "{verb}: {:?}", out.requests);
    }
}

#[test]
fn revoking_an_api_key_with_yes_skips_the_prompt() {
    let out = fabric(
        vec![reply("POST", "/v1/api-keys/s-1/k-1/revoke", "204 No Content", "")],
        &["api-keys", "revoke", "k-1", "--agent-id", "s-1", "-y"],
    );

    assert!(out.success, "{}", out.stderr);
    assert_eq!(out.stdout, "Revoked API key 'k-1'\n");
}
