//! Runs the built `fabric` binary to check that `fabric agent-stream` exists
//! only when the binary was built with the `agent-stream` Cargo feature, that
//! its saved connections stay apart from the Agent Gateway ones, what its
//! commands send when the host or the token comes from the environment, and,
//! against an Agent Stream stand-in, that the groups it shares with Agent
//! Gateway print the same tables and lines, keep secret values hidden, report
//! what Agent Stream did with a deleted user, and warn about the settings
//! fields Agent Stream stores its own way.

// The runner and the recording host are taken from `common`, but not its
// saved-connection helper, which is for Agent Gateway commands and would go
// unused here.
#[path = "common/fresh_home.rs"]
mod fresh_home;
#[cfg(feature = "agent-stream")]
#[path = "common/recording_host.rs"]
mod recording_host;

#[cfg(feature = "agent-stream")]
use std::path::{Path, PathBuf};
use std::process::Output;

use fresh_home::fabric_in_fresh_home;
#[cfg(feature = "agent-stream")]
use fresh_home::fabric_in_home;
#[cfg(feature = "agent-stream")]
use recording_host::{PROBE_REQUEST, Reply, Requests, host_answering, host_replying, request_lines, request_lowercase};

/// Exit status clap uses for a command line it cannot parse.
#[cfg(not(feature = "agent-stream"))]
const USAGE_EXIT_CODE: i32 = 2;

/// A `config.toml` as the 0.1.4 CLI wrote it, with one Agent Gateway connection.
#[cfg(feature = "agent-stream")]
const GATEWAY_CONFIG: &str = "current = \"default\"\n\n[connections.default]\nhost = \"https://gateway.example\"\n";

/// An `agent-stream.toml` with one Agent Stream connection of the same name.
#[cfg(feature = "agent-stream")]
const AGENT_STREAM_CONFIG: &str = "current = \"default\"\n\n[connections.default]\nhost = \"https://stream.example\"\n";

/// An `agent-stream.toml` whose one connection has a `#` in its name.
#[cfg(feature = "agent-stream")]
const HASH_NAME_CONFIG: &str = "[connections.\"prod#1\"]\nhost = \"https://stream.example\"\n";

/// Runs `fabric <args>` in a fresh home holding `files`, with no `FABRIC_*`
/// variable set and nothing on standard input.
fn fabric(
    args: &[&str],
    files: &[(&str, &str)],
) -> Output {
    fabric_in_fresh_home(args, files, &[], "")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[cfg(not(feature = "agent-stream"))]
#[test]
fn the_default_build_does_not_know_agent_stream() {
    let output = fabric(&["agent-stream"], &[]);

    assert_eq!(output.status.code(), Some(USAGE_EXIT_CODE), "{}", stderr(&output));
    assert!(stderr(&output).contains("unrecognized subcommand"), "{}", stderr(&output));
    assert!(!stdout(&fabric(&["--help"], &[])).contains("agent-stream"));
}

#[cfg(feature = "agent-stream")]
#[test]
fn the_feature_build_lists_agent_stream_connections_apart_from_the_gateway_ones() {
    let files = [("config.toml", GATEWAY_CONFIG), ("agent-stream.toml", AGENT_STREAM_CONFIG)];

    let gateway = fabric(&["agent-gateway", "config", "list"], &files);
    let stream = fabric(&["agent-stream", "config", "list"], &files);

    assert!(gateway.status.success(), "{}", stderr(&gateway));
    assert!(stream.status.success(), "{}", stderr(&stream));
    assert!(stdout(&gateway).contains("https://gateway.example"), "{}", stdout(&gateway));
    assert!(!stdout(&gateway).contains("https://stream.example"), "{}", stdout(&gateway));
    assert!(stdout(&stream).contains("https://stream.example"), "{}", stdout(&stream));
    assert!(!stdout(&stream).contains("https://gateway.example"), "{}", stdout(&stream));
}

#[cfg(feature = "agent-stream")]
#[test]
fn the_feature_build_starts_with_no_agent_stream_connections_beside_a_gateway_one() {
    let output = fabric(&["agent-stream", "config", "list"], &[("config.toml", GATEWAY_CONFIG)]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "No Agent Stream connections yet.");
}

#[cfg(feature = "agent-stream")]
#[test]
fn an_agent_stream_command_naming_a_gateway_only_connection_says_it_does_not_exist() {
    let output = fabric(&["agent-stream", "config", "use", "default"], &[("config.toml", GATEWAY_CONFIG)]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("Agent Stream connection 'default' does not exist"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn an_agent_stream_connection_with_a_hash_in_its_name_gets_the_warning() {
    let output = fabric(&["agent-stream", "config", "list"], &[("agent-stream.toml", HASH_NAME_CONFIG)]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stderr(&output).contains("warning: connection 'prod#1' has a '#' in its name"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn a_token_and_host_both_from_the_environment_get_the_note_on_an_agent_stream_command() {
    let token = "aspat_secret-value";
    let output = fabric_in_fresh_home(
        &["agent-stream", "config", "list"],
        &[],
        &[("FABRIC_TOKEN", token), ("FABRIC_HOST", "https://stream.example")],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stderr(&output)
            .matches("note: sending the token from FABRIC_TOKEN to the host from FABRIC_HOST (https://stream.example)")
            .count(),
        1,
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(token), "{}", stderr(&output));
    assert!(!stdout(&output).contains(token), "{}", stdout(&output));
}

/// Agent Stream's public permission list, which has `pipes.view`.
#[cfg(feature = "agent-stream")]
const AGENT_STREAM_PERMISSIONS: &str = r#"{"pipes.view":false,"users.view":false}"#;

/// What Agent Stream answers to `tokens list` when there are no tokens.
#[cfg(feature = "agent-stream")]
const NO_ACCESS_TOKENS: &str = r#"{"access_tokens":[]}"#;

#[cfg(feature = "agent-stream")]
const TOKENS_LIST_REQUEST: &str = "GET /api/v1/access-tokens HTTP/1.1";

#[cfg(feature = "agent-stream")]
const ACCESS_TOKEN: &str = "aspat_secret-value";

#[cfg(feature = "agent-stream")]
const SESSION_TOKEN: &str = "session-secret-value";

/// A D-Bus session address nothing listens on. On Linux the keyring is the
/// Secret Service over D-Bus, so a command that opened it with this set would
/// fail instead of carrying on.
#[cfg(feature = "agent-stream")]
const UNREACHABLE_DBUS: (&str, &str) = ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/fabric-test-bus");

/// Starts an Agent Stream that answers the probe and `tokens list`.
#[cfg(feature = "agent-stream")]
fn agent_stream_host() -> (String, Requests) {
    host_answering(AGENT_STREAM_PERMISSIONS, NO_ACCESS_TOKENS)
}

/// Every file under `directory`, at any depth, in sorted order.
#[cfg(feature = "agent-stream")]
fn files_under(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).expect("read directory") {
            let path = entry
                .expect("directory entry")
                .path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// Asserts that `requests` is the anonymous probe, then one `tokens list`
/// request that carries `token` as its bearer.
#[cfg(feature = "agent-stream")]
fn assert_probe_then_bearer_list(
    requests: &Requests,
    token: &str,
) {
    assert_eq!(request_lines(requests), [PROBE_REQUEST, TOKENS_LIST_REQUEST]);
    let probe = request_lowercase(requests, 0);
    assert!(!probe.contains("authorization"), "{probe}");
    assert!(!probe.contains(token), "{probe}");
    let list = request_lowercase(requests, 1);
    assert!(list.contains(&format!("authorization: bearer {token}")), "{list}");
}

/// The host and the token both come from the environment, and nothing is
/// saved, so the command must not open the credential store. On Linux that is
/// proven by [`UNREACHABLE_DBUS`], which makes any keyring call fail the run.
/// An empty home only shows that no config file was written, because a keyring
/// read writes nothing and the system store lives outside this home, so on
/// macOS the proof is the unit test
/// `a_given_host_and_token_with_no_saved_connection_never_touch_the_keyring` in
/// `agent_stream/mod.rs`, whose store fails every call.
#[cfg(feature = "agent-stream")]
#[test]
fn tokens_list_with_host_and_token_from_the_environment_asks_the_host_then_sends_the_token_and_saves_nothing() {
    let (host, requests) = agent_stream_host();
    let home = tempfile::TempDir::new().expect("temp dir");

    let output = fabric_in_home(
        home.path(),
        &["agent-stream", "tokens", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stderr(&output);
    assert!(output.status.success(), "{text}");
    assert!(!text.contains("keyring"), "{text}");
    assert!(!text.contains(ACCESS_TOKEN), "{text}");
    assert_probe_then_bearer_list(&requests, ACCESS_TOKEN);
    assert!(files_under(home.path()).is_empty(), "{:?}", files_under(home.path()));
}

#[cfg(feature = "agent-stream")]
#[test]
fn tokens_list_with_a_session_token_from_the_environment_asks_a_saved_agent_stream_then_sends_the_token() {
    let (host, requests) = agent_stream_host();
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");

    let output = fabric_in_fresh_home(
        &["agent-stream", "tokens", "list"],
        &[("agent-stream.toml", &config)],
        &[("FABRIC_TOKEN", SESSION_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_probe_then_bearer_list(&requests, SESSION_TOKEN);
}

#[cfg(feature = "agent-stream")]
#[test]
fn tokens_list_with_an_access_token_from_the_environment_sends_it_to_a_saved_agent_stream_without_asking() {
    let (host, requests) = agent_stream_host();
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");

    let output = fabric_in_fresh_home(
        &["agent-stream", "tokens", "list"],
        &[("agent-stream.toml", &config)],
        &[("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(request_lines(&requests), [TOKENS_LIST_REQUEST]);
}

/// An Agent Stream access token, which settles the product without a probe.
#[cfg(feature = "agent-stream")]
const STREAM_TOKEN: &str = "aspat_feature-test";

/// A stored secret as Agent Stream answers get, create, and update with it.
#[cfg(feature = "agent-stream")]
const STORED_SECRET: &str =
    r#"{"id":"s-1","secret_id":"stripe-live","name":"Stripe live","value":"sk_live_do_not_print"}"#;

/// Starts an Agent Stream stand-in that answers each of `replies`, matched on
/// the request line, and `404 Not Found` to anything else, until the test
/// ends. It also answers the public permission list the CLI reads to confirm
/// the host is an Agent Stream, unless `replies` answers that route. Returns
/// its address and every request it received.
#[cfg(feature = "agent-stream")]
fn agent_stream_stand_in(mut replies: Vec<Reply>) -> (String, Requests) {
    replies.push(("GET /api/v1/permissions/public", "200 OK", AGENT_STREAM_PERMISSIONS));
    host_replying(replies, ("404 Not Found", ""))
}

/// The JSON body of the one request in `requests` whose request line starts
/// with `start`, such as `POST /api/v1/api-keys/pipe-1`.
#[cfg(feature = "agent-stream")]
fn sent_body(
    requests: &Requests,
    start: &str,
) -> serde_json::Value {
    let requests = requests
        .lock()
        .expect("recorded requests");
    let sent: Vec<&String> = requests
        .iter()
        .filter(|request| request.starts_with(&format!("{start} ")))
        .collect();
    assert_eq!(sent.len(), 1, "{start}: {requests:?}");
    let (_, body) = sent[0]
        .split_once("\r\n\r\n")
        .expect("a request head");
    serde_json::from_str(body).unwrap_or_else(|error| panic!("{start}: {error}: {body}"))
}

/// Runs `fabric agent-stream <args>` against the Agent Stream at `host`, with
/// the host and token given through the environment and `stdin` on standard
/// input.
#[cfg(feature = "agent-stream")]
fn fabric_on_stream(
    host: &str,
    args: &[&str],
    stdin: &str,
) -> Output {
    let args: Vec<&str> = ["agent-stream"]
        .into_iter()
        .chain(args.iter().copied())
        .collect();
    fabric_in_fresh_home(&args, &[], &[("FABRIC_HOST", host), ("FABRIC_TOKEN", STREAM_TOKEN)], stdin)
}

#[cfg(feature = "agent-stream")]
#[test]
fn secrets_get_create_and_update_hide_the_value_agent_stream_sends_unless_reveal_is_given() {
    let (host, _) = agent_stream_stand_in(vec![
        ("GET /api/v1/secrets/s-1", "200 OK", STORED_SECRET),
        ("POST /api/v1/secrets/new", "201 Created", STORED_SECRET),
        ("PUT /api/v1/secrets/s-1", "200 OK", STORED_SECRET),
        ("GET /api/v1/secrets", "200 OK", r#"[{"id":"s-1","secret_id":"stripe-live","name":"Stripe live"}]"#),
    ]);
    let get = fabric_on_stream(&host, &["secrets", "get", "stripe-live"], "");
    let create = fabric_on_stream(
        &host,
        &[
            "--output",
            "json",
            "secrets",
            "create",
            "--name",
            "Stripe live",
            "--secret-id",
            "stripe-live",
            "--value-stdin",
        ],
        "sk_live_do_not_print\n",
    );
    let update = fabric_on_stream(
        &host,
        &["--output", "json", "secrets", "update", "stripe-live", "--file", "-"],
        r#"{"description":"Billing"}"#,
    );
    let revealed = fabric_on_stream(&host, &["secrets", "get", "stripe-live", "--reveal"], "");

    for (name, output) in [("get", &get), ("create", &create), ("update", &update)] {
        assert!(output.status.success(), "{name}: {}", stderr(output));
        assert!(!stdout(output).contains("sk_live_do_not_print"), "{name}: {}", stdout(output));
        assert!(!stderr(output).contains("sk_live_do_not_print"), "{name}: {}", stderr(output));
    }
    assert!(stdout(&get).contains(r#""value": "<hidden; pass --reveal to show>""#), "{}", stdout(&get));
    assert!(stdout(&create).contains("<hidden; pass --reveal to show>"), "{}", stdout(&create));
    assert!(revealed.status.success(), "{}", stderr(&revealed));
    assert!(stdout(&revealed).contains("sk_live_do_not_print"), "{}", stdout(&revealed));
}

#[cfg(feature = "agent-stream")]
#[test]
fn secrets_update_and_delete_print_the_same_lines_as_on_agent_gateway() {
    let (host, _) = agent_stream_stand_in(vec![
        ("PUT /api/v1/secrets/s-1", "200 OK", STORED_SECRET),
        ("DELETE /api/v1/secrets/s-1", "204 No Content", ""),
        ("GET /api/v1/secrets", "200 OK", r#"[{"id":"s-1","secret_id":"stripe-live","name":"Stripe live"}]"#),
    ]);

    let update = fabric_on_stream(&host, &["secrets", "update", "stripe-live", "--file", "-"], r#"{"tags":["a"]}"#);
    let delete = fabric_on_stream(&host, &["secrets", "delete", "stripe-live"], "");

    assert_eq!(stdout(&update), "Updated secret 's-1'\n", "{}", stderr(&update));
    assert_eq!(stdout(&delete), "Deleted secret 's-1'\n", "{}", stderr(&delete));
}

#[cfg(feature = "agent-stream")]
#[test]
fn users_delete_says_whether_agent_stream_removed_or_kept_the_user() {
    let (host, _) = agent_stream_stand_in(vec![
        ("DELETE /api/v1/users/u-removed", "200 OK", r#"{"outcome":"removed"}"#),
        ("DELETE /api/v1/users/u-kept", "200 OK", r#"{"outcome":"disabled"}"#),
    ]);

    let removed = fabric_on_stream(&host, &["users", "delete", "u-removed"], "");
    let kept = fabric_on_stream(&host, &["users", "delete", "u-kept"], "");
    let kept_json = fabric_on_stream(&host, &["--output", "json", "users", "delete", "u-kept"], "");

    assert_eq!(stdout(&removed), "Deleted user 'u-removed'\n", "{}", stderr(&removed));
    assert!(!stderr(&removed).contains("identity provider"), "{}", stderr(&removed));
    assert_eq!(stdout(&kept), "Disabled user 'u-kept'\n", "{}", stderr(&kept));
    assert!(
        stderr(&kept).contains(
            "note: the user signs in through an identity provider, so Agent Stream keeps their record, disabled, \
             and refuses their sign-ins through that provider"
        ),
        "{}",
        stderr(&kept)
    );
    let printed: serde_json::Value = serde_json::from_str(&stdout(&kept_json)).expect("JSON");
    assert_eq!(printed, serde_json::json!({"outcome": "disabled"}));
    assert!(!stderr(&kept_json).contains("identity provider"), "{}", stderr(&kept_json));
}

#[cfg(feature = "agent-stream")]
#[test]
fn the_shared_lists_print_the_agent_gateway_tables() {
    let (host, _) = agent_stream_stand_in(vec![
        (
            "GET /api/v1/policy-definitions",
            "200 OK",
            r#"[{"id":"p-1","name":"Block PII","description":"No card numbers","policy_type":"llm","enabled":true,"version":2,"updated_at":"2026-11-01T00:00:00Z"}]"#,
        ),
        (
            "GET /api/v1/identities",
            "200 OK",
            r#"{"identities":[{"id":"i-1","did":"did:webvh:x:agents/a","version":1,"active":true,"updated_at":"2026-11-01T00:00:00Z"}],"count":1}"#,
        ),
        ("GET /api/v1/users", "200 OK", "[]"),
    ]);

    let policies = fabric_on_stream(&host, &["policies", "list"], "");
    let identities = fabric_on_stream(&host, &["identities", "list"], "");
    let users = fabric_on_stream(&host, &["users", "list"], "");

    assert_eq!(
        stdout(&policies),
        "NAME       ID   DESCRIPTION      ENABLED  VERSION  UPDATED\n\
         Block PII  p-1  No card numbers  yes      2        2026-11-01T00:00:00Z\n",
        "{}",
        stderr(&policies)
    );
    assert_eq!(
        stdout(&identities),
        "DID                   ID   VERSION  ACTIVE  UPDATED\n\
         did:webvh:x:agents/a  i-1  1        yes     2026-11-01T00:00:00Z\n",
        "{}",
        stderr(&identities)
    );
    assert_eq!(stdout(&users), "No users yet.\n", "{}", stderr(&users));
}

#[cfg(feature = "agent-stream")]
#[test]
fn api_keys_create_sends_the_client_id_and_labels_and_prints_the_secret_alone() {
    let (host, requests) = agent_stream_stand_in(vec![(
        "POST /api/v1/api-keys/pipe-1",
        "201 Created",
        r#"{"key_id":"ak_1","secret":"ask_shown_once","agent_id":"pipe-1","client_id":"billing"}"#,
    )]);

    let output =
        fabric_on_stream(&host, &["api-keys", "create", "pipe-1", "--client-id", "billing", "--label", "team=ops"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "ask_shown_once\n");
    assert!(stderr(&output).contains("Created API key 'ak_1'"), "{}", stderr(&output));
    assert_eq!(
        sent_body(&requests, "POST /api/v1/api-keys/pipe-1"),
        serde_json::json!({"client_id": "billing", "labels": {"team": "ops"}})
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn policies_create_and_delete_print_the_agent_gateway_lines() {
    let (host, _) = agent_stream_stand_in(vec![
        ("POST /api/v1/policy-definitions", "201 Created", r#"{"id":"block-pii"}"#),
        ("DELETE /api/v1/policy-definitions/block-pii", "204 No Content", ""),
    ]);
    let rego = tempfile::NamedTempFile::new().expect("temp file");
    std::fs::write(rego.path(), "package llm.policy\n").expect("write the Rego source");
    let rego_path = rego
        .path()
        .to_str()
        .expect("a UTF-8 path");

    let create = fabric_on_stream(
        &host,
        &[
            "policies",
            "create",
            "--id",
            "block-pii",
            "--name",
            "Block PII",
            "--policy-type",
            "llm",
            "--policy-file",
            rego_path,
        ],
        "",
    );
    let delete = fabric_on_stream(&host, &["policies", "delete", "block-pii", "--yes"], "");

    assert_eq!(stdout(&create), "Created policy 'block-pii'\n", "{}", stderr(&create));
    assert_eq!(stdout(&delete), "Deleted policy 'block-pii'\n", "{}", stderr(&delete));
}

/// What `secrets get --reveal` prints on standard error when Agent Stream
/// sends no value.
#[cfg(feature = "agent-stream")]
const WITHHELD_NOTE: &str =
    "note: Agent Stream sent no value, because secrets.reveal_values is off in its agent-stream.json\n";

#[cfg(feature = "agent-stream")]
#[test]
fn secrets_get_with_reveal_says_why_agent_stream_sent_no_value() {
    let (host, _) = agent_stream_stand_in(vec![
        ("GET /api/v1/secrets/s-1", "200 OK", r#"{"id":"s-1","secret_id":"stripe-live","name":"Stripe live"}"#),
        ("GET /api/v1/secrets", "200 OK", r#"[{"id":"s-1","secret_id":"stripe-live","name":"Stripe live"}]"#),
    ]);

    let revealed = fabric_on_stream(&host, &["secrets", "get", "stripe-live", "--reveal"], "");
    let masked = fabric_on_stream(&host, &["secrets", "get", "stripe-live"], "");

    assert!(revealed.status.success(), "{}", stderr(&revealed));
    assert!(stderr(&revealed).contains(WITHHELD_NOTE), "{}", stderr(&revealed));
    assert!(masked.status.success(), "{}", stderr(&masked));
    assert!(!stderr(&masked).contains(WITHHELD_NOTE), "{}", stderr(&masked));
}

#[cfg(feature = "agent-stream")]
#[test]
fn api_keys_rotate_prints_the_new_secret_alone_and_names_the_new_key() {
    let (host, _) = agent_stream_stand_in(vec![(
        "POST /api/v1/api-keys/pipe-1/ak_1/rotate",
        "200 OK",
        r#"{"key_id":"ak_2","secret":"ask_new_secret","agent_id":"pipe-1","client_id":"billing"}"#,
    )]);

    let output = fabric_on_stream(&host, &["api-keys", "rotate", "ak_1", "--agent-id", "pipe-1", "--yes"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "ask_new_secret\n");
    assert!(stderr(&output).contains("Rotated API key 'ak_2'"), "{}", stderr(&output));
    assert!(!stderr(&output).contains("ask_new_secret"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn api_keys_revoke_sends_the_actor_and_revoke_and_delete_print_one_line_each() {
    let (host, requests) = agent_stream_stand_in(vec![
        ("POST /api/v1/api-keys/pipe-1/ak_1/revoke", "204 No Content", ""),
        ("DELETE /api/v1/api-keys/pipe-1/ak_1", "204 No Content", ""),
    ]);

    let revoke = fabric_on_stream(
        &host,
        &["api-keys", "revoke", "ak_1", "--agent-id", "pipe-1", "--actor", "ops-team", "--yes"],
        "",
    );
    let delete = fabric_on_stream(&host, &["api-keys", "delete", "ak_1", "--agent-id", "pipe-1", "--yes"], "");

    assert_eq!(stdout(&revoke), "Revoked API key 'ak_1'\n", "{}", stderr(&revoke));
    assert_eq!(stdout(&delete), "Deleted API key 'ak_1'\n", "{}", stderr(&delete));
    assert_eq!(
        sent_body(&requests, "POST /api/v1/api-keys/pipe-1/ak_1/revoke"),
        serde_json::json!({"actor": "ops-team"})
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn api_keys_revoke_rotate_and_delete_with_a_typed_host_and_no_terminal_send_nothing() {
    for verb in ["revoke", "rotate", "delete"] {
        let (host, requests) = agent_stream_host();

        let output = fabric_in_fresh_home(
            &["agent-stream", "--host", &host, "api-keys", verb, "ak_1", "--agent-id", "pipe-1"],
            &[],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{verb}: {text}");
        assert!(
            text.contains(&format!("refusing to {verb} 'ak_1' without confirmation in a non-interactive session")),
            "{verb}: {text}"
        );
        assert!(request_lines(&requests).is_empty(), "{verb}: {:?}", request_lines(&requests));
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn policies_delete_without_yes_and_with_a_typed_host_and_no_terminal_sends_nothing() {
    let (host, requests) = agent_stream_host();

    let output = fabric_in_fresh_home(
        &["agent-stream", "--host", &host, "policies", "delete", "block-pii"],
        &[],
        &[("FABRIC_TOKEN", SESSION_TOKEN)],
        "",
    );

    let text = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(
        text.contains("refusing to delete 'block-pii' without confirmation in a non-interactive session"),
        "{text}"
    );
    assert!(request_lines(&requests).is_empty(), "{:?}", request_lines(&requests));
}

#[cfg(feature = "agent-stream")]
#[test]
fn connections_delete_without_yes_and_with_a_typed_host_and_no_terminal_sends_nothing() {
    let (host, requests) = agent_stream_host();

    let output = fabric_in_fresh_home(
        &["agent-stream", "--host", &host, "connections", "delete", "g-1"],
        &[],
        &[("FABRIC_TOKEN", SESSION_TOKEN)],
        "",
    );

    let text = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("refusing to delete 'g-1' without confirmation in a non-interactive session"), "{text}");
    assert!(request_lines(&requests).is_empty(), "{:?}", request_lines(&requests));
}

#[cfg(feature = "agent-stream")]
#[test]
fn connections_delete_with_yes_sends_the_delete_without_asking() {
    let (host, requests) = agent_stream_stand_in(vec![("DELETE /api/v1/gateways/g-1", "204 No Content", "")]);

    let output = fabric_on_stream(&host, &["connections", "delete", "g-1", "--yes"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("[y/N]"), "{}", stderr(&output));
    assert!(
        request_lines(&requests).contains(&"DELETE /api/v1/gateways/g-1 HTTP/1.1".to_owned()),
        "{:?}",
        request_lines(&requests)
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn credential_deletes_and_revokes_without_yes_and_with_a_typed_host_and_no_terminal_send_nothing() {
    for (words, refusal) in [
        (&["certificates", "delete", "cert-1"][..], "refusing to delete 'cert-1'"),
        (&["credential-providers", "delete", "cp-1"], "refusing to delete 'cp-1'"),
        (&["jwt-verification-strategies", "delete", "j-1"], "refusing to delete 'j-1'"),
        (&["delegation-vault", "revoke", "g-1"], "refusing to revoke 'g-1'"),
        (&["delegation-vault", "revoke-user", "3f9a0c"], "refusing to revoke '3f9a0c'"),
    ] {
        let (host, requests) = agent_stream_host();
        let args: Vec<&str> = ["agent-stream", "--host", &host]
            .into_iter()
            .chain(words.iter().copied())
            .collect();

        let output = fabric_in_fresh_home(&args, &[], &[("FABRIC_TOKEN", SESSION_TOKEN)], "");

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{words:?}: {text}");
        assert!(
            text.contains(&format!("{refusal} without confirmation in a non-interactive session; pass --yes")),
            "{words:?}: {text}"
        );
        assert!(request_lines(&requests).is_empty(), "{words:?}: {:?}", request_lines(&requests));
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn settings_reset_without_force_and_with_a_typed_host_sends_nothing() {
    let (host, requests) = agent_stream_host();

    let output = fabric_in_fresh_home(
        &["agent-stream", "--host", &host, "settings", "reset"],
        &[],
        &[("FABRIC_TOKEN", SESSION_TOKEN)],
        "",
    );

    let text = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("re-run with --force"), "{text}");
    assert!(request_lines(&requests).is_empty(), "{:?}", request_lines(&requests));
}

#[cfg(feature = "agent-stream")]
#[test]
fn metrics_and_logs_truncate_without_yes_and_with_a_typed_host_send_nothing() {
    for (group, refusal) in [
        ("metrics", "pass --yes to confirm truncating stored metrics; this cannot be undone"),
        ("logs", "pass --yes to confirm deleting every rotated log file; this cannot be undone"),
    ] {
        let (host, requests) = agent_stream_host();

        let output = fabric_in_fresh_home(
            &["agent-stream", "--host", &host, group, "truncate"],
            &[],
            &[("FABRIC_TOKEN", SESSION_TOKEN)],
            "",
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{group}: {text}");
        assert!(text.contains(refusal), "{group}: {text}");
        assert!(request_lines(&requests).is_empty(), "{group}: {:?}", request_lines(&requests));
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn users_update_and_delete_of_the_reserved_integrations_route_with_a_typed_host_send_nothing() {
    for (verb, extra, refusal) in [
        (
            "update",
            &["--file", "-"][..],
            "'integrations' is a reserved route, not a user id; use `fabric agent-stream api put",
        ),
        ("delete", &[][..], "'integrations' is a reserved route, not a user id, so there is no user to delete"),
    ] {
        let (host, requests) = agent_stream_host();
        let mut args = vec!["agent-stream", "--host", &host, "users", verb, "integrations"];
        args.extend_from_slice(extra);

        let output = fabric_in_fresh_home(&args, &[], &[("FABRIC_TOKEN", SESSION_TOKEN)], "{}");

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(1), "{verb}: {text}");
        assert!(text.contains(refusal), "{verb}: {text}");
        assert!(request_lines(&requests).is_empty(), "{verb}: {:?}", request_lines(&requests));
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn identities_create_update_and_deactivate_print_the_agent_gateway_lines() {
    let identity = r#"{"id":"i-1","did":"did:webvh:x:agents/a","version":1,"active":true}"#;
    let deactivated = r#"{"message":"Identity deactivated","id":"i-1","version_id":"2-QmHash","deactivated_at":"2026-11-01T00:00:00Z"}"#;
    let (host, _) = agent_stream_stand_in(vec![
        ("POST /api/v1/identities/i-1/update", "200 OK", identity),
        ("POST /api/v1/identities", "201 Created", identity),
        ("DELETE /api/v1/identities/i-1", "200 OK", deactivated),
    ]);

    let create = fabric_on_stream(&host, &["identities", "create"], "");
    let update = fabric_on_stream(
        &host,
        &["identities", "update", "i-1", "--file", "-"],
        r#"{"did_document":{"id":"did:webvh:x:agents/a"}}"#,
    );
    let deactivate = fabric_on_stream(&host, &["identities", "deactivate", "i-1"], "");
    let deactivate_json = fabric_on_stream(&host, &["--output", "json", "identities", "deactivate", "i-1"], "");

    assert_eq!(stdout(&create), "Created identity 'i-1'\n", "{}", stderr(&create));
    assert_eq!(stdout(&update), "Updated identity 'i-1'\n", "{}", stderr(&update));
    assert_eq!(stdout(&deactivate), "Deactivated identity 'i-1'\n", "{}", stderr(&deactivate));
    let printed: serde_json::Value = serde_json::from_str(&stdout(&deactivate_json)).expect("JSON");
    let sent: serde_json::Value = serde_json::from_str(deactivated).expect("JSON");
    assert_eq!(printed, sent);
}

#[cfg(feature = "agent-stream")]
#[test]
fn identities_get_hides_a_key_pair_with_a_note_that_names_no_flag() {
    let (host, _) = agent_stream_stand_in(vec![(
        "GET /api/v1/identities/i-1",
        "200 OK",
        r#"{"id":"i-1","did":"did:webvh:x:agents/a","key_pair":{"private_key":{"d":"private-scalar"}}}"#,
    )]);

    let output = fabric_on_stream(&host, &["identities", "get", "i-1"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stdout(&output).contains("private-scalar"), "{}", stdout(&output));
    assert_eq!(stderr_beyond_the_environment_note(&output), "note: hid 'key_pair'.\n");
}

#[cfg(feature = "agent-stream")]
#[test]
fn users_delete_with_output_json_prints_a_removed_outcome() {
    let (host, _) = agent_stream_stand_in(vec![("DELETE /api/v1/users/u-1", "200 OK", r#"{"outcome":"removed"}"#)]);

    let output = fabric_on_stream(&host, &["--output", "json", "users", "delete", "u-1"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    let printed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert_eq!(printed, serde_json::json!({"outcome": "removed"}));
}

/// What a command printed on standard error, less the note every
/// [`fabric_on_stream`] run gets for taking both the host and the token from
/// the environment.
#[cfg(feature = "agent-stream")]
fn stderr_beyond_the_environment_note(output: &Output) -> String {
    stderr(output)
        .lines()
        .filter(|line| !line.starts_with("note: sending the token from FABRIC_TOKEN"))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// An Agent Stream audit page: no `truncated`, `dropped_records`,
/// `history_bytes`, or `soft_cap_bytes`, which only Agent Gateway sends.
#[cfg(feature = "agent-stream")]
const AUDIT_PAGE: &str = r#"{"events":[{"timestamp":"2026-11-01T00:00:00Z","event":{"policy_decision":{"scope":"pipe","flow":"access_point","policy_id":"data.llm.policy.allow","decision":"deny","surface_id":"pipe-1"}},"vp_jwt":"eyJ.secret.jwt"}],"total":1,"page":1,"page_size":100,"total_pages":1,"category_counts":{"policy_decision":1}}"#;

#[cfg(feature = "agent-stream")]
#[test]
fn audit_list_prints_the_agent_gateway_table_with_no_truncation_note() {
    let (host, _) = agent_stream_stand_in(vec![("GET /api/v1/audit?limit=100&page=1", "200 OK", AUDIT_PAGE)]);

    let table = fabric_on_stream(&host, &["audit", "list"], "");
    let json = fabric_on_stream(&host, &["--output", "json", "audit", "list"], "");

    assert_eq!(
        stdout(&table),
        "TIMESTAMP             EVENT            SURFACE  DECISION  DETAIL\n\
         2026-11-01T00:00:00Z  policy_decision  pipe-1   deny      -\n",
        "{}",
        stderr(&table)
    );
    assert_eq!(stderr_beyond_the_environment_note(&table), "");
    assert!(json.status.success(), "{}", stderr(&json));
    assert!(!stdout(&json).contains("eyJ.secret.jwt"), "{}", stdout(&json));
}

#[cfg(feature = "agent-stream")]
#[test]
fn settings_set_warns_about_the_agent_stream_audit_field_and_prints_the_read_back() {
    let (host, _) = agent_stream_stand_in(vec![
        ("POST /api/v1/settings", "200 OK", r#"{"audit_enabled":true}"#),
        ("GET /api/v1/settings", "200 OK", r#"{"audit_enabled":true,"prometheus_auth_password_hash":""}"#),
    ]);

    let output = fabric_on_stream(
        &host,
        &["--output", "json", "settings", "set", "--file", "-"],
        r#"{"audit_enabled":true,"audit_categories":{"policies":true}}"#,
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stderr_beyond_the_environment_note(&output),
        "warning: 'audit_categories' replaces the stored categories; any category missing from this document is \
         switched off\n"
    );
    let printed: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON");
    assert_eq!(printed, serde_json::json!({"audit_enabled": true, "prometheus_auth_password_hash": ""}));
}

#[cfg(feature = "agent-stream")]
#[test]
fn metrics_test_endpoint_prints_no_latency_agent_stream_does_not_send() {
    let (host, _) = agent_stream_stand_in(vec![(
        "POST /api/v1/metrics/test-connection",
        "200 OK",
        r#"{"success":true,"message":"Reached the collector at collector.example:4317."}"#,
    )]);

    let output = fabric_on_stream(&host, &["metrics", "test-endpoint", "https://collector.example:4317"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "{\n  \"message\": \"Reached the collector at collector.example:4317.\",\n  \"success\": true\n}\n"
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn logs_truncate_prints_what_agent_stream_removed() {
    let (host, _) = agent_stream_stand_in(vec![(
        "POST /api/v1/logs/truncate",
        "200 OK",
        r#"{"files_removed":2,"bytes_freed":2048,"current_log_kept":true}"#,
    )]);

    let output = fabric_on_stream(&host, &["logs", "truncate", "--yes"], "");

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "{\n  \"bytes_freed\": 2048,\n  \"current_log_kept\": true,\n  \"files_removed\": 2\n}\n"
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn audit_list_reports_an_audit_log_agent_stream_has_not_started_instead_of_an_empty_one() {
    let (host, _) = agent_stream_stand_in(vec![(
        "GET /api/v1/audit?limit=100&page=1",
        "503 Service Unavailable",
        "audit log temporarily unavailable: Audit logger not initialized",
    )]);

    let output = fabric_on_stream(&host, &["audit", "list"], "");

    assert!(!output.status.success());
    assert_eq!(stdout(&output), "");
    assert_eq!(
        stderr_beyond_the_environment_note(&output),
        "error: audit log temporarily unavailable: Audit logger not initialized\n"
    );
}

/// Runs `fabric agent-stream <args>` against a saved Agent Stream at `host`
/// with an access token from the environment, which is sent without the
/// product probe, and nothing on standard input, which is not a terminal.
#[cfg(feature = "agent-stream")]
fn agent_stream_command(
    host: &str,
    args: &[&str],
) -> Output {
    let config = format!("current = \"test\"\n\n[connections.test]\nhost = \"{host}\"\n");
    let mut argv = vec!["agent-stream"];
    argv.extend_from_slice(args);
    fabric_in_fresh_home(
        &argv,
        &[("agent-stream.toml", &config)],
        &[("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    )
}

/// A governance record whose surface stores bodies.
#[cfg(feature = "agent-stream")]
const GOVERNANCE_RECORD: &str = r#"{"record":{"record_id":"r1","prompt":"my card is 4111-1111","completion":"noted","stages":[{"stage":"llm","outcome":"allow"}]},"signed_vc":{"credentialSubject":{"prompt":"my card is 4111-1111"}},"seq":3}"#;

#[cfg(feature = "agent-stream")]
#[test]
fn governance_verify_exits_1_and_reports_a_security_finding_for_a_broken_chain() {
    let (host, requests) = host_answering(
        AGENT_STREAM_PERMISSIONS,
        r#"{"surface_id":"s2","valid":false,"count":0,"problem":"broken","error":"hash mismatch at seq 2"}"#,
    );

    let output = agent_stream_command(&host, &["governance", "verify", "--surface", "s2"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stdout(&output).contains("broken"), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("security finding: the governance record chain of surface 's2' is broken"),
        "{}",
        stderr(&output)
    );
    assert!(stderr(&output).contains("1 of 1 governance record chains are not valid"), "{}", stderr(&output));
    assert_eq!(request_lines(&requests), ["GET /api/v1/governance/verify?surface_id=s2 HTTP/1.1"]);
}

#[cfg(feature = "agent-stream")]
#[test]
fn governance_verify_exits_0_for_an_intact_chain() {
    let (host, _) = host_answering(AGENT_STREAM_PERMISSIONS, r#"{"surface_id":"s1","valid":true,"count":12}"#);

    let output = agent_stream_command(&host, &["governance", "verify", "--surface", "s1"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("12"), "{}", stdout(&output));
    assert!(!stderr(&output).contains("security finding"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn governance_records_get_hides_prompt_content_without_reveal() {
    let (host, _) = host_answering(AGENT_STREAM_PERMISSIONS, GOVERNANCE_RECORD);

    let output = agent_stream_command(&host, &["governance", "records", "get", "r1", "--surface", "s1"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stdout(&output).contains("4111"), "{}", stdout(&output));
    assert!(!stdout(&output).contains("noted"), "{}", stdout(&output));
    assert!(stdout(&output).contains("pass --reveal to show"), "{}", stdout(&output));
    assert!(!stderr(&output).contains("warning"), "{}", stderr(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn governance_records_get_with_reveal_shows_prompt_content_and_warns() {
    let (host, _) = host_answering(AGENT_STREAM_PERMISSIONS, GOVERNANCE_RECORD);

    let output = agent_stream_command(&host, &["governance", "records", "get", "r1", "--surface", "s1", "--reveal"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("my card is 4111-1111"), "{}", stdout(&output));
    assert!(stderr(&output).contains("warning: this output contains prompt content"), "{}", stderr(&output));
    assert!(!stdout(&output).contains("warning"), "{}", stdout(&output));
}

#[cfg(feature = "agent-stream")]
#[test]
fn governance_records_list_never_shows_prompt_content_and_has_no_all_option() {
    let page: &'static str = Box::leak(format!("[{GOVERNANCE_RECORD}]").into_boxed_str());
    let (host, _) = host_answering(AGENT_STREAM_PERMISSIONS, page);

    let output = agent_stream_command(&host, &["--output", "json", "governance", "records", "list", "--surface", "s1"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(value["next_cursor"], serde_json::Value::Null);
    assert!(!stdout(&output).contains("4111"), "{}", stdout(&output));
    let all = fabric(&["agent-stream", "governance", "records", "list", "--surface", "s1", "--all"], &[]);
    assert_eq!(all.status.code(), Some(2), "{}", stderr(&all));
}

#[cfg(feature = "agent-stream")]
#[test]
fn drift_run_and_baseline_set_refuse_without_a_terminal_and_send_nothing() {
    let (host, requests) = agent_stream_host();

    for args in [
        &["drift", "run", "--surface", "s1"][..],
        &["drift", "baseline", "set", "--surface", "s1", "--window", "7d"][..],
    ] {
        let output = agent_stream_command(&host, args);

        assert_eq!(output.status.code(), Some(1), "{args:?}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("without confirmation in a non-interactive session; pass --yes"),
            "{}",
            stderr(&output)
        );
    }
    assert!(request_lines(&requests).is_empty(), "{:?}", request_lines(&requests));
}

#[cfg(feature = "agent-stream")]
#[test]
fn drift_run_wait_exits_1_when_the_run_is_cancelled() {
    let (host, requests) = host_answering(
        AGENT_STREAM_PERMISSIONS,
        r#"{"id":"run-1","status":"cancelled","samples":[{"input":"secret prompt","output":"answer"}]}"#,
    );

    let output = agent_stream_command(&host, &["drift", "run", "--surface", "s1", "--yes", "--force", "--wait"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("drift run 'run-1' ended cancelled"), "{}", stderr(&output));
    assert!(!stdout(&output).contains("secret prompt"), "{}", stdout(&output));
    // drift run has no --reveal, so its placeholder points to runs get.
    assert!(stdout(&output).contains("shown only by `get --reveal`"), "{}", stdout(&output));
    assert_eq!(
        request_lines(&requests),
        ["POST /api/v1/drift/eval/run?surface_id=s1 HTTP/1.1", "GET /api/v1/drift/runs/run-1 HTTP/1.1"]
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn drift_runs_get_hides_samples_unless_reveal_and_then_warns() {
    let (host, _) = host_answering(
        AGENT_STREAM_PERMISSIONS,
        r#"{"id":"run-1","status":"completed","samples":[{"input":"replayed secret prompt","output":"answer","passed":true}]}"#,
    );

    let hidden = agent_stream_command(&host, &["drift", "runs", "get", "run-1"]);
    let shown = agent_stream_command(&host, &["drift", "runs", "get", "run-1", "--reveal"]);

    assert!(hidden.status.success(), "{}", stderr(&hidden));
    assert!(!stdout(&hidden).contains("replayed secret prompt"), "{}", stdout(&hidden));
    assert!(!stderr(&hidden).contains("warning"), "{}", stderr(&hidden));
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert!(stdout(&shown).contains("replayed secret prompt"), "{}", stdout(&shown));
    assert!(stderr(&shown).contains("warning: this output contains prompt content"), "{}", stderr(&shown));
}

#[cfg(feature = "agent-stream")]
#[test]
fn connections_connection_points_and_mediators_lists_print_the_agent_gateway_tables_and_runtime_status_json() {
    let (host, _) = agent_stream_stand_in(vec![
        (
            "GET /api/v1/gateways",
            "200 OK",
            r#"[{"id":"g-1","name":"Partner","description":"","did":"did:web:partner.example","gateway_type":"remote","status":"active","creation_type":"user","created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z","exposed_channels":[],"runtime_status":{"status":"connected","last_active_at":"2026-11-02T00:00:00Z"}}]"#,
        ),
        (
            "GET /api/v1/connection-points",
            "200 OK",
            r#"[{"id":"cp-1","gateway_id":"g-self","mediator_id":"m-1","connection_point_did":"did:web:x","name":"Front door","description":"","oob_url":"https://x","use_count":2,"expires_at":null,"integration_id":null,"integration_variables":{},"integrations":[],"cp_type":"user","exposed_channels":[],"enabled":true,"did_method":"web"}]"#,
        ),
        (
            "GET /api/v1/mediators",
            "200 OK",
            r#"[{"id":"m-1","name":"EU mediator","description":"Main","did":"did:web:mediator.example","status":"active","our_did":"did:peer:2.x","created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-01T00:00:00Z"}]"#,
        ),
    ]);

    let connections = fabric_on_stream(&host, &["connections", "list"], "");
    let connections_json = fabric_on_stream(&host, &["--output", "json", "connections", "list"], "");
    let points = fabric_on_stream(&host, &["connection-points", "list"], "");
    let mediators = fabric_on_stream(&host, &["mediators", "list"], "");

    assert_eq!(
        stdout(&connections),
        "NAME     ID   TYPE    STATUS  UPDATED\n\
         Partner  g-1  remote  active  2026-11-02T00:00:00Z\n",
        "{}",
        stderr(&connections)
    );
    let listed: serde_json::Value = serde_json::from_str(&stdout(&connections_json)).expect("JSON");
    assert_eq!(listed[0]["runtime_status"]["status"], "connected", "{}", stderr(&connections_json));
    assert_eq!(
        stdout(&points),
        "NAME        ID    CONNECTION  ENABLED  USES  EXPIRES\n\
         Front door  cp-1  g-self      yes      2     never\n",
        "{}",
        stderr(&points)
    );
    assert_eq!(
        stdout(&mediators),
        "NAME         ID   STATUS  DID                       DESCRIPTION\n\
         EU mediator  m-1  active  did:web:mediator.example  Main\n",
        "{}",
        stderr(&mediators)
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn connections_connection_points_and_mediators_print_the_agent_gateway_lines() {
    let (host, _) = agent_stream_stand_in(vec![
        ("POST /api/v1/gateways", "200 OK", r#"{"id":"g-1","name":"Partner"}"#),
        ("PUT /api/v1/gateways/g-1", "200 OK", r#"{"id":"g-1","name":"Partner"}"#),
        ("DELETE /api/v1/gateways/g-1", "204 No Content", ""),
        ("PUT /api/v1/connection-points/cp-1", "200 OK", r#"{"id":"cp-1","name":"Door"}"#),
        ("DELETE /api/v1/connection-points/cp-1", "204 No Content", ""),
        ("POST /api/v1/mediators", "200 OK", r#"{"id":"m-1","name":"EU mediator"}"#),
        ("PUT /api/v1/mediators/m-1", "200 OK", r#"{"id":"m-1","name":"EU mediator"}"#),
        ("DELETE /api/v1/mediators/m-1", "204 No Content", ""),
    ]);
    let run = |args: &[&str]| fabric_on_stream(&host, args, r#"{"name":"x"}"#);

    for (args, line) in [
        (&["connections", "create", "--file", "-"][..], "Created connection 'g-1'\n"),
        (&["connections", "update", "g-1", "--file", "-"], "Updated connection 'g-1'\n"),
        (&["connections", "delete", "g-1", "--yes"], "Deleted connection 'g-1'\n"),
        (&["connection-points", "update", "cp-1", "--file", "-"], "Updated connection point 'cp-1'\n"),
        (&["connection-points", "delete", "cp-1"], "Deleted connection point 'cp-1'\n"),
        (&["mediators", "create", "--file", "-"], "Created mediator 'm-1'\n"),
        (&["mediators", "update", "m-1", "--file", "-"], "Updated mediator 'm-1'\n"),
        (&["mediators", "delete", "m-1"], "Deleted mediator 'm-1'\n"),
    ] {
        let output = run(args);

        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        assert_eq!(stdout(&output), line, "{args:?}: {}", stderr(&output));
    }
}

/// The invitation secret a `connection-points create` document sends, which
/// the stand-in sends back in its create answer.
#[cfg(feature = "agent-stream")]
const INVITATION_SECRET: &str = "invitation-secret-of-at-least-32-bytes";

#[cfg(feature = "agent-stream")]
#[test]
fn connection_points_create_prints_only_the_id_in_a_table_and_the_answer_in_json() {
    let answer = r#"{"connection_point":{"id":"cp-1","gateway_id":"g-self","mediator_id":"m-1","name":"Door","use_count":0,"secret":"invitation-secret-of-at-least-32-bytes"}}"#;
    let (host, _) = agent_stream_stand_in(vec![("POST /api/v1/connection-points", "200 OK", answer)]);
    let document = format!(
        r#"{{"gateway_id":"g-self","mediator_id":"m-1","name":"Door","description":"","secret":"{INVITATION_SECRET}"}}"#
    );

    let table = fabric_on_stream(&host, &["connection-points", "create", "--file", "-"], &document);
    let json = fabric_on_stream(&host, &["--output", "json", "connection-points", "create", "--file", "-"], &document);

    assert!(table.status.success(), "{}", stderr(&table));
    assert_eq!(stdout(&table), "Created connection point 'cp-1'\n");
    assert!(!stderr(&table).contains(INVITATION_SECRET), "{}", stderr(&table));
    let printed: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("JSON");
    assert_eq!(printed["connection_point"]["secret"], INVITATION_SECRET);
}

/// The groups this build adds for an Agent Stream's account settings and
/// credentials, each with a command that would otherwise parse.
#[cfg(not(feature = "agent-stream"))]
const ACCOUNT_AND_CREDENTIAL_COMMANDS: [&[&str]; 8] = [
    &["user-settings", "show"],
    &["terms", "status"],
    &["notifications", "welcome-template", "show"],
    &["tenant-ownership", "impact", "pipes", "p-1"],
    &["certificates", "list"],
    &["credential-providers", "list"],
    &["jwt-verification-strategies", "list"],
    &["delegation-vault", "list"],
];

#[cfg(not(feature = "agent-stream"))]
#[test]
fn the_default_build_refuses_each_agent_stream_account_and_credential_group() {
    for words in ACCOUNT_AND_CREDENTIAL_COMMANDS {
        let args: Vec<&str> = ["agent-stream"]
            .into_iter()
            .chain(words.iter().copied())
            .collect();

        let output = fabric(&args, &[]);

        assert_eq!(output.status.code(), Some(USAGE_EXIT_CODE), "{words:?}: {}", stderr(&output));
        assert!(stderr(&output).contains("unrecognized subcommand 'agent-stream'"), "{words:?}: {}", stderr(&output));
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn certificates_credential_providers_jwt_strategies_and_grants_print_the_agent_gateway_tables() {
    let (host, _) = agent_stream_stand_in(vec![
        (
            "GET /api/v1/certificates",
            "200 OK",
            r#"[{"id":"cert-1","name":"Edge","certificate_id":"c-1","tags":[],"kind":"server_leaf","active":true,"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z"}]"#,
        ),
        (
            "GET /api/v1/credential-providers",
            "200 OK",
            r#"[{"id":"cp-1","name":"Stripe","provider_id":"stripe","provider_type":"api_key","default_scopes":[],"token_refresh_enabled":true}]"#,
        ),
        (
            "GET /api/v1/jwt-verification-strategies",
            "200 OK",
            r#"[{"id":"j-1","name":"Partner IdP","expected_issuer":"https://idp.example.com/","jwks_source":{"type":"remote","jwks_uri":"https://idp.example.com/jwks.json"},"created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z"}]"#,
        ),
        (
            "GET /api/v1/delegation-vault",
            "200 OK",
            r#"[{"id":"g-1","agent_did":"did:web:agent.example","user_identity_hash":"3f9a0c","credential_provider_id":"cp-1","provider_id":"stripe","token_type":"Bearer","scopes":[],"expires_at":null,"is_expired":false,"can_refresh":false}]"#,
        ),
    ]);

    let certificates = fabric_on_stream(&host, &["certificates", "list"], "");
    let providers = fabric_on_stream(&host, &["credential-providers", "list"], "");
    let strategies = fabric_on_stream(&host, &["jwt-verification-strategies", "list"], "");
    let grants = fabric_on_stream(&host, &["delegation-vault", "list"], "");

    assert_eq!(
        stdout(&certificates),
        "NAME  ID      KIND         ACTIVE  UPDATED\n\
         Edge  cert-1  server_leaf  yes     2026-11-02T00:00:00Z\n",
        "{}",
        stderr(&certificates)
    );
    assert_eq!(
        stdout(&providers),
        "NAME    ID    PROVIDER ID  TYPE\n\
         Stripe  cp-1  stripe       api_key\n",
        "{}",
        stderr(&providers)
    );
    assert_eq!(
        stdout(&strategies),
        "NAME         ID   ISSUER                    UPDATED\n\
         Partner IdP  j-1  https://idp.example.com/  2026-11-02T00:00:00Z\n",
        "{}",
        stderr(&strategies)
    );
    assert_eq!(
        stdout(&grants),
        "ID   AGENT DID              PROVIDER  EXPIRES  EXPIRED\n\
         g-1  did:web:agent.example  stripe    never    no\n",
        "{}",
        stderr(&grants)
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn certificates_credential_providers_jwt_strategies_and_grants_print_the_agent_gateway_lines() {
    let certificate = r#"{"id":"cert-1","name":"Edge","certificate_pem":"-----BEGIN CERTIFICATE-----"}"#;
    let (host, _) = agent_stream_stand_in(vec![
        ("POST /api/v1/certificates", "201 Created", certificate),
        ("PUT /api/v1/certificates/cert-1", "200 OK", certificate),
        ("DELETE /api/v1/certificates/cert-1", "204 No Content", ""),
        ("GET /api/v1/certificates", "200 OK", r#"[{"id":"cert-1","name":"Edge"}]"#),
        ("POST /api/v1/credential-providers", "201 Created", r#"{"id":"cp-1","name":"Stripe"}"#),
        ("PUT /api/v1/credential-providers/cp-1", "200 OK", r#"{"id":"cp-1","name":"Stripe"}"#),
        ("DELETE /api/v1/credential-providers/cp-1", "204 No Content", ""),
        ("POST /api/v1/jwt-verification-strategies", "201 Created", r#"{"id":"j-1","name":"Partner IdP"}"#),
        ("PUT /api/v1/jwt-verification-strategies/j-1", "200 OK", r#"{"id":"j-1","name":"Partner IdP"}"#),
        ("DELETE /api/v1/jwt-verification-strategies/j-1", "204 No Content", ""),
        ("DELETE /api/v1/delegation-vault/by-user/3f9a0c", "200 OK", r#"{"revoked":2}"#),
        ("DELETE /api/v1/delegation-vault/g-1", "204 No Content", ""),
    ]);
    let run = |args: &[&str]| fabric_on_stream(&host, args, r#"{"name":"x"}"#);

    for (args, line) in [
        (&["certificates", "create", "--file", "-"][..], "Created certificate 'cert-1'\n"),
        (&["certificates", "update", "Edge", "--file", "-"], "Updated certificate 'cert-1'\n"),
        (&["certificates", "delete", "Edge", "--yes"], "Deleted certificate 'cert-1'\n"),
        (&["credential-providers", "create", "--file", "-"], "Created credential provider 'cp-1'\n"),
        (&["credential-providers", "update", "cp-1", "--file", "-"], "Updated credential provider 'cp-1'\n"),
        (&["credential-providers", "delete", "cp-1", "--yes"], "Deleted credential provider 'cp-1'\n"),
        (&["jwt-verification-strategies", "create", "--file", "-"], "Created JWT verification strategy 'j-1'\n"),
        (&["jwt-verification-strategies", "update", "j-1", "--file", "-"], "Updated JWT verification strategy 'j-1'\n"),
        (&["jwt-verification-strategies", "delete", "j-1", "--yes"], "Deleted JWT verification strategy 'j-1'\n"),
        (&["delegation-vault", "revoke", "g-1", "--yes"], "Revoked grant 'g-1'\n"),
        (&["delegation-vault", "revoke-user", "3f9a0c", "--yes"], "Revoked 2 grants for user '3f9a0c'\n"),
    ] {
        let output = run(args);

        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        assert_eq!(stdout(&output), line, "{args:?}: {}", stderr(&output));
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn user_settings_terms_notifications_and_tenant_ownership_print_the_agent_gateway_tables_and_lines() {
    let (host, _) = agent_stream_stand_in(vec![
        (
            "GET /api/v1/user-settings",
            "200 OK",
            r#"{"refresh_interval_seconds":30,"prometheus_auth_password_hash":"$2b$12$hash"}"#,
        ),
        ("POST /api/v1/user-settings", "200 OK", r#"{"refresh_interval_seconds":60}"#),
        ("DELETE /api/v1/user-settings", "200 OK", r#"{"refresh_interval_seconds":30}"#),
        ("GET /api/v1/terms/status", "200 OK", r#"{"accepted":true,"required":[]}"#),
        ("POST /api/v1/terms/customer/deactivate", "204 No Content", ""),
        ("PUT /api/v1/notifications/user-welcome-template", "204 No Content", ""),
        ("GET /api/v1/users/u-1", "200 OK", r#"{"id":"u-1"}"#),
        ("POST /api/v1/notifications/send-welcome", "204 No Content", ""),
        (
            "GET /api/v1/tenant-ownership/pipes/p-1/impact",
            "200 OK",
            r#"{"kind":"pipes","id":"p-1","tenant_id":"acme","immutable":false}"#,
        ),
        ("PUT /api/v1/tenant-ownership/pipes/p-1", "200 OK", r#"{"kind":"pipes","id":"p-1","tenant_id":"acme"}"#),
    ]);
    let run = |args: &[&str]| fabric_on_stream(&host, args, r#"{"refresh_interval_seconds":60}"#);

    for (args, printed) in [
        (&["user-settings", "show"][..], "{\n  \"refresh_interval_seconds\": 30\n}\n"),
        (&["user-settings", "set", "--file", "-"], "{\n  \"refresh_interval_seconds\": 60\n}\n"),
        (&["user-settings", "reset"], "{\n  \"refresh_interval_seconds\": 30\n}\n"),
        (&["terms", "status"], "{\n  \"accepted\": true,\n  \"required\": []\n}\n"),
        (&["terms", "deactivate"], "Customer Terms of Use deactivated.\n"),
        (&["notifications", "welcome-template", "set", "--file", "-"], "Welcome notification template updated.\n"),
        (
            &["notifications", "send-welcome", "--user-id", "u-1", "--title", "Welcome", "--message", "Hello"],
            "Welcome notification sent.\n",
        ),
        (
            &["tenant-ownership", "impact", "pipes", "p-1"],
            "{\n  \"id\": \"p-1\",\n  \"immutable\": false,\n  \"kind\": \"pipes\",\n  \"tenant_id\": \"acme\"\n}\n",
        ),
        (
            &["tenant-ownership", "set", "pipes", "p-1", "--tenant", "acme"],
            "{\n  \"id\": \"p-1\",\n  \"kind\": \"pipes\",\n  \"tenant_id\": \"acme\"\n}\n",
        ),
    ] {
        let output = run(args);

        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        assert_eq!(stdout(&output), printed, "{args:?}: {}", stderr(&output));
    }
}

/// A certificate answer carrying a private key, which Agent Stream never
/// sends, to check that the CLI would not print one anyway.
#[cfg(feature = "agent-stream")]
const CERTIFICATE_WITH_KEY: &str =
    r#"{"id":"cert-1","name":"Edge","certificate_pem":"pem","private_key_pem":"-----BEGIN PRIVATE KEY-----x"}"#;

#[cfg(feature = "agent-stream")]
#[test]
fn certificates_never_print_a_private_key_and_offer_no_reveal() {
    let (host, _) = agent_stream_stand_in(vec![
        ("GET /api/v1/certificates/cert-1", "200 OK", CERTIFICATE_WITH_KEY),
        ("POST /api/v1/certificates", "201 Created", CERTIFICATE_WITH_KEY),
        ("PUT /api/v1/certificates/cert-1", "200 OK", CERTIFICATE_WITH_KEY),
        (
            "GET /api/v1/certificates",
            "200 OK",
            r#"[{"id":"cert-1","name":"Edge","private_key_pem":"-----BEGIN PRIVATE KEY-----x"}]"#,
        ),
    ]);
    let document = r#"{"name":"Edge","certificate_pem":"pem","private_key_pem":"-----BEGIN PRIVATE KEY-----x"}"#;

    let get = fabric_on_stream(&host, &["certificates", "get", "cert-1"], "");
    let create = fabric_on_stream(&host, &["--output", "json", "certificates", "create", "--file", "-"], document);
    let update =
        fabric_on_stream(&host, &["--output", "json", "certificates", "update", "cert-1", "--file", "-"], document);
    let list = fabric_on_stream(&host, &["--output", "json", "certificates", "list"], "");
    let reveal = fabric_on_stream(&host, &["certificates", "get", "cert-1", "--reveal"], "");

    for (name, output) in [("get", &get), ("create", &create), ("update", &update), ("list", &list)] {
        assert!(output.status.success(), "{name}: {}", stderr(output));
        assert!(!stdout(output).contains("PRIVATE KEY"), "{name}: {}", stdout(output));
        assert!(!stderr(output).contains("PRIVATE KEY"), "{name}: {}", stderr(output));
        assert!(!stdout(output).contains("private_key_pem"), "{name}: {}", stdout(output));
        assert!(stderr(output).contains("note: hid 'private_key_pem'.\n"), "{name}: {}", stderr(output));
    }
    assert_eq!(reveal.status.code(), Some(2), "{}", stderr(&reveal));
    assert!(stderr(&reveal).contains("unexpected argument '--reveal'"), "{}", stderr(&reveal));
}

/// A document saved from a masked answer, as `fabric agent-gateway
/// certificates get` prints it.
#[cfg(feature = "agent-stream")]
const MASKED_CERTIFICATE: &str =
    r#"{"name":"Edge","certificate_pem":"pem","private_key_pem":"<hidden; pass --reveal to show>"}"#;

#[cfg(feature = "agent-stream")]
#[test]
fn a_masked_document_is_refused_without_pointing_at_a_reveal_flag_the_command_lacks() {
    let (host, requests) = agent_stream_stand_in(vec![
        ("POST /api/v1/certificates", "201 Created", r#"{"id":"cert-1"}"#),
        ("POST /api/v1/credential-providers", "201 Created", r#"{"id":"cp-1"}"#),
        ("PUT /api/v1/certificates/cert-1", "200 OK", r#"{"id":"cert-1"}"#),
    ]);

    for args in [
        &["certificates", "create", "--file", "-"][..],
        &["credential-providers", "create", "--file", "-"],
        &["api", "put", "/v1/certificates/cert-1", "--file", "-"],
        &["surfaces", "create", "--file", "-"],
    ] {
        let output = fabric_on_stream(&host, args, MASKED_CERTIFICATE);

        assert_eq!(output.status.code(), Some(1), "{args:?}: {}", stderr(&output));
        assert!(
            stderr(&output).ends_with(
                "\nerror: the request body still carries the masked placeholder <hidden; pass --reveal to show>; \
                 this command has no --reveal, so remove the masked field to leave the stored credential untouched, \
                 or put the real value in its place\n"
            ),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    let secret = fabric_on_stream(
        &host,
        &["secrets", "update", "s-1", "--file", "-"],
        r#"{"value":"<hidden; pass --reveal to show>","update_value":true}"#,
    );
    assert!(
        stderr(&secret).ends_with(
            "\nerror: the request body still carries the masked placeholder <hidden; pass --reveal to show>; \
             re-read the entity with --reveal, or remove the masked field to leave the stored credential untouched\n"
        ),
        "`secrets` has --reveal: {}",
        stderr(&secret)
    );
    assert!(
        request_lines(&requests)
            .iter()
            .all(|line| line.starts_with("GET ")),
        "{:?}",
        request_lines(&requests)
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn delegation_vault_reads_never_print_a_grant_token() {
    let grant = r#"{"id":"g-1","agent_did":"did:web:agent.example","provider_id":"stripe","access_token":"at_do_not_print","refresh_token":"rt_do_not_print"}"#;
    let (host, _) = agent_stream_stand_in(vec![
        ("GET /api/v1/delegation-vault/g-1", "200 OK", grant),
        (
            "GET /api/v1/delegation-vault",
            "200 OK",
            r#"[{"id":"g-1","agent_did":"did:web:agent.example","provider_id":"stripe","access_token":"at_do_not_print","refresh_token":"rt_do_not_print"}]"#,
        ),
    ]);

    for args in [
        &["--output", "json", "delegation-vault", "list"][..],
        &["--output", "json", "delegation-vault", "get", "g-1"],
        &["delegation-vault", "get", "g-1"],
    ] {
        let output = fabric_on_stream(&host, args, "");

        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        for token in ["at_do_not_print", "rt_do_not_print"] {
            assert!(!stdout(&output).contains(token), "{args:?}: {}", stdout(&output));
            assert!(!stderr(&output).contains(token), "{args:?}: {}", stderr(&output));
        }
        assert!(stdout(&output).contains("g-1"), "{args:?}: {}", stdout(&output));
        assert!(
            stderr(&output).contains("note: hid 'access_token', 'refresh_token'.\n"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[cfg(feature = "agent-stream")]
#[test]
fn send_welcome_stops_without_a_permission_warning_when_the_terms_gate_refuses_the_lookup() {
    let (host, requests) = agent_stream_stand_in(vec![
        (
            "GET /api/v1/users/u-1",
            "403 Forbidden",
            r#"{"code":"TERMS_ACCEPTANCE_REQUIRED","message":"Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then retry."}"#,
        ),
        ("POST /api/v1/notifications/send-welcome", "204 No Content", ""),
    ]);

    let output = fabric_on_stream(
        &host,
        &["notifications", "send-welcome", "--user-id", "u-1", "--title", "Welcome", "--message", "Hello"],
        "",
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).ends_with(
            "\nerror: Sign in to Agent Stream as this access token's owner, accept the required Terms and \
             Conditions, then retry.\n"
        ),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("warning:"), "{}", stderr(&output));
    assert!(
        !request_lines(&requests)
            .iter()
            .any(|line| line.starts_with("POST ")),
        "{:?}",
        request_lines(&requests)
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn send_welcome_warns_then_sends_when_the_lookup_lacks_users_view() {
    let (host, requests) = agent_stream_stand_in(vec![
        ("GET /api/v1/users/u-1", "403 Forbidden", r#"{"required_permission":"users.view"}"#),
        ("POST /api/v1/notifications/send-welcome", "204 No Content", ""),
    ]);

    let output = fabric_on_stream(
        &host,
        &["notifications", "send-welcome", "--user-id", "u-1", "--title", "Welcome", "--message", "Hello"],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "Welcome notification sent.\n");
    assert!(stderr(&output).contains("\nwarning: could not verify that user 'u-1' exists"), "{}", stderr(&output));
    assert!(
        request_lines(&requests).contains(&"POST /api/v1/notifications/send-welcome HTTP/1.1".to_owned()),
        "{:?}",
        request_lines(&requests)
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn tenant_ownership_set_names_the_agent_stream_impact_command_when_a_move_is_blocked() {
    let (host, _) = agent_stream_stand_in(vec![(
        "PUT /api/v1/tenant-ownership/teams/t-1",
        "409 Conflict",
        r#"{"error":"tenant_ownership_conflict","kind":"teams","id":"t-1","requested_tenant_id":"acme","conflicts":[]}"#,
    )]);

    let output = fabric_on_stream(&host, &["tenant-ownership", "set", "teams", "t-1", "--tenant", "acme"], "");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "run `fabric agent-stream tenant-ownership impact <kind> <id>` to see the references blocking this move"
        ),
        "{}",
        stderr(&output)
    );
}

/// Two prompt templates as Agent Stream lists them, messages included.
#[cfg(feature = "agent-stream")]
const PROMPT_TEMPLATES: &str = r#"[{"id":"greeter","name":"Greeter","status":"enabled","default_version":2,
  "versions":[{"version":1,"messages":[{"role":"system","content":"SECRET-PROMPT-TEXT"}]},
              {"version":2,"messages":[{"role":"system","content":"SECRET-PROMPT-TEXT"}]}],
  "updated_at":"2026-11-02T00:00:00Z"}]"#;

#[cfg(feature = "agent-stream")]
#[test]
fn prompts_list_prints_each_template_with_its_version_numbers_and_never_its_messages() {
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, PROMPT_TEMPLATES);

    let output = fabric_in_fresh_home(
        &["agent-stream", "prompts", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(text.contains("ID") && text.contains("VERSIONS") && text.contains("DEFAULT"), "{text}");
    assert!(text.contains("greeter") && text.contains("1, 2"), "{text}");
    assert!(!text.contains("SECRET-PROMPT-TEXT"), "{text}");
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "GET /api/v1/prompts HTTP/1.1"]);
}

#[cfg(feature = "agent-stream")]
#[test]
fn prompts_render_prints_each_message_role_and_content() {
    let answer = r#"{"messages":[{"role":"system","content":"Hi Ada"},{"role":"user","content":"Where is it?"}],"variables":["name"]}"#;
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, answer);

    let output = fabric_in_fresh_home(
        &["agent-stream", "prompts", "render", "greeter", "--var", "name=Ada"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "[system]\nHi Ada\n\n[user]\nWhere is it?\n");
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "POST /api/v1/prompts/greeter/render HTTP/1.1"]);
}

#[cfg(feature = "agent-stream")]
#[test]
fn prompts_create_dry_run_prints_the_preview_and_needs_no_login() {
    let home = tempfile::TempDir::new().expect("temp dir");
    let template = home
        .path()
        .join("template.json");
    std::fs::write(
        &template,
        r#"{"id":"greeter","name":"Greeter","versions":[{"version":1,"messages":[{"role":"user","content":"Hi"}]}]}"#,
    )
    .expect("template file");

    let output = fabric_in_home(
        home.path(),
        &[
            "agent-stream",
            "prompts",
            "create",
            "--file",
            template
                .to_str()
                .expect("path"),
            "--dry-run",
            "--output",
            "json",
        ],
        &[],
        &[UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let preview: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON preview");
    assert_eq!(preview["dry_run"], serde_json::json!(true));
    assert_eq!(preview["after"]["id"], serde_json::json!("greeter"));
    assert!(
        preview["changes"]
            .as_array()
            .expect("changes")
            .contains(&serde_json::json!({"version": 1, "change": "added"})),
        "{preview}"
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn prompts_list_as_json_keeps_each_template_but_never_its_messages() {
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, PROMPT_TEMPLATES);

    let output = fabric_in_fresh_home(
        &["agent-stream", "prompts", "list", "--output", "json"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(!text.contains("SECRET-PROMPT-TEXT"), "{text}");
    let listed: serde_json::Value = serde_json::from_str(&text).expect("JSON list");
    assert_eq!(listed[0]["id"], serde_json::json!("greeter"));
    assert_eq!(listed[0]["versions"], serde_json::json!([{"version": 1}, {"version": 2}]));
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "GET /api/v1/prompts HTTP/1.1"]);
}

#[cfg(feature = "agent-stream")]
#[test]
fn prompts_create_shows_agent_streams_plain_text_refusal_and_exits_non_zero() {
    let (host, requests) = host_replying(
        vec![("GET /api/v1/permissions/public", "200 OK", AGENT_STREAM_PERMISSIONS)],
        ("409 Conflict", "A prompt with id 'greeter' already exists"),
    );
    let home = tempfile::TempDir::new().expect("temp dir");
    let template = home
        .path()
        .join("template.json");
    std::fs::write(
        &template,
        r#"{"id":"greeter","name":"Greeter","versions":[{"version":1,"messages":[{"role":"user","content":"Hi"}]}]}"#,
    )
    .expect("template file");

    let output = fabric_in_home(
        home.path(),
        &[
            "agent-stream",
            "prompts",
            "create",
            "--file",
            template
                .to_str()
                .expect("path"),
        ],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stderr(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("A prompt with id 'greeter' already exists"), "{text}");
    assert!(!text.contains(ACCESS_TOKEN), "{text}");
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "POST /api/v1/prompts HTTP/1.1"]);
}

/// One member as Agent Stream lists it.
#[cfg(feature = "agent-stream")]
const MEMBER_LIST: &str = r#"[{"id":"m-ada","name":"Ada","status":"enabled","monthly_budget_usd":50,
  "identifiers":[{"kind":"email","email":"ada@example.com"},{"kind":"api_key","key_name":"ada-key"}],
  "updated_at":"2026-11-02T00:00:00Z"}]"#;

/// One team as Agent Stream lists it.
#[cfg(feature = "agent-stream")]
const TEAM_LIST: &str = r#"[{"id":"t-research","name":"Research","status":"enabled","members":["m-ada","m-bob"],
  "monthly_budget_usd":100,"updated_at":"2026-11-02T00:00:00Z"}]"#;

#[cfg(feature = "agent-stream")]
#[test]
fn members_list_prints_each_member_with_its_identifiers() {
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, MEMBER_LIST);

    let output = fabric_in_fresh_home(
        &["agent-stream", "members", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(text.contains("IDENTIFIERS"), "{text}");
    assert!(text.contains("m-ada") && text.contains("email:ada@example.com, api_key:ada-key"), "{text}");
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "GET /api/v1/members HTTP/1.1"]);
}

#[cfg(feature = "agent-stream")]
#[test]
fn teams_list_prints_each_team_with_its_number_of_members() {
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, TEAM_LIST);

    let output = fabric_in_fresh_home(
        &["agent-stream", "teams", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    let row = text
        .lines()
        .find(|line| line.starts_with("t-research"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(
        row.contains("Research")
            && row
                .split_whitespace()
                .any(|cell| cell == "2"),
        "{row}"
    );
    assert!(!text.contains("m-bob"), "{text}");
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "GET /api/v1/teams HTTP/1.1"]);
}

#[cfg(feature = "agent-stream")]
#[test]
fn teams_create_dry_run_prints_the_preview_and_needs_no_login() {
    let output = fabric_in_fresh_home(
        &[
            "agent-stream",
            "teams",
            "create",
            "--name",
            "Research",
            "--member",
            "m-ada",
            "--dry-run",
            "--output",
            "json",
        ],
        &[],
        &[UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let preview: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON preview");
    assert_eq!(preview["dry_run"], serde_json::json!(true));
    assert_eq!(preview["after"], serde_json::json!({"id": "", "name": "Research", "members": ["m-ada"]}));
}

#[cfg(feature = "agent-stream")]
#[test]
fn members_delete_shows_agent_stream_refusal_and_exits_non_zero() {
    let (host, requests) = agent_stream_stand_in(vec![(
        "DELETE /api/v1/members/m-ada",
        "409 Conflict",
        "Member belongs to team(s): Research. Remove them first.",
    )]);

    let output = fabric_in_fresh_home(
        &["agent-stream", "members", "delete", "m-ada"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stderr(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("Member belongs to team(s): Research. Remove them first."), "{text}");
    assert!(!text.contains(ACCESS_TOKEN), "{text}");
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "DELETE /api/v1/members/m-ada HTTP/1.1"]);
}

/// One answer that serves both catalog reads: built-in providers under
/// `providers`, and the custom catalog's text under `raw`.
#[cfg(feature = "agent-stream")]
const CATALOG: &str = r#"{"providers":[{"enum_value":"openai","name":"OpenAI","enabled":true,
  "models":[{"name":"GPT-4o mini","value":"gpt-4o-mini","cost_per_1k_input":0.00015,"cost_per_1k_output":0.0006},
            {"name":"GPT-4o","value":"gpt-4o","enabled":false}]}],
  "raw":"{\"providers\":[{\"enum_value\":\"acme\",\"name\":\"Acme\"}]}"}"#;

#[cfg(feature = "agent-stream")]
#[test]
fn providers_list_prints_built_in_and_custom_providers_with_their_source() {
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, CATALOG);

    let output = fabric_in_fresh_home(
        &["agent-stream", "providers", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    let row = |id: &str| {
        text.lines()
            .find(|line| line.starts_with(id))
            .unwrap_or_else(|| panic!("{text}"))
            .to_owned()
    };
    assert!(row("openai").contains("built-in"), "{text}");
    assert!(row("acme").contains("custom"), "{text}");
    assert_eq!(
        request_lines(&requests),
        [PROBE_REQUEST, "GET /api/v1/llm-providers HTTP/1.1", "GET /api/v1/llm-providers/custom HTTP/1.1"]
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn providers_models_prints_each_model_with_its_prices_and_whether_it_is_enabled() {
    let (host, _) = host_answering(AGENT_STREAM_PERMISSIONS, CATALOG);

    let output = fabric_in_fresh_home(
        &["agent-stream", "providers", "models", "openai"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stdout(&output);
    assert!(output.status.success(), "{}", stderr(&output));
    let mini = text
        .lines()
        .find(|line| line.starts_with("gpt-4o-mini"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(mini.contains("yes") && mini.contains("0.00015") && mini.contains("0.0006"), "{mini}");
    let full = text
        .lines()
        .find(|line| line.starts_with("gpt-4o "))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(full.contains("no"), "{full}");
}

#[cfg(feature = "agent-stream")]
#[test]
fn providers_delete_of_a_custom_provider_prints_deleted_and_its_id_as_json() {
    let (host, requests) = host_answering(AGENT_STREAM_PERMISSIONS, CATALOG);

    let output = fabric_in_fresh_home(
        &["agent-stream", "-o", "json", "providers", "delete", "acme"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    assert!(output.status.success(), "{}", stderr(&output));
    let answer: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("JSON answer");
    assert_eq!(answer, serde_json::json!({"deleted": "acme"}));
    assert_eq!(
        request_lines(&requests)
            .last()
            .map(String::as_str),
        Some("PUT /api/v1/llm-providers/custom HTTP/1.1")
    );
}

#[cfg(feature = "agent-stream")]
#[test]
fn providers_list_refused_by_agent_stream_prints_its_reason_and_exits_non_zero() {
    let probe = PROBE_REQUEST.trim_end_matches(" HTTP/1.1");
    let (host, requests) = host_replying(
        vec![(probe, "200 OK", AGENT_STREAM_PERMISSIONS)],
        ("403 Forbidden", "missing permission llm_catalog.edit"),
    );

    let output = fabric_in_fresh_home(
        &["agent-stream", "providers", "list"],
        &[],
        &[("FABRIC_HOST", &host), ("FABRIC_TOKEN", ACCESS_TOKEN), UNREACHABLE_DBUS],
        "",
    );

    let text = stderr(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("missing permission llm_catalog.edit"), "{text}");
    assert!(!text.contains(ACCESS_TOKEN), "{text}");
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert_eq!(request_lines(&requests), [PROBE_REQUEST, "GET /api/v1/llm-providers HTTP/1.1"]);
}
