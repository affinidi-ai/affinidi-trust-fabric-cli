//! `fabric agent-stream whoami`: the current login and the connected Agent
//! Stream.

use anyhow::Result;
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};

use super::{
    Globals,
    login::{authenticated, profile},
};
use crate::{
    client::{GatewayClient, pretty_json_for_terminal, response_status, sanitize_for_terminal},
    commands::{CommandTarget, Output, command_target, whoami_table_lines},
    config::Config,
    credentials::CredentialStore,
    product::{self, Product},
};

/// The key of the Agent Stream's version in the `whoami` answer.
const VERSION_KEY: &str = "agent_stream_version";

/// The fields of the `whoami` table, in the order it shows them.
const TABLE_ORDER: &[&str] = &[
    "connection",
    "host",
    VERSION_KEY,
    "token_stored",
    "authenticated",
    "username",
    "role",
    "email",
    "user_id",
    "first_name",
    "last_name",
    "error",
];

/// The fields of the caller's profile that `whoami` shows.
const PROFILE_FIELDS: [&str; 6] = ["username", "role", "email", "user_id", "first_name", "last_name"];

/// Reports the connection a command would use, its host, the Agent Stream's
/// version, and the user behind the token, checked live. A warning about a
/// version that could not be read goes to standard error, so the JSON on
/// standard output stays clean.
pub async fn whoami(
    saved: &Config,
    credentials: &impl CredentialStore,
    globals: &Globals,
) -> Result<()> {
    let (info, version_warning) = whoami_info(saved, credentials, globals).await?;
    if let Some(warning) = version_warning {
        eprintln!("{warning}");
    }
    match globals.output {
        Output::Json => println!("{}", pretty_json_for_terminal(&info)?),
        Output::Table => {
            for line in whoami_table_lines(&info, TABLE_ORDER, VERSION_KEY) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

/// The JSON object `whoami` prints, and the warning for standard error when
/// the version could not be read for a reason worth reporting. The version is
/// asked for alongside the token check, with or without a token, and is `null`
/// when the Agent Stream does not give one. No token id or scopes are shown:
/// Agent Stream has no route that says which token is in use.
async fn whoami_info(
    saved: &Config,
    credentials: &impl CredentialStore,
    globals: &Globals,
) -> Result<(Value, Option<String>)> {
    let CommandTarget {
        connection,
        host,
        token,
        token_stored,
    } = command_target(
        saved,
        credentials,
        globals.connection.as_deref(),
        globals.host.as_deref(),
        globals.flags,
        globals.token.as_deref(),
    )?;
    product::check_product(Product::AgentStream, &host, token.as_deref(), globals.host.is_some()).await?;

    let mut info = json!({
        "connection": connection,
        "host": host,
        VERSION_KEY: null,
        "token_stored": token_stored,
        "authenticated": false,
    });
    let fields = info
        .as_object_mut()
        .expect("whoami info is a JSON object");
    let client = GatewayClient::for_agent_stream(
        &host,
        token
            .clone()
            .unwrap_or_default(),
    )?;
    let login = async {
        if let Some(token) = &token {
            insert_login_details(fields, &client, token).await;
        }
    };
    let (version, ()) = tokio::join!(client.gateway_version(), login);
    let version_warning = match version {
        Ok(version) => {
            fields.insert(VERSION_KEY.to_owned(), json!(version));
            None
        }
        Err(error) => version_warning(&error),
    };
    Ok((info, version_warning))
}

/// The standard error line for a failed version lookup, or `None` for a 404,
/// an Agent Stream without the route.
fn version_warning(error: &anyhow::Error) -> Option<String> {
    if response_status(error) == Some(StatusCode::NOT_FOUND) {
        return None;
    }
    Some(format!("warning: could not read the Agent Stream version: {}", sanitize_for_terminal(&format!("{error:#}"))))
}

/// Checks `token` live and adds `authenticated` and the signed-in user to
/// `fields`. An access token is accepted when it reads the caller's profile;
/// a session token when `/auth/check` calls it authenticated, and the profile
/// is then read for the user's details. A failed check is added as `error`.
async fn insert_login_details(
    fields: &mut Map<String, Value>,
    client: &GatewayClient,
    token: &str,
) {
    if product::token_product(token).is_some() {
        match profile(client).await {
            Ok(profile) => {
                fields.insert("authenticated".to_owned(), json!(true));
                insert_profile(fields, &profile);
            }
            Err(error) => {
                fields.insert("error".to_owned(), json!(error.to_string()));
            }
        }
        return;
    }
    match client
        .request(Method::GET, "/auth/check", None)
        .await
    {
        Ok(check) => {
            let signed_in = authenticated(&check);
            fields.insert("authenticated".to_owned(), json!(signed_in));
            if signed_in && let Ok(profile) = profile(client).await {
                insert_profile(fields, &profile);
            }
            if !fields.contains_key("username")
                && let Some(username) = check
                    .get("username")
                    .filter(|value| !value.is_null())
            {
                fields.insert("username".to_owned(), username.clone());
            }
        }
        Err(error) => {
            fields.insert("error".to_owned(), json!(error.to_string()));
        }
    }
}

/// Copies the [`PROFILE_FIELDS`] that `profile` has, other than `null`, into
/// `fields`.
fn insert_profile(
    fields: &mut Map<String, Value>,
    profile: &Value,
) {
    for key in PROFILE_FIELDS {
        if let Some(value) = profile
            .get(key)
            .filter(|value| !value.is_null())
        {
            fields.insert(key.to_owned(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{MemoryCredentials, Route, scripted_agent_stream, start_lines},
        commands::HostFlags,
        config::Connection,
    };

    const ACCESS_TOKEN: &str = "aspat_live-secret";
    const SESSION_TOKEN: &str = "session-live-secret";
    const VERSION: Route = ("GET /api/v1/version", "HTTP/1.1 200 OK", r#"{"version":"1.0.2"}"#);
    const PROFILE: Route = (
        "GET /api/v1/profile",
        "HTTP/1.1 200 OK",
        r#"{"username":"ada","role":"administrator","email":"ada@example.test","user_id":"u-1","status":"approved"}"#,
    );

    /// The `whoami` answer for the connection `default` at a scripted Agent
    /// Stream answering `routes`, with `token` saved for it, and the start
    /// lines of the requests it sent, in order.
    async fn whoami_with_saved(
        routes: Vec<Route>,
        token: &str,
    ) -> (Value, Vec<String>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let mut saved = Config {
            current: Some("default".to_owned()),
            ..Config::default()
        };
        saved
            .connections
            .insert("default".to_owned(), Connection::new(host.clone()));
        let credentials = MemoryCredentials::default();
        credentials
            .set_token("default", token)
            .unwrap();
        credentials
            .set_bound_host("default", &host)
            .unwrap();
        let globals = Globals {
            connection: None,
            host: None,
            token: None,
            flags: HostFlags::default(),
            output: Output::Json,
        };

        let (info, warning) = whoami_info(&saved, &credentials, &globals)
            .await
            .expect("whoami");

        assert_eq!(warning, None);
        let mut lines = start_lines(&requests);
        lines.sort();
        (info, lines)
    }

    #[tokio::test]
    async fn an_access_token_is_shown_with_its_user_and_the_agent_stream_version_but_no_token_details() {
        let (info, requests) = whoami_with_saved(vec![VERSION, PROFILE], ACCESS_TOKEN).await;

        assert_eq!(requests, ["GET /api/v1/profile HTTP/1.1", "GET /api/v1/version HTTP/1.1"]);
        assert_eq!(info["connection"], "default");
        assert_eq!(info[VERSION_KEY], "1.0.2");
        assert_eq!(info["token_stored"], true);
        assert_eq!(info["authenticated"], true);
        assert_eq!(info["username"], "ada");
        assert_eq!(info["role"], "administrator");
        for absent in ["token_id", "token_name", "scopes", "status", "error"] {
            assert!(info.get(absent).is_none(), "{absent}: {info}");
        }
        assert!(
            !info
                .to_string()
                .contains(ACCESS_TOKEN),
            "{info}"
        );
    }

    #[tokio::test]
    async fn a_session_is_checked_with_auth_check_and_then_reads_the_profile() {
        let signed_in = ("GET /api/auth/check", "HTTP/1.1 200 OK", r#"{"authenticated":true,"username":"ada"}"#);

        let (info, requests) = whoami_with_saved(vec![VERSION, signed_in, PROFILE], SESSION_TOKEN).await;

        assert_eq!(
            requests,
            ["GET /api/auth/check HTTP/1.1", "GET /api/v1/profile HTTP/1.1", "GET /api/v1/version HTTP/1.1"]
        );
        assert_eq!(info["authenticated"], true);
        assert_eq!(info["email"], "ada@example.test");
    }

    #[tokio::test]
    async fn a_session_that_has_ended_shows_authenticated_false_without_reading_the_profile() {
        let ended = ("GET /api/auth/check", "HTTP/1.1 200 OK", r#"{"authenticated":false,"username":null}"#);

        let (info, requests) = whoami_with_saved(vec![VERSION, ended, PROFILE], SESSION_TOKEN).await;

        assert_eq!(requests, ["GET /api/auth/check HTTP/1.1", "GET /api/v1/version HTTP/1.1"]);
        assert_eq!(info["authenticated"], false);
        assert!(info.get("username").is_none(), "{info}");
    }

    #[tokio::test]
    async fn a_refused_access_token_shows_the_error_and_authenticated_false() {
        let refused = ("GET /api/v1/profile", "HTTP/1.1 401 Unauthorized", "");

        let (info, _) = whoami_with_saved(vec![VERSION, refused], ACCESS_TOKEN).await;

        assert_eq!(info["authenticated"], false);
        let error = info["error"]
            .as_str()
            .expect("an error");
        assert!(error.contains("did not accept the access token"), "{error}");
    }

    #[tokio::test]
    async fn a_saved_connection_with_no_token_reads_only_the_version_and_shows_authenticated_false() {
        let (host, requests) = scripted_agent_stream(vec![VERSION, PROFILE]).await;
        let mut saved = Config {
            current: Some("default".to_owned()),
            ..Config::default()
        };
        saved
            .connections
            .insert("default".to_owned(), Connection::new(host.clone()));
        let globals = Globals {
            connection: None,
            host: None,
            token: None,
            flags: HostFlags::default(),
            output: Output::Json,
        };

        let (info, warning) = whoami_info(&saved, &MemoryCredentials::default(), &globals)
            .await
            .expect("whoami");

        assert_eq!(warning, None);
        assert_eq!(start_lines(&requests), ["GET /api/v1/version HTTP/1.1"]);
        assert_eq!(info["connection"], "default");
        assert_eq!(info[VERSION_KEY], "1.0.2");
        assert_eq!(info["token_stored"], false);
        assert_eq!(info["authenticated"], false);
        assert!(info.get("error").is_none(), "{info}");
    }

    #[test]
    fn the_table_shows_the_agent_stream_version_after_the_host_and_unknown_when_missing() {
        let info = json!({
            "connection": "default",
            "host": "https://stream.example",
            VERSION_KEY: null,
            "token_stored": true,
            "authenticated": true,
            "username": "ada",
        });

        assert_eq!(
            whoami_table_lines(&info, TABLE_ORDER, VERSION_KEY),
            [
                "connection: default",
                "host: https://stream.example",
                "agent_stream_version: unknown",
                "token_stored: true",
                "authenticated: true",
                "username: ada",
            ]
        );
    }

    #[test]
    fn a_version_route_that_is_missing_gives_no_warning_and_any_other_failure_names_agent_stream() {
        let missing = crate::client::gateway_error(StatusCode::NOT_FOUND, b"", &[]);
        assert_eq!(version_warning(&missing), None);

        let failed = anyhow::anyhow!("connection refused");
        assert_eq!(
            version_warning(&failed).as_deref(),
            Some("warning: could not read the Agent Stream version: connection refused")
        );
    }
}
