//! `fabric agent-stream terms`: the Terms of Use of an Agent Stream, run
//! through the terms commands Agent Gateway uses.

use clap::Subcommand;

use crate::commands::{self, JsonFileArgs};

#[derive(Debug, Subcommand)]
pub enum TermsCommand {
    /// Show the Terms of Use definitions.
    ///
    /// Needs the terms.view permission.
    Show,
    /// Show the terms that apply to this Agent Stream.
    ///
    /// Agent Stream answers this even before the terms are accepted.
    Applicable,
    /// Show whether the signed-in user has accepted the current terms.
    Status,
    /// Show the health of the upstream terms provider.
    ///
    /// Agent Stream answers this even before the terms are accepted.
    #[command(name = "provider-health")]
    ProviderHealth,
    /// Save the customer Terms of Use draft from a JSON document.
    ///
    /// The document carries `version`, `title` and `url` (an absolute https
    /// URL), plus an optional `requires_reconsent` that defaults to false.
    /// Saving replaces any earlier draft. Nothing applies to users until
    /// `fabric agent-stream terms publish`. Needs the terms.edit permission.
    #[command(after_long_help = DRAFT_EXAMPLES)]
    Draft(JsonFileArgs),
    /// Publish the saved customer Terms of Use draft as a new version.
    ///
    /// Runs without a prompt. The published version becomes the current
    /// customer Terms of Use, the draft is used up, and the new version is
    /// printed. Refused when no draft is saved (TERMS_DRAFT_REQUIRED), and
    /// when a version with the same `version` was already published. Needs the
    /// terms.edit permission.
    Publish,
    /// Deactivate the published customer Terms of Use.
    ///
    /// Runs without a prompt. The customer Terms of Use stop applying, and
    /// the versions published so far are kept. To apply customer terms again,
    /// save and publish a draft with a new `version`. Prints a confirmation
    /// line, or `null` with --output json. Needs the terms.edit permission.
    Deactivate,
}

/// Examples shown at the bottom of `terms draft --help`.
const DRAFT_EXAMPLES: &str = r#"Examples:
  Save a draft from terms.json, then publish it:
    fabric agent-stream terms draft --file terms.json
    fabric agent-stream terms publish
  where terms.json is:
    {
      "version": "2.0",
      "title": "Acme Terms of Use",
      "url": "https://example.com/terms-2.0",
      "requires_reconsent": true
    }"#;

impl From<TermsCommand> for commands::TermsCommand {
    fn from(command: TermsCommand) -> Self {
        match command {
            TermsCommand::Show => Self::Show,
            TermsCommand::Applicable => Self::Applicable,
            TermsCommand::Status => Self::Status,
            TermsCommand::ProviderHealth => Self::ProviderHealth,
            TermsCommand::Draft(args) => Self::Draft(args),
            TermsCommand::Publish => Self::Publish,
            TermsCommand::Deactivate => Self::Deactivate,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{json_file, run_stream, saved_login, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_terms_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/terms/applicable", "HTTP/1.1 200 OK", "{}"),
            ("GET /api/v1/terms/status", "HTTP/1.1 200 OK", r#"{"consent_required":false}"#),
            ("GET /api/v1/terms/provider-health", "HTTP/1.1 200 OK", "{}"),
            ("PUT /api/v1/terms/customer/draft", "HTTP/1.1 200 OK", "{}"),
            ("POST /api/v1/terms/customer/publish", "HTTP/1.1 201 Created", r#"{"version":"2.0"}"#),
            ("POST /api/v1/terms/customer/deactivate", "HTTP/1.1 204 No Content", ""),
            ("GET /api/v1/terms", "HTTP/1.1 200 OK", "{}"),
        ])
        .await;
        let client = client(host);
        let draft = json_file(r#"{"version":"2.0","title":"Acme","url":"https://example.com/terms"}"#);

        for command in [
            TermsCommand::Show,
            TermsCommand::Applicable,
            TermsCommand::Status,
            TermsCommand::ProviderHealth,
            TermsCommand::Draft(JsonFileArgs {
                file: draft.path().to_path_buf(),
            }),
            TermsCommand::Publish,
            TermsCommand::Deactivate,
        ] {
            run_shared(&client, SharedCommand::Terms(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/terms HTTP/1.1",
                "GET /api/v1/terms/applicable HTTP/1.1",
                "GET /api/v1/terms/status HTTP/1.1",
                "GET /api/v1/terms/provider-health HTTP/1.1",
                "PUT /api/v1/terms/customer/draft HTTP/1.1",
                "POST /api/v1/terms/customer/publish HTTP/1.1",
                "POST /api/v1/terms/customer/deactivate HTTP/1.1",
            ]
        );
    }
    #[tokio::test]
    async fn a_terms_code_agent_stream_sends_alone_comes_with_what_it_means() {
        for (status, body, hint) in [
            (
                "HTTP/1.1 409 Conflict",
                r#"{"code":"TERMS_DRAFT_REQUIRED"}"#,
                "there is no saved draft to publish; save one with `fabric agent-stream terms draft --file <json>` \
                 first",
            ),
            (
                "HTTP/1.1 404 Not Found",
                r#"{"code":"TERMS_DISABLED"}"#,
                "this 404 means the Terms of Use feature is switched off on this Agent Stream, not that the route is \
                 missing",
            ),
            (
                "HTTP/1.1 409 Conflict",
                r#"{"code":"TERMS_VERSION_STALE"}"#,
                "the published terms changed while this request was in flight; re-read `fabric agent-stream terms \
                 show` and retry",
            ),
            (
                "HTTP/1.1 503 Service Unavailable",
                r#"{"code":"TERMS_OPERATIONAL_FAILURE"}"#,
                "the upstream terms provider is unavailable; check `fabric agent-stream terms provider-health`",
            ),
        ] {
            let (host, _) = scripted_agent_stream(vec![("POST /api/v1/terms/customer/publish", status, body)]).await;
            let (saved, credentials) = saved_login(&host, TOKEN);

            let error = run_stream(&["terms", "publish"], saved, &credentials)
                .await
                .expect_err("Agent Stream refuses the publish");

            assert_eq!(format!("{error:#}"), format!("{hint}: {body}"));
        }
    }

    #[tokio::test]
    async fn a_terms_error_with_its_own_message_gets_no_hint() {
        let (host, _) = scripted_agent_stream(vec![(
            "POST /api/v1/terms/customer/publish",
            "HTTP/1.1 400 Bad Request",
            r#"{"code":"TERMS_INVALID","message":"Customer Terms version has already been published"}"#,
        )])
        .await;
        let (saved, credentials) = saved_login(&host, TOKEN);

        let error = run_stream(&["terms", "publish"], saved, &credentials)
            .await
            .expect_err("Agent Stream refuses the publish");

        assert_eq!(format!("{error:#}"), "Customer Terms version has already been published");
    }
}
