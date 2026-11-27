//! `fabric agent-stream notifications`: the welcome notifications of an
//! Agent Stream, run through the notification commands Agent Gateway uses.

use clap::{Args, Subcommand};

use crate::commands::{self, JsonFileArgs, SendWelcomeArgs};

#[derive(Debug, Subcommand)]
pub enum NotificationCommand {
    /// Manage the welcome notification sent to newly approved users.
    #[command(name = "welcome-template")]
    WelcomeTemplate {
        #[command(subcommand)]
        command: WelcomeTemplateCommand,
    },
    /// Send a welcome notification to a user.
    ///
    /// Agent Stream accepts any recipient id, so the CLI looks the user up
    /// first and refuses an unknown id. A caller without the users.view
    /// permission cannot look another user up, and is warned that the
    /// recipient went unverified instead. Sending needs the
    /// notifications.edit permission.
    #[command(name = "send-welcome", after_long_help = SEND_WELCOME_EXAMPLES)]
    SendWelcome(SendWelcome),
}

#[derive(Debug, Subcommand)]
pub enum WelcomeTemplateCommand {
    /// Show the welcome notification template.
    ///
    /// Any signed-in user can read it; an access token with its own scope
    /// list needs notifications.view.
    Show,
    /// Replace the welcome notification template from a JSON document.
    ///
    /// The document carries "title" and "message". Agent Stream sends the
    /// template to each user approved from now on, except administrators.
    /// Needs the notifications.edit permission. Prints a confirmation line, or
    /// `null` with --output json.
    #[command(after_long_help = WELCOME_TEMPLATE_SET_EXAMPLES)]
    Set(JsonFileArgs),
}

#[derive(Debug, Args)]
pub struct SendWelcome {
    /// User ID of the recipient, as `fabric agent-stream users list` prints
    /// it.
    #[arg(long)]
    user_id: String,
    /// Heading shown in the recipient's notification feed.
    #[arg(long)]
    title: String,
    /// Body of the notification.
    #[arg(long)]
    message: String,
}

/// Examples shown at the bottom of `notifications send-welcome --help`.
const SEND_WELCOME_EXAMPLES: &str = r#"Examples:
  Send a welcome notification:
    fabric agent-stream notifications send-welcome --user-id <user-id> \
      --title "Welcome" --message "Your account is ready"

The recipient lookup is an ordinary user read: it fires any integration bound
to the user.accessed event. Prints a confirmation line, or null with --output
json."#;

/// Examples shown at the bottom of `notifications welcome-template set --help`.
const WELCOME_TEMPLATE_SET_EXAMPLES: &str = r#"Examples:
  Replace the template, starting from the current one:
    fabric agent-stream notifications welcome-template show --output json > \
      template.json
    fabric agent-stream notifications welcome-template set --file template.json

  Replace it from standard input:
    echo '{"title": "Welcome", "message": "Your account is ready"}' | fabric \
      agent-stream notifications welcome-template set --file -"#;

impl From<NotificationCommand> for commands::NotificationCommand {
    fn from(command: NotificationCommand) -> Self {
        match command {
            NotificationCommand::WelcomeTemplate { command } => Self::WelcomeTemplate {
                command: match command {
                    WelcomeTemplateCommand::Show => commands::WelcomeTemplateCommand::Show,
                    WelcomeTemplateCommand::Set(args) => commands::WelcomeTemplateCommand::Set(args),
                },
            },
            NotificationCommand::SendWelcome(SendWelcome { user_id, title, message }) => {
                Self::SendWelcome(SendWelcomeArgs { user_id, title, message })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{json_file, request_body, scripted_agent_stream, start_lines},
        client::GatewayClient,
        commands::{Output, SharedCommand, run_shared},
    };

    const TOKEN: &str = "aspat_test";

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn send_welcome_to(user_id: &str) -> NotificationCommand {
        NotificationCommand::SendWelcome(SendWelcome {
            user_id: user_id.to_owned(),
            title: "Welcome".to_owned(),
            message: "Hello".to_owned(),
        })
    }

    #[tokio::test]
    async fn each_command_reaches_its_notification_route() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/notifications/user-welcome-template", "HTTP/1.1 200 OK", r#"{"title":"Hi","message":"x"}"#),
            ("PUT /api/v1/notifications/user-welcome-template", "HTTP/1.1 204 No Content", ""),
            ("GET /api/v1/users/u-1", "HTTP/1.1 200 OK", r#"{"user_id":"u-1","username":"ada"}"#),
            ("POST /api/v1/notifications/send-welcome", "HTTP/1.1 204 No Content", ""),
        ])
        .await;
        let client = client(host);
        let template = json_file(r#"{"title":"Welcome","message":"Your account is ready"}"#);

        for command in [
            NotificationCommand::WelcomeTemplate {
                command: WelcomeTemplateCommand::Show,
            },
            NotificationCommand::WelcomeTemplate {
                command: WelcomeTemplateCommand::Set(JsonFileArgs {
                    file: template.path().to_path_buf(),
                }),
            },
            send_welcome_to("u-1"),
        ] {
            run_shared(&client, SharedCommand::Notifications(command.into()), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/notifications/user-welcome-template HTTP/1.1",
                "PUT /api/v1/notifications/user-welcome-template HTTP/1.1",
                "GET /api/v1/users/u-1 HTTP/1.1",
                "POST /api/v1/notifications/send-welcome HTTP/1.1",
            ]
        );
        let sent: serde_json::Value = serde_json::from_str(request_body(&requests.lock().unwrap()[3])).expect("JSON");
        assert_eq!(sent, serde_json::json!({"user_id": "u-1", "title": "Welcome", "message": "Hello"}));
    }

    /// Agent Stream's Terms gate refusing an access token, which carries a
    /// message, and a session token, which carries the code alone.
    const TERMS_REFUSALS: [(&str, &str); 2] = [
        (
            TOKEN,
            r#"{"code":"TERMS_ACCEPTANCE_REQUIRED","message":"Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then retry."}"#,
        ),
        ("session-token", r#"{"code":"TERMS_ACCEPTANCE_REQUIRED"}"#),
    ];

    #[tokio::test]
    async fn send_welcome_sends_nothing_once_the_terms_gate_refuses_the_recipient_lookup() {
        for (token, body) in TERMS_REFUSALS {
            let (host, requests) = scripted_agent_stream(vec![
                ("GET /api/v1/users/u-1", "HTTP/1.1 403 Forbidden", body),
                ("POST /api/v1/notifications/send-welcome", "HTTP/1.1 204 No Content", ""),
            ])
            .await;
            let client = GatewayClient::for_agent_stream(host, token).expect("client");

            run_shared(&client, SharedCommand::Notifications(send_welcome_to("u-1").into()), Output::Table)
                .await
                .expect_err("the Terms gate refuses the send too");

            assert_eq!(start_lines(&requests), ["GET /api/v1/users/u-1 HTTP/1.1"], "{token}");
        }
    }

    #[tokio::test]
    async fn send_welcome_still_sends_when_the_lookup_is_refused_for_a_missing_permission() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/users/u-1", "HTTP/1.1 403 Forbidden", r#"{"required_permission":"users.view"}"#),
            ("POST /api/v1/notifications/send-welcome", "HTTP/1.1 204 No Content", ""),
        ])
        .await;

        run_shared(&client(host), SharedCommand::Notifications(send_welcome_to("u-1").into()), Output::Table)
            .await
            .expect("sending needs no users.view");

        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/users/u-1 HTTP/1.1", "POST /api/v1/notifications/send-welcome HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn send_welcome_refuses_a_user_agent_stream_does_not_know_and_names_the_agent_stream_command() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/users/nobody", "HTTP/1.1 404 Not Found", "User not found")]).await;

        let error =
            run_shared(&client(host), SharedCommand::Notifications(send_welcome_to("nobody").into()), Output::Table)
                .await
                .expect_err("a notification for no user is not sent");

        assert_eq!(
            error.to_string(),
            "user 'nobody' not found: no Agent Stream user has that id, so the notification would reach nobody. \
             Nothing was sent; `fabric agent-stream users list` lists user ids"
        );
        assert_eq!(start_lines(&requests), ["GET /api/v1/users/nobody HTTP/1.1"]);
    }
}
