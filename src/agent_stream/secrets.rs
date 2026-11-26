//! `fabric agent-stream secrets`: the secrets of an Agent Stream, run through
//! the secret commands Agent Gateway uses.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{
    client::GatewayClient,
    commands::{self, Output, SecretCreateArgs, SharedCommand, run_shared},
};

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    /// List secrets. List answers never carry secret values.
    List {
        /// Only list secrets carrying this tag.
        #[arg(long)]
        tag: Option<String>,
    },
    /// Get a secret by its id, secret_id or name.
    ///
    /// The value is masked unless --reveal is given. Agent Stream sends the
    /// value only while `secrets.reveal_values` is on in its agent-stream.json
    /// configuration file, which it is by default. While it is off, --reveal
    /// prints the record without a value and says why on standard error.
    Get {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
    },
    /// Create a secret using flags or a complete JSON document.
    ///
    /// With no --file, give --name, --secret-id and a value through --value
    /// or --value-stdin. Prefer --value-stdin: a value typed after --value
    /// stays in shell history and shows in the process list.
    ///
    /// The secret_id must be unique and cannot be changed later. Other
    /// configuration refers to the secret as $SECRET:<secret-id>. Agent Stream
    /// answers with the stored value, which is masked unless --reveal is given.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Update a secret from a JSON document.
    ///
    /// Fields the document leaves out keep their stored values, except
    /// description, which is always replaced: leave it out and the stored
    /// description is cleared, so restate it. The secret_id cannot be changed;
    /// Agent Stream ignores it in the document.
    ///
    /// To change the value, set "update_value": true beside "value". Agent
    /// Stream ignores "value" without it and still reports success, so the CLI
    /// refuses a document that has "value" but no "update_value" key. The
    /// answer carries the stored value, which is masked unless --reveal is
    /// given.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
        /// JSON document with the fields to change: name, description,
        /// secret_type, tags, and value with update_value. Use '-' to read from
        /// standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a secret by its id, secret_id or name.
    ///
    /// The secret is deleted immediately: there is no confirmation prompt and
    /// no --yes flag, and Agent Stream does not check whether anything still
    /// refers to it. Check which secret a secret_id or name matches with
    /// `fabric agent-stream secrets get` first.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// The secret's id, secret_id or name. A secret_id or name matching more
        /// than one secret is refused; pass the id instead.
        secret: String,
    },
}

/// Examples shown at the bottom of `secrets create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Read the value from a file, keeping it out of shell history:
    fabric agent-stream secrets create --name "Stripe live" \
      --secret-id stripe-live --value-stdin < key.txt

  Pipe the value in from an environment variable, with a description, type and
  tags:
    printf '%s' "$STRIPE_KEY" | fabric agent-stream secrets create \
      --name "Stripe live" --secret-id stripe-live --value-stdin \
      --description "Billing API key" --type ApiKey --tag billing --tag stripe

  Create from a complete JSON document:
    fabric agent-stream secrets create --file secret.json"#;

/// Examples shown at the bottom of `secrets update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Replace the value, restating the description so it is kept:
    printf \
      '{"value":"%s","update_value":true,"description":"Billing API key"}' \
      "$NEW_KEY" | fabric agent-stream secrets update stripe-live --file -

  Change the tags and keep the value, restating the description:
    echo '{"tags":["billing","prod"],"description":"Billing API key"}' | \
      fabric agent-stream secrets update stripe-live --file -"#;

/// Examples shown at the bottom of `secrets delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Check which secret a name matches, then delete it:
    fabric agent-stream secrets get "Stripe live"
    fabric agent-stream secrets delete "Stripe live""#;

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Human-readable name.
    #[arg(long, required_unless_present = "file")]
    name: Option<String>,
    /// Machine-readable identifier used by $SECRET:<secret-id> references.
    #[arg(long, required_unless_present = "file")]
    secret_id: Option<String>,
    /// Secret value, stored exactly as given including any whitespace. It
    /// stays in shell history; prefer --value-stdin.
    #[arg(long, conflicts_with = "value_stdin")]
    value: Option<String>,
    /// Read the secret value from standard input. One trailing line ending
    /// is removed; use --file when a final newline matters, as in a PEM block.
    #[arg(long)]
    value_stdin: bool,
    /// What the secret is for.
    #[arg(long)]
    description: Option<String>,
    /// Secret type, any text, such as ApiKey. Agent Stream stores it as given;
    /// omit it for the default, General.
    #[arg(long = "type")]
    secret_type: Option<String>,
    /// Tag to attach. Repeat for multiple tags.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Complete JSON document with name, secret_id, value, description,
    /// secret_type and tags. Use '-' to read from standard input. Other
    /// creation flags are ignored when set.
    #[arg(short, long)]
    file: Option<PathBuf>,
}

/// Runs one `secrets` command on the Agent Stream behind `client`. Values
/// are masked unless `reveal` is set.
pub async fn run(
    client: &GatewayClient,
    command: SecretCommand,
    reveal: bool,
    output: Output,
) -> Result<()> {
    let command = SharedCommand::Secrets {
        command: command.into(),
        reveal,
    };
    run_shared(client, command, output).await
}

impl From<SecretCommand> for commands::SecretCommand {
    fn from(command: SecretCommand) -> Self {
        match command {
            SecretCommand::List { tag } => Self::List { tag },
            SecretCommand::Get { secret } => Self::Get { secret },
            SecretCommand::Create(args) => Self::Create(SecretCreateArgs {
                name: args.name,
                secret_id: args.secret_id,
                value: args.value,
                value_stdin: args.value_stdin,
                description: args.description,
                secret_type: args.secret_type,
                tags: args.tags,
                file: args.file,
            }),
            SecretCommand::Update { secret, file } => Self::Update { secret, file },
            SecretCommand::Delete { secret } => Self::Delete { secret },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_stream::test_support::{Route, scripted_agent_stream, start_lines};

    const TOKEN: &str = "aspat_test";
    const SECRET_LIST: Route =
        ("GET /api/v1/secrets", "HTTP/1.1 200 OK", r#"[{"id":"s-1","secret_id":"stripe-live","name":"Stripe live"}]"#);

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    fn json_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(file.path(), contents).expect("write the document");
        file
    }

    #[tokio::test]
    async fn each_command_reaches_its_secret_route_after_looking_the_name_up() {
        let stored = r#"{"id":"s-1","secret_id":"stripe-live","name":"Stripe live","value":"sk_live"}"#;
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/secrets/tag/billing", "HTTP/1.1 200 OK", "[]"),
            ("GET /api/v1/secrets/s-1", "HTTP/1.1 200 OK", stored),
            ("POST /api/v1/secrets/new", "HTTP/1.1 201 Created", stored),
            ("PUT /api/v1/secrets/s-1", "HTTP/1.1 200 OK", stored),
            ("DELETE /api/v1/secrets/s-1", "HTTP/1.1 204 No Content", ""),
            SECRET_LIST,
        ])
        .await;
        let client = client(host);
        let update = json_file(r#"{"description":"Billing"}"#);

        for command in [
            SecretCommand::List {
                tag: Some("billing".to_owned()),
            },
            SecretCommand::Get {
                secret: "stripe-live".to_owned(),
            },
            SecretCommand::Create(CreateArgs {
                name: Some("Stripe live".to_owned()),
                secret_id: Some("stripe-live".to_owned()),
                value: Some("sk_live".to_owned()),
                value_stdin: false,
                description: None,
                secret_type: None,
                tags: Vec::new(),
                file: None,
            }),
            SecretCommand::Update {
                secret: "Stripe live".to_owned(),
                file: update.path().to_path_buf(),
            },
            SecretCommand::Delete { secret: "s-1".to_owned() },
        ] {
            run(&client, command, false, Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/secrets/tag/billing HTTP/1.1",
                "GET /api/v1/secrets HTTP/1.1",
                "GET /api/v1/secrets/s-1 HTTP/1.1",
                "POST /api/v1/secrets/new HTTP/1.1",
                "GET /api/v1/secrets HTTP/1.1",
                "PUT /api/v1/secrets/s-1 HTTP/1.1",
                "GET /api/v1/secrets HTTP/1.1",
                "DELETE /api/v1/secrets/s-1 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn an_unknown_secret_names_the_agent_stream_list_command() {
        let (host, _) = scripted_agent_stream(vec![SECRET_LIST]).await;

        let error = run(&client(host), SecretCommand::Get { secret: "missing".to_owned() }, false, Output::Table)
            .await
            .expect_err("no secret has that reference");

        assert_eq!(
            error.to_string(),
            "secret not found: no secret has the ID, secret_id or name 'missing'; run `fabric agent-stream secrets \
             list` to see them"
        );
    }

    #[tokio::test]
    async fn a_secret_list_that_is_not_a_list_names_agent_stream() {
        let (host, _) = scripted_agent_stream(vec![("GET /api/v1/secrets", "HTTP/1.1 200 OK", "{}")]).await;

        let error = run(&client(host), SecretCommand::Get { secret: "stripe".to_owned() }, false, Output::Table)
            .await
            .expect_err("the list is not an array");

        assert_eq!(error.to_string(), "Agent Stream's secret list is not a JSON array");
    }

    #[tokio::test]
    async fn an_update_setting_value_without_update_value_names_agent_stream_and_sends_nothing() {
        let (host, requests) = scripted_agent_stream(vec![SECRET_LIST]).await;
        let update = json_file(r#"{"value":"sk_new"}"#);

        let error = run(
            &client(host),
            SecretCommand::Update {
                secret: "s-1".to_owned(),
                file: update.path().to_path_buf(),
            },
            false,
            Output::Table,
        )
        .await
        .expect_err("Agent Stream would keep the stored value");

        assert_eq!(
            error.to_string(),
            r#"the document sets "value" without "update_value": true, and Agent Stream would keep the stored secret; add "update_value": true to replace it, or drop "value" to leave it alone"#
        );
        assert!(start_lines(&requests).is_empty());
    }

    #[test]
    fn create_keeps_every_flag_it_was_given() {
        let command = commands::SecretCommand::from(SecretCommand::Create(CreateArgs {
            name: Some("Stripe live".to_owned()),
            secret_id: Some("stripe-live".to_owned()),
            value: None,
            value_stdin: true,
            description: Some("Billing".to_owned()),
            secret_type: Some("ApiKey".to_owned()),
            tags: vec!["billing".to_owned()],
            file: None,
        }));

        let commands::SecretCommand::Create(args) = command else {
            panic!("create stays create");
        };
        assert_eq!(args.name.as_deref(), Some("Stripe live"));
        assert_eq!(args.secret_id.as_deref(), Some("stripe-live"));
        assert!(args.value_stdin);
        assert_eq!(args.description.as_deref(), Some("Billing"));
        assert_eq!(args.secret_type.as_deref(), Some("ApiKey"));
        assert_eq!(args.tags, ["billing"]);
    }
}
