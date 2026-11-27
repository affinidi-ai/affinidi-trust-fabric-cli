//! `fabric agent-stream certificates`: the TLS certificates of an Agent
//! Stream, run through the certificate commands Agent Gateway uses. Agent
//! Stream never returns a private key, so there is no --reveal.

use std::path::PathBuf;

use clap::Subcommand;

use crate::commands::{CrudCommand, JsonFileArgs, SharedCommand};

#[derive(Debug, Subcommand)]
pub enum CertificateCommand {
    /// List certificates.
    ///
    /// Needs the certificates.view permission.
    List,
    /// Get a certificate by its id or name.
    ///
    /// The answer never carries `private_key_pem`: Agent Stream does not
    /// return a stored private key. Needs the certificates.view permission.
    Get {
        /// The certificate's id or name. A name shared by several
        /// certificates is refused; pass the id instead.
        #[arg(value_name = "CERTIFICATE")]
        certificate: String,
    },
    /// Create a certificate from a JSON document.
    ///
    /// The document carries `name` and `certificate_pem`, and optionally
    /// `description`, `tags`, `kind` (`server_leaf`, the default,
    /// `client_leaf` or `ca`), `private_key_pem`, `expires_at`, `active`,
    /// `identity_did`, and `tenant_id`. The private key is write-only: Agent
    /// Stream stores it and never returns it. From a session login,
    /// `tenant_id` names the tenant that owns the new certificate. An access
    /// token limited to a tenant always uses its own tenant and refuses
    /// another, and an appliance-wide access token refuses `tenant_id`. Needs
    /// the certificates.edit permission.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(JsonFileArgs),
    /// Update a certificate from a JSON document.
    ///
    /// Agent Stream changes only the fields the document sets and keeps the
    /// rest. `private_key_pem` is write-only: leave it out to keep the stored
    /// key, or send a new one to replace it. The tenant does not change here;
    /// `fabric agent-stream tenant-ownership set certificates <ID> --tenant
    /// <TENANT>` changes it. Needs the certificates.edit permission, and the
    /// certificates.view permission to look a name up; without it, pass the
    /// certificate's id, a UUID.
    Update {
        /// The certificate's id or name. A name shared by several
        /// certificates is refused; pass the id instead.
        #[arg(value_name = "CERTIFICATE")]
        certificate: String,
        /// JSON document carrying the fields to change. Use '-' to read from
        /// standard input.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete a certificate by its id or name.
    ///
    /// The command asks for confirmation first unless you pass --yes, and
    /// Agent Stream does not check whether anything still uses the
    /// certificate. Needs the certificates.edit permission, and the
    /// certificates.view permission to look a name up; without it, pass the
    /// certificate's id, a UUID.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// The certificate's id or name. A name shared by several
        /// certificates is refused; pass the id instead.
        #[arg(value_name = "CERTIFICATE")]
        certificate: String,
        /// Skip the confirmation prompt. Required when running non-interactively.
        #[arg(short, long)]
        yes: bool,
    },
}

/// Examples shown at the bottom of `certificates create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Add a server certificate and its key, kept in a file so the key stays out of
  shell history:
    fabric agent-stream certificates create --file certificate.json
  where certificate.json is:
    {
      "name": "Edge",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
      "private_key_pem": "-----BEGIN PRIVATE KEY-----\n..."
    }"#;

/// Examples shown at the bottom of `certificates delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Delete a certificate after the prompt:
    fabric agent-stream certificates delete Edge

  Delete it from a script, with no prompt:
    fabric agent-stream certificates delete Edge --yes"#;

impl CertificateCommand {
    /// Whether this is a delete that asks for confirmation first, because
    /// --yes was not given.
    fn asks_before_deleting(&self) -> bool {
        matches!(self, Self::Delete { yes: false, .. })
    }
}

impl SharedCommand {
    /// The shared form of an Agent Stream certificate command, which
    /// remembers whether a delete asks for confirmation first.
    pub(crate) fn certificates(command: CertificateCommand) -> Self {
        Self::Certificates {
            ask_first: command.asks_before_deleting(),
            command: command.into(),
        }
    }
}

impl From<CertificateCommand> for CrudCommand {
    fn from(command: CertificateCommand) -> Self {
        match command {
            CertificateCommand::List => Self::List,
            CertificateCommand::Get { certificate } => Self::Get { id: certificate },
            CertificateCommand::Create(args) => Self::Create(args),
            CertificateCommand::Update { certificate, file } => Self::Update { id: certificate, file },
            CertificateCommand::Delete { certificate, .. } => Self::Delete { id: certificate },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_stream::test_support::{
            ScriptedPrompter, json_file, run_stream, saved_login, scripted_agent_stream, start_lines,
        },
        client::GatewayClient,
        commands::{Output, run_shared, run_shared_with},
    };

    const TOKEN: &str = "aspat_test";

    /// What Agent Stream lists: no certificate carries a private key.
    const LISTED: &str =
        r#"[{"id":"cert-1","name":"Edge","certificate_id":"c-1","tags":[],"kind":"server_leaf","active":true}]"#;

    /// Two certificates that share one name.
    const SAME_NAME: &str = r#"[{"id":"cert-1","name":"Dup"},{"id":"cert-2","name":"Dup"}]"#;

    /// What Agent Stream answers a read or a write of one certificate with.
    const CERTIFICATE: &str = r#"{"id":"cert-1","name":"Edge","certificate_pem":"-----BEGIN CERTIFICATE-----","kind":"server_leaf","active":true}"#;

    fn client(host: String) -> GatewayClient {
        GatewayClient::for_agent_stream(host, TOKEN).expect("client")
    }

    #[tokio::test]
    async fn each_command_reaches_its_certificate_route_and_a_name_is_looked_up() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/certificates/cert-1", "HTTP/1.1 200 OK", CERTIFICATE),
            ("PUT /api/v1/certificates/cert-1", "HTTP/1.1 200 OK", CERTIFICATE),
            ("DELETE /api/v1/certificates/cert-1", "HTTP/1.1 204 No Content", ""),
            ("POST /api/v1/certificates", "HTTP/1.1 201 Created", CERTIFICATE),
            ("GET /api/v1/certificates", "HTTP/1.1 200 OK", LISTED),
        ])
        .await;
        let client = client(host);
        let document = json_file(r#"{"name":"Edge","certificate_pem":"-----BEGIN CERTIFICATE-----"}"#);
        let file = || document.path().to_path_buf();

        for command in [
            CertificateCommand::List,
            CertificateCommand::Get { certificate: "Edge".to_owned() },
            CertificateCommand::Create(JsonFileArgs { file: file() }),
            CertificateCommand::Update {
                certificate: "cert-1".to_owned(),
                file: file(),
            },
            CertificateCommand::Delete {
                certificate: "cert-1".to_owned(),
                yes: true,
            },
        ] {
            run_shared(&client, SharedCommand::certificates(command), Output::Json)
                .await
                .expect("the command succeeds");
        }

        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/certificates HTTP/1.1",
                "GET /api/v1/certificates HTTP/1.1",
                "GET /api/v1/certificates/cert-1 HTTP/1.1",
                "POST /api/v1/certificates HTTP/1.1",
                "GET /api/v1/certificates HTTP/1.1",
                "PUT /api/v1/certificates/cert-1 HTTP/1.1",
                "GET /api/v1/certificates HTTP/1.1",
                "DELETE /api/v1/certificates/cert-1 HTTP/1.1",
            ]
        );
    }

    fn delete(yes: bool) -> SharedCommand {
        SharedCommand::certificates(CertificateCommand::Delete {
            certificate: "cert-1".to_owned(),
            yes,
        })
    }

    #[tokio::test]
    async fn a_declined_delete_names_the_certificate_and_host_and_sends_no_delete() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/certificates/cert-1", "HTTP/1.1 200 OK", CERTIFICATE),
            ("GET /api/v1/certificates", "HTTP/1.1 200 OK", LISTED),
        ])
        .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host.clone()), delete(false), Output::Table, &mut prompter)
            .await
            .expect("a declined delete is not an error");

        assert_eq!(prompter.questions, [format!("Delete certificate 'Edge' (cert-1) on {host}?")]);
        assert_eq!(prompter.aborted, ["Aborted. Certificate 'cert-1' was not deleted."]);
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/certificates HTTP/1.1", "GET /api/v1/certificates/cert-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn a_delete_by_name_asks_about_the_name_and_its_id_and_deletes_that_id() {
        let (host, requests) = scripted_agent_stream(vec![
            ("GET /api/v1/certificates/cert-1", "HTTP/1.1 200 OK", CERTIFICATE),
            ("DELETE /api/v1/certificates/cert-1", "HTTP/1.1 204 No Content", ""),
            ("GET /api/v1/certificates", "HTTP/1.1 200 OK", LISTED),
        ])
        .await;
        let mut prompter = ScriptedPrompter::answering(true);
        let by_name = SharedCommand::certificates(CertificateCommand::Delete {
            certificate: "Edge".to_owned(),
            yes: false,
        });

        run_shared_with(&client(host.clone()), by_name, Output::Table, &mut prompter)
            .await
            .expect("the delete is confirmed");

        assert_eq!(prompter.questions, [format!("Delete certificate 'Edge' (cert-1) on {host}?")]);
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/certificates HTTP/1.1",
                "GET /api/v1/certificates/cert-1 HTTP/1.1",
                "DELETE /api/v1/certificates/cert-1 HTTP/1.1",
            ]
        );
    }

    #[tokio::test]
    async fn an_ambiguous_name_is_refused_before_anything_is_asked_or_deleted() {
        let (host, requests) =
            scripted_agent_stream(vec![("GET /api/v1/certificates", "HTTP/1.1 200 OK", SAME_NAME)]).await;
        let mut prompter = ScriptedPrompter::answering(true);
        let by_name = SharedCommand::certificates(CertificateCommand::Delete {
            certificate: "Dup".to_owned(),
            yes: false,
        });

        let error = run_shared_with(&client(host), by_name, Output::Table, &mut prompter)
            .await
            .expect_err("two certificates carry the name");

        let printed = format!("{error:#}");
        assert!(printed.contains("cert-1") && printed.contains("cert-2"), "{printed}");
        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(start_lines(&requests), ["GET /api/v1/certificates HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_delete_with_yes_sends_the_delete_without_asking() {
        let (host, requests) = scripted_agent_stream(vec![
            ("DELETE /api/v1/certificates/cert-1", "HTTP/1.1 204 No Content", ""),
            ("GET /api/v1/certificates", "HTTP/1.1 200 OK", LISTED),
        ])
        .await;
        let mut prompter = ScriptedPrompter::answering(false);

        run_shared_with(&client(host), delete(true), Output::Table, &mut prompter)
            .await
            .expect("delete");

        assert!(prompter.questions.is_empty(), "{:?}", prompter.questions);
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/certificates HTTP/1.1", "DELETE /api/v1/certificates/cert-1 HTTP/1.1"]
        );
    }

    #[tokio::test]
    async fn a_terms_gate_failure_on_a_certificate_route_gets_the_terms_hint() {
        let body = r#"{"code":"TERMS_OPERATIONAL_FAILURE"}"#;
        let (host, _) =
            scripted_agent_stream(vec![("GET /api/v1/certificates", "HTTP/1.1 503 Service Unavailable", body)]).await;
        let (saved, credentials) = saved_login(&host, TOKEN);

        let error = run_stream(&["certificates", "list"], saved, &credentials)
            .await
            .expect_err("the Terms gate refuses the list");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "the upstream terms provider is unavailable; check `fabric agent-stream terms provider-health`: {body}"
            )
        );
    }
}
