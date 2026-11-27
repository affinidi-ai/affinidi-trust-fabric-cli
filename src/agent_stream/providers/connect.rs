//! `fabric agent-stream providers connect`: point an LLM surface at a
//! provider of the Model catalog, one of its models, and the stored secret
//! that holds the provider's API key.
//!
//! A surface keeps its provider in `pipe_type.provider`, whose fields depend
//! on the provider: most take `model` and `api_key_secret`, and only some
//! keep a `base_url`. Agent Stream drops a field a provider doesn't take
//! without an error, so the CLI writes only the fields that provider takes,
//! and saves through the same path as `surfaces update`.

use anyhow::{Result, bail};
use clap::Args;
use reqwest::Url;
use serde_json::{Map, Value};

use super::{Catalog, enum_value};
use crate::{
    agent_stream::surfaces::change_surface,
    client::{GatewayClient, sanitize_for_terminal},
    commands::Output,
};

/// Longest secret id Agent Stream can look up.
const MAX_SECRET_ID_LEN: usize = 256;

/// The settings every provider of a surface takes, which `connect` keeps when
/// it switches the surface to another provider.
const SHARED_SETTINGS: [&str; 5] = ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"];

/// Providers Agent Stream knows by name whose surface settings keep a
/// `base_url`.
const KEEP_BASE_URL: [&str; 15] = [
    "openai",
    "groq",
    "xai",
    "openrouter",
    "fireworks",
    "cerebras",
    "deepseek",
    "moonshot",
    "sambanova",
    "hyperbolic",
    "nvidia",
    "nebius",
    "bedrock",
    "ollama",
    "m365_copilot",
];

/// Providers Agent Stream knows by name whose surface settings have no
/// `base_url`.
const NO_BASE_URL: [&str; 7] = ["anthropic", "gemini", "cohere", "mistral", "together_ai", "replicate", "huggingface"];

/// Providers a surface describes with other fields than a model and an API
/// key secret, each with what it needs instead.
const OTHER_SETTINGS: [(&str, &str); 2] = [
    ("azure", "`deployment_name`, `endpoint`, and `api_version`"),
    ("custom", "`name`, `endpoint`, and `auth_secret`"),
];

/// The start of API keys that providers hand out, which a secret id never
/// needs, to catch a key given in place of the id of the secret holding it.
const KEY_PREFIXES: [&str; 9] = ["sk-", "sk_", "gsk_", "xai-", "AIza", "hf_", "r8_", "nvapi-", "pplx-"];

/// The shortest --secret [`KEY_PREFIXES`] apply to. Provider keys are longer,
/// so a short secret id that happens to start the same way, such as
/// `sk-prod-openai`, is still accepted.
const KEY_MIN_LEN: usize = 32;

/// Examples shown at the bottom of `providers connect --help`.
pub(super) const CONNECT_EXAMPLES: &str = r#"Examples:
  Point a surface at an OpenAI model, after a dry run:
    fabric agent-stream providers connect openai --surface s-1a2b3c4d5e6f \
      --secret openai-key --model gpt-4o-mini --dry-run
    fabric agent-stream providers connect openai --surface s-1a2b3c4d5e6f \
      --secret openai-key --model gpt-4o-mini

  Give the surface another key, keeping its provider and model:
    fabric agent-stream providers connect openai --surface s-1a2b3c4d5e6f \
      --secret openai-key-2"#;

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Id of the provider, its `enum_value` (see `fabric agent-stream
    /// providers list`).
    provider: String,
    /// ID of the LLM surface to change (see `fabric agent-stream surfaces
    /// list`).
    #[arg(long, value_name = "ID")]
    surface: String,
    /// Id of the stored secret that holds the provider's API key (see
    /// `fabric agent-stream secrets list`), not the key itself. The surface
    /// keeps only this id; the key is never read, sent, or printed.
    #[arg(long, value_name = "SECRET_ID")]
    secret: String,
    /// The model, by its `value` (see `fabric agent-stream providers
    /// models`). It must be in the provider's catalog entry and enabled
    /// there. Without it, the surface keeps its model, which must pass the
    /// same check.
    #[arg(long)]
    model: Option<String>,
    /// Base URL the surface sends the provider's calls to, instead of the
    /// one in the catalog. Only providers that keep a base URL on a surface
    /// take it.
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Runs `providers connect` and returns the text to print, if any.
pub(super) async fn run(
    client: &GatewayClient,
    args: ConnectArgs,
    output: Output,
) -> Result<Option<String>> {
    check_secret_id(&args.secret)?;
    if let Some(url) = &args.base_url {
        check_base_url(url)?;
    }
    if let Some((_, needs)) = OTHER_SETTINGS
        .iter()
        .find(|(id, _)| *id == args.provider)
    {
        bail!(
            "a surface describes provider '{}' with {needs} rather than a model and an API key secret, so `connect` \
             can't set it; use `fabric agent-stream surfaces update {} --set pipe_type.provider.<field>=<value>`",
            args.provider,
            args.surface
        );
    }
    let entry = Catalog::read(client)
        .await?
        .find_to_read(&args.provider)?
        .provider;
    if entry.get("enabled") == Some(&Value::Bool(false)) {
        eprintln!(
            "warning: provider '{0}' is disabled in the Model catalog; turn it on with `fabric agent-stream providers \
             update {0} --set enabled=true`",
            args.provider
        );
    }
    if args.base_url.is_some() && !keeps_base_url(&entry) {
        bail!(
            "a surface on provider '{}' has no base URL, and Agent Stream would drop it without an error; leave out \
             --base-url",
            args.provider
        );
    }
    let target = Target {
        provider: enum_value(&entry).to_owned(),
        catalog_entry: entry,
        secret: args.secret,
        model: args.model,
        base_url: args.base_url,
    };
    change_surface(client, &args.surface, args.dry_run, output, |before| target.apply(&args.surface, before)).await
}

/// What `connect` sets on the surface.
struct Target {
    provider: String,
    catalog_entry: Value,
    secret: String,
    model: Option<String>,
    base_url: Option<String>,
}

impl Target {
    /// The surface `before` with its provider settings pointing at this
    /// target. A surface already on the provider keeps its other provider
    /// settings; one on another provider keeps only [`SHARED_SETTINGS`], and
    /// loses `pipe_type.endpoint_path`, the upstream path Agent Stream's
    /// execute API calls, since those belong to the provider it leaves.
    fn apply(
        &self,
        surface_id: &str,
        before: &Value,
    ) -> Result<Value> {
        let kind = before
            .pointer("/pipe_type/type")
            .and_then(Value::as_str);
        if kind != Some("llm") {
            bail!(
                "surface '{surface_id}' is not an LLM surface (its `pipe_type.type` is {}), so it has no provider to \
                 connect",
                kind.map_or_else(|| "missing".to_owned(), |kind| format!("`{}`", sanitize_for_terminal(kind)))
            );
        }
        let current = before
            .pointer("/pipe_type/provider")
            .and_then(Value::as_object);
        let same_provider = current
            .and_then(|settings| settings.get("provider_type"))
            .and_then(Value::as_str)
            == Some(self.provider.as_str());
        let model = self.model(surface_id, current)?;
        let mut settings = match current {
            Some(settings) if same_provider => settings.clone(),
            _ => {
                let mut kept = Map::new();
                for field in SHARED_SETTINGS {
                    if let Some(value) = current.and_then(|settings| settings.get(field)) {
                        kept.insert(field.to_owned(), value.clone());
                    }
                }
                kept
            }
        };
        settings.insert("provider_type".to_owned(), Value::String(self.provider.clone()));
        settings.insert("model".to_owned(), Value::String(model));
        settings.insert("api_key_secret".to_owned(), Value::String(self.secret.clone()));
        if let Some(url) = &self.base_url {
            settings.insert("base_url".to_owned(), Value::String(url.clone()));
        }
        let mut after = before.clone();
        if let Some(pipe_type) = after
            .get_mut("pipe_type")
            .and_then(Value::as_object_mut)
        {
            pipe_type.insert("provider".to_owned(), Value::Object(settings));
            if !same_provider {
                pipe_type.remove("endpoint_path");
            }
        }
        Ok(after)
    }

    /// The model to set: --model, else the surface's own. Either must be in
    /// the provider's catalog entry and enabled there.
    fn model(
        &self,
        surface_id: &str,
        current: Option<&Map<String, Value>>,
    ) -> Result<String> {
        let model = match &self.model {
            Some(model) => model.clone(),
            None => match current
                .and_then(|settings| settings.get("model"))
                .and_then(Value::as_str)
            {
                Some(model) => model.to_owned(),
                None => bail!("surface '{surface_id}' has no model yet; give one with --model"),
            },
        };
        let listed = self
            .catalog_entry
            .get("models")
            .and_then(Value::as_array)
            .and_then(|models| {
                models.iter().find(|listed| {
                    listed
                        .get("value")
                        .and_then(Value::as_str)
                        == Some(model.as_str())
                })
            });
        let shown = sanitize_for_terminal(&model);
        let given = if self.model.is_some() {
            "model"
        } else {
            "the surface's model"
        };
        match listed {
            None => bail!(
                "{given} '{shown}' is not in provider '{}' of the Model catalog; choose one with --model from `fabric \
                 agent-stream providers models {}`",
                self.provider,
                self.provider
            ),
            Some(listed) if listed.get("enabled") == Some(&Value::Bool(false)) => bail!(
                "{given} '{shown}' is disabled in provider '{}', and Agent Stream refuses calls to a disabled model; \
                 enable it with `fabric agent-stream providers enable-model {} {shown}`, or choose another with --model",
                self.provider,
                self.provider
            ),
            Some(_) => Ok(model),
        }
    }
}

/// Whether a surface on the provider of `entry` keeps a `base_url`. A
/// provider Agent Stream doesn't know by name, such as a custom one, keeps it
/// unless its `api_schema` is `anthropic` or `gemini`.
fn keeps_base_url(entry: &Value) -> bool {
    let id = enum_value(entry);
    if KEEP_BASE_URL.contains(&id) {
        return true;
    }
    if NO_BASE_URL.contains(&id) {
        return false;
    }
    !matches!(
        entry
            .get("api_schema")
            .and_then(Value::as_str),
        Some("anthropic" | "gemini")
    )
}

/// Refuses a --secret Agent Stream can't look up, and one that looks like an
/// API key rather than the id of the secret that holds it. The value is never
/// echoed, in case it is a key.
fn check_secret_id(secret: &str) -> Result<()> {
    let shaped = !secret.is_empty()
        && secret.len() <= MAX_SECRET_ID_LEN
        && !secret.contains("..")
        && secret
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !shaped {
        bail!(
            "--secret must be the id of a stored secret: 1 to {MAX_SECRET_ID_LEN} letters, digits, `-`, `_`, or `.`, \
             without `..`; see `fabric agent-stream secrets list`"
        );
    }
    if secret.len() >= KEY_MIN_LEN
        && KEY_PREFIXES
            .iter()
            .any(|prefix| secret.starts_with(prefix))
    {
        bail!(
            "--secret looks like an API key; give the id of the stored secret that holds the key instead (see `fabric \
             agent-stream secrets list`), so the key is never saved on the surface or printed"
        );
    }
    Ok(())
}

/// Refuses a --base-url that isn't an http or https URL with a host, or that
/// carries a user name or password, which the surface would keep and print.
fn check_base_url(url: &str) -> Result<()> {
    let Ok(parsed) = Url::parse(url) else {
        bail!("--base-url must be an http or https URL, such as https://llm.example.com/v1");
    };
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        bail!("--base-url must be an http or https URL, such as https://llm.example.com/v1");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!(
            "--base-url can't carry a user name or password, which the surface would keep in plain text; store the \
             key as a secret and give its id with --secret"
        );
    }
    let loopback = match parsed.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if parsed.scheme() == "http" && !loopback {
        eprintln!(
            "warning: --base-url is plain http to a host other than this machine, so Agent Stream will send the \
             provider's API key there unencrypted"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::super::super::test_support::{
        Route, TEST_ACCESS_TOKEN, request_body, run_stream, saved_login, scripted_agent_stream, start_lines,
    };

    const BUILT_IN: &str = r#"{"providers":[
        {"enum_value":"openai","name":"OpenAI","api_schema":"openai",
         "models":[{"name":"GPT-4o mini","value":"gpt-4o-mini"},{"name":"GPT-4o","value":"gpt-4o","enabled":false}]},
        {"enum_value":"anthropic","name":"Anthropic","api_schema":"anthropic",
         "models":[{"name":"Claude","value":"claude-x"}]},
        {"enum_value":"azure","name":"Azure OpenAI","models":[{"name":"GPT-4o","value":"gpt-4o"}]}]}"#;
    const CUSTOM: &str = r#"{"raw":"{\"providers\":[{\"enum_value\":\"acme\",\"name\":\"Acme\",\"api_schema\":\"openai\",\"models\":[{\"name\":\"A\",\"value\":\"a\"}]},{\"enum_value\":\"claude-proxy\",\"name\":\"Proxy\",\"api_schema\":\"anthropic\",\"models\":[{\"name\":\"C\",\"value\":\"c\"}]}]}","providers":[]}"#;

    /// An LLM surface on Anthropic, with a setting every provider takes and
    /// one only Anthropic takes.
    const ON_ANTHROPIC: &str = r#"{"id":"s-1","name":"Chat","status":"enabled","updated_at":"2026-11-01T00:00:00Z",
        "pipe_type":{"type":"llm","endpoint_path":"/v1/messages","provider":{"provider_type":"anthropic","model":"claude-x",
        "api_key_secret":"anthropic-key","version":"2023-06-01","temperature":0.2}}}"#;
    /// An LLM surface on OpenAI with an organization id and a base URL.
    const ON_OPENAI: &str = r#"{"id":"s-1","name":"Chat","status":"enabled","updated_at":"2026-11-01T00:00:00Z",
        "pipe_type":{"type":"llm","provider":{"provider_type":"openai","model":"gpt-4o-mini",
        "api_key_secret":"openai-key","organization_id":"org-1","base_url":"https://proxy.example.com/v1"}}}"#;
    const ON_OPENAI_LATER: &str = r#"{"id":"s-1","name":"Chat 2","status":"enabled","updated_at":"2026-11-02T00:00:00Z",
        "pipe_type":{"type":"llm","provider":{"provider_type":"openai","model":"gpt-4o-mini",
        "api_key_secret":"openai-key"}}}"#;
    const WEBHOOK: &str = r#"{"id":"s-1","name":"Hook","updated_at":"2026-11-01T00:00:00Z",
        "pipe_type":{"type":"webhook","endpoint":"https://hooks.example.com"}}"#;
    const NO_MODEL: &str =
        r#"{"id":"s-1","name":"New","updated_at":"2026-11-01T00:00:00Z","pipe_type":{"type":"llm"}}"#;

    const GET_BUILT_IN: Route = ("GET /api/v1/llm-providers", "HTTP/1.1 200 OK", BUILT_IN);
    const GET_CUSTOM: Route = ("GET /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", CUSTOM);
    const PUT_SURFACE: Route = ("PUT /api/v1/pipes/s-1", "HTTP/1.1 200 OK", "{}");

    fn get_surface(body: &'static str) -> Route {
        ("GET /api/v1/pipes/s-1", "HTTP/1.1 200 OK", body)
    }

    /// The catalog, then the surface read twice, then the save.
    fn connecting(surface: &'static str) -> Vec<Route> {
        vec![GET_BUILT_IN, GET_CUSTOM, get_surface(surface), get_surface(surface), PUT_SURFACE]
    }

    async fn connect(
        words: &[&str],
        routes: Vec<Route>,
    ) -> (anyhow::Result<()>, Arc<Mutex<Vec<String>>>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let (saved, credentials) = saved_login(&host, TEST_ACCESS_TOKEN);
        let mut all = vec!["providers", "connect"];
        all.extend_from_slice(words);
        let result = run_stream(&all, saved, &credentials).await;
        (result, requests)
    }

    fn error_text(result: anyhow::Result<()>) -> String {
        match result {
            Err(error) => format!("{error:#}"),
            Ok(()) => panic!("expected the command to fail"),
        }
    }

    fn saved_provider(requests: &Arc<Mutex<Vec<String>>>) -> serde_json::Value {
        let recorded = requests.lock().unwrap();
        let put = recorded
            .iter()
            .find(|request| request.starts_with("PUT "))
            .expect("a save");
        let surface: serde_json::Value =
            serde_json::from_str(request_body(put)).unwrap_or_else(|error| panic!("{error}"));
        surface["pipe_type"]["provider"].clone()
    }

    fn writes(requests: &Arc<Mutex<Vec<String>>>) -> usize {
        start_lines(requests)
            .iter()
            .filter(|line| line.starts_with("PUT"))
            .count()
    }

    #[tokio::test]
    async fn moving_a_surface_to_another_provider_keeps_only_the_shared_settings() {
        let (result, requests) = connect(
            &["openai", "--surface", "s-1", "--secret", "openai-key", "--model", "gpt-4o-mini"],
            connecting(ON_ANTHROPIC),
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/llm-providers HTTP/1.1",
                "GET /api/v1/llm-providers/custom HTTP/1.1",
                "GET /api/v1/pipes/s-1 HTTP/1.1",
                "GET /api/v1/pipes/s-1 HTTP/1.1",
                "PUT /api/v1/pipes/s-1 HTTP/1.1"
            ]
        );
        assert_eq!(
            saved_provider(&requests),
            json!({"provider_type":"openai","model":"gpt-4o-mini","api_key_secret":"openai-key","temperature":0.2})
        );
    }

    #[tokio::test]
    async fn the_rest_of_the_surface_is_sent_as_read_without_the_old_provider_s_upstream_path() {
        let (result, requests) = connect(
            &["openai", "--surface", "s-1", "--secret", "openai-key", "--model", "gpt-4o-mini"],
            connecting(ON_ANTHROPIC),
        )
        .await;
        result.unwrap();
        let recorded = requests.lock().unwrap();
        let sent: serde_json::Value = serde_json::from_str(request_body(&recorded[4])).expect("JSON");
        assert_eq!(sent["name"], "Chat");
        assert_eq!(sent["updated_at"], "2026-11-01T00:00:00Z");
        assert_eq!(sent["pipe_type"]["type"], "llm");
        assert!(
            sent["pipe_type"]
                .get("endpoint_path")
                .is_none(),
            "Anthropic's upstream path stays on a surface moved to OpenAI: {sent}"
        );
    }

    #[tokio::test]
    async fn on_the_same_provider_only_the_secret_changes_and_the_model_is_kept() {
        let (result, requests) =
            connect(&["openai", "--surface", "s-1", "--secret", "openai-key-2"], connecting(ON_OPENAI)).await;
        result.unwrap();
        assert_eq!(
            saved_provider(&requests),
            json!({"provider_type":"openai","model":"gpt-4o-mini","api_key_secret":"openai-key-2",
                   "organization_id":"org-1","base_url":"https://proxy.example.com/v1"})
        );
    }

    #[tokio::test]
    async fn a_base_url_is_set_for_a_provider_that_keeps_one() {
        let (result, requests) = connect(
            &[
                "acme",
                "--surface",
                "s-1",
                "--secret",
                "acme-key",
                "--model",
                "a",
                "--base-url",
                "https://llm.acme.example/v1",
            ],
            connecting(ON_OPENAI),
        )
        .await;
        result.unwrap();
        assert_eq!(
            saved_provider(&requests),
            json!({"provider_type":"acme","model":"a","api_key_secret":"acme-key","base_url":"https://llm.acme.example/v1"})
        );
    }

    #[tokio::test]
    async fn a_model_not_in_the_catalog_or_disabled_there_is_refused_and_nothing_is_saved() {
        for (model, expected) in [
            ("gpt-5", "model 'gpt-5' is not in provider 'openai'"),
            ("gpt-4o", "model 'gpt-4o' is disabled in provider 'openai'"),
        ] {
            let (result, requests) = connect(
                &["openai", "--surface", "s-1", "--secret", "openai-key", "--model", model],
                connecting(ON_ANTHROPIC),
            )
            .await;
            let text = error_text(result);
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("providers "), "{text}");
            assert_eq!(writes(&requests), 0);
        }
    }

    #[tokio::test]
    async fn without_model_the_surface_s_model_must_be_in_the_new_provider() {
        let (result, requests) =
            connect(&["openai", "--surface", "s-1", "--secret", "openai-key"], connecting(ON_ANTHROPIC)).await;
        let text = error_text(result);
        assert!(text.contains("the surface's model 'claude-x' is not in provider 'openai'"), "{text}");
        assert_eq!(writes(&requests), 0);

        let (result, requests) =
            connect(&["openai", "--surface", "s-1", "--secret", "openai-key"], connecting(NO_MODEL)).await;
        let text = error_text(result);
        assert!(text.contains("has no model yet; give one with --model"), "{text}");
        assert_eq!(writes(&requests), 0);
    }

    #[tokio::test]
    async fn a_base_url_for_a_provider_without_one_is_refused_before_the_surface_is_read() {
        for provider in ["anthropic", "claude-proxy"] {
            let (result, requests) = connect(
                &[provider, "--surface", "s-1", "--secret", "key-id", "--base-url", "https://llm.example.com"],
                connecting(ON_ANTHROPIC),
            )
            .await;
            let text = error_text(result);
            assert!(text.contains("has no base URL"), "{text}");
            assert!(
                !start_lines(&requests)
                    .iter()
                    .any(|line| line.contains("/pipes/")),
                "{:?}",
                start_lines(&requests)
            );
        }
    }

    #[tokio::test]
    async fn a_secret_that_looks_like_a_key_or_can_t_name_a_secret_is_refused_before_anything_is_sent() {
        let key = "sk-this-is-not-a-real-key-only-a-test";
        for (secret, expected) in [
            (key, "--secret looks like an API key"),
            ("../keys", "--secret must be the id of a stored secret"),
            ("my key", "--secret must be the id of a stored secret"),
        ] {
            let (result, requests) =
                connect(&["openai", "--surface", "s-1", "--secret", secret], connecting(ON_OPENAI)).await;
            let text = error_text(result);
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains(secret), "the error echoes --secret: {text}");
            assert!(start_lines(&requests).is_empty(), "{:?}", start_lines(&requests));
        }
    }

    #[tokio::test]
    async fn a_base_url_with_a_password_or_not_http_is_refused_before_anything_is_sent() {
        for (url, expected) in [
            ("https://user:pass@llm.example.com", "can't carry a user name or password"),
            ("ftp://llm.example.com", "must be an http or https URL"),
            ("llm.example.com", "must be an http or https URL"),
        ] {
            let (result, requests) = connect(
                &["openai", "--surface", "s-1", "--secret", "openai-key", "--base-url", url],
                connecting(ON_OPENAI),
            )
            .await;
            let text = error_text(result);
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains("pass@"), "{text}");
            assert!(start_lines(&requests).is_empty(), "{:?}", start_lines(&requests));
        }
    }

    #[tokio::test]
    async fn azure_and_custom_are_refused_with_the_fields_they_need() {
        for (provider, needs) in [
            ("azure", "`deployment_name`, `endpoint`, and `api_version`"),
            ("custom", "`name`, `endpoint`, and `auth_secret`"),
        ] {
            let (result, requests) =
                connect(&[provider, "--surface", "s-1", "--secret", "key-id"], connecting(ON_OPENAI)).await;
            let text = error_text(result);
            assert!(text.contains(needs), "{text}");
            assert!(text.contains("surfaces update s-1"), "{text}");
            assert!(start_lines(&requests).is_empty(), "{:?}", start_lines(&requests));
        }
    }

    #[tokio::test]
    async fn a_short_secret_id_that_starts_like_a_key_is_accepted() {
        let (result, requests) =
            connect(&["openai", "--surface", "s-1", "--secret", "sk-prod-openai"], connecting(ON_OPENAI)).await;
        result.unwrap();
        assert_eq!(saved_provider(&requests)["api_key_secret"], "sk-prod-openai");
    }

    #[tokio::test]
    async fn a_surface_that_is_not_an_llm_surface_is_refused() {
        let (result, requests) = connect(
            &["openai", "--surface", "s-1", "--secret", "openai-key", "--model", "gpt-4o-mini"],
            connecting(WEBHOOK),
        )
        .await;
        let text = error_text(result);
        assert!(text.contains("surface 's-1' is not an LLM surface (its `pipe_type.type` is `webhook`)"), "{text}");
        assert_eq!(writes(&requests), 0);
    }

    #[tokio::test]
    async fn an_unknown_provider_is_refused() {
        let (result, requests) =
            connect(&["nope", "--surface", "s-1", "--secret", "key-id"], connecting(ON_OPENAI)).await;
        let text = error_text(result);
        assert!(text.contains("the Model catalog has no provider 'nope'"), "{text}");
        assert_eq!(writes(&requests), 0);
    }

    #[tokio::test]
    async fn a_dry_run_or_a_change_to_nothing_sends_no_save() {
        let (result, requests) = connect(
            &["openai", "--surface", "s-1", "--secret", "openai-key", "--model", "gpt-4o-mini", "--dry-run"],
            connecting(ON_ANTHROPIC),
        )
        .await;
        result.unwrap();
        assert_eq!(writes(&requests), 0);

        let (result, requests) =
            connect(&["openai", "--surface", "s-1", "--secret", "openai-key"], connecting(ON_OPENAI)).await;
        result.unwrap();
        assert_eq!(writes(&requests), 0);
    }

    #[tokio::test]
    async fn a_surface_saved_after_it_was_read_stops_the_save() {
        let (result, requests) = connect(
            &["openai", "--surface", "s-1", "--secret", "openai-key-2"],
            vec![GET_BUILT_IN, GET_CUSTOM, get_surface(ON_OPENAI), get_surface(ON_OPENAI_LATER), PUT_SURFACE],
        )
        .await;
        let text = error_text(result);
        assert!(text.contains("was saved by someone else after it was read"), "{text}");
        assert_eq!(writes(&requests), 0);
    }

    #[test]
    fn a_provider_keeps_a_base_url_by_its_name_or_else_its_api_schema() {
        let entry = |id: &str, schema: &str| json!({"enum_value": id, "api_schema": schema});
        assert!(super::keeps_base_url(&entry("groq", "openai")));
        assert!(!super::keeps_base_url(&entry("anthropic", "anthropic")));
        assert!(!super::keeps_base_url(&entry("mistral", "openai")));
        assert!(super::keeps_base_url(&entry("acme", "openai")));
        assert!(super::keeps_base_url(&entry("copilot-proxy", "copilot")));
        assert!(!super::keeps_base_url(&entry("gemini-proxy", "gemini")));
    }
}
