use std::{collections::BTreeMap, fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    credentials::{CredentialStore, add_no_keyring_migration_hint},
    product::Product,
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub current: Option<String>,
    #[serde(default)]
    pub connections: BTreeMap<String, Connection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub host: String,
    #[serde(default, rename = "token", skip_serializing)]
    legacy_token: Option<String>,
}

impl Connection {
    pub fn new(host: String) -> Self {
        Self { host, legacy_token: None }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        Self::load_from(&config_path()?)
    }

    pub fn migrate_legacy_tokens(
        &mut self,
        credentials: &impl CredentialStore,
    ) -> Result<()> {
        let path = config_path()?;
        self.migrate_legacy_tokens_to(credentials, &path)
    }

    /// [`Self::resolve_for`] on Agent Gateway connections.
    #[cfg(test)]
    pub fn resolve(
        &self,
        name: Option<&str>,
    ) -> Result<(&str, &Connection)> {
        self.resolve_for(Product::AgentGateway, name)
    }

    /// The saved connection called `name`, or the current one when `name` is
    /// `None`, with the name as it is saved. `product` is whose connections
    /// these are, so an error names that product's connections and tells the
    /// user to run its `login`.
    pub fn resolve_for(
        &self,
        product: Product,
        name: Option<&str>,
    ) -> Result<(&str, &Connection)> {
        let noun = product.connection_noun();
        let name = name
            .or(self.current.as_deref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no {noun} configured; run `{} login --host <URL>`, or set both FABRIC_HOST and FABRIC_TOKEN",
                    product.command()
                )
            })?;
        let (stored_name, connection) = self
            .connections
            .get_key_value(name)
            .ok_or_else(|| anyhow::anyhow!("{noun} '{name}' does not exist"))?;
        Ok((stored_name, connection))
    }

    /// A warning for each saved connection whose name contains `#`, which login
    /// refuses: the host a token is bound to is kept under `<name>#bound-host`,
    /// so such a name can share a credential key with another connection.
    pub fn hash_name_warnings(&self) -> Vec<String> {
        self.connections
            .keys()
            .filter(|name| name.contains('#'))
            .map(|name| {
                format!(
                    "warning: connection '{}' has a '#' in its name, which can share a saved token with another \
                     connection; remove it and log in again under a name without '#'",
                    crate::client::sanitize_whole(name)
                )
            })
            .collect()
    }

    pub(crate) fn load_from(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("parse {}", path.display()))
    }

    pub(crate) fn save_to(
        &self,
        path: &std::path::Path,
    ) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let contents = toml::to_string_pretty(self).context("serialize CLI configuration")?;
        fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
        set_owner_only(path)?;
        Ok(())
    }

    /// Moves every plaintext `token` read from the file at `path` into
    /// `credentials`, records the host each one belongs to, and rewrites the
    /// file without them. Does nothing, and touches neither, when the file
    /// held no token.
    pub(crate) fn migrate_legacy_tokens_to(
        &mut self,
        credentials: &impl CredentialStore,
        path: &std::path::Path,
    ) -> Result<()> {
        let legacy: Vec<(String, String, String)> = self
            .connections
            .iter()
            .filter_map(|(name, connection)| {
                connection
                    .legacy_token
                    .clone()
                    .map(|token| {
                        let host = normalize_host(&connection.host).unwrap_or_else(|_| connection.host.clone());
                        (name.clone(), token, host)
                    })
            })
            .collect();
        if legacy.is_empty() {
            return Ok(());
        }
        for (name, token, host) in &legacy {
            credentials
                .set_token(name, token)
                .with_context(|| format!("migrate connection '{name}' token to OS keyring"))
                .map_err(|error| add_no_keyring_migration_hint(error, path, name, host))?;
            credentials
                .set_bound_host(name, host)
                .with_context(|| format!("record the host of connection '{name}' in OS keyring"))
                .map_err(|error| add_no_keyring_migration_hint(error, path, name, host))?;
        }
        for connection in self.connections.values_mut() {
            connection.legacy_token = None;
        }
        self.save_to(path)
            .context("remove migrated plaintext tokens from CLI configuration")
    }
}

pub fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        bail!("host must not be empty");
    }
    let normalized = if host.contains("://") {
        host.to_owned()
    } else {
        format!("https://{host}")
    };
    let mut url = url::Url::parse(&normalized).context("host must be a valid http or https URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("host URL scheme must be http or https");
    }
    if url.cannot_be_a_base() || url.host_str().is_none() {
        bail!("host must include a hostname");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url
        .as_str()
        .trim_end_matches('/')
        .to_owned())
}

/// Normalize a host the user typed on the command line. Plain `http://` to a
/// host other than this machine is refused unless `allow_http` is set, and
/// prints a warning to stderr when it is, since the login code exchange and
/// the session token cross the network unencrypted. Saved connection hosts
/// skip this, so an existing http connection keeps working.
pub fn normalize_user_host(
    host: &str,
    allow_http: bool,
) -> Result<String> {
    let normalized = normalize_host(host)?;
    let url = url::Url::parse(&normalized).context("host must be a valid http or https URL")?;
    if url.scheme() == "http" && !allow_http && !is_loopback_host(&url) {
        bail!(
            "refusing to use plain http for a non-local host ({}), the session token would be sent unencrypted; use \
             https or pass --allow-http",
            url.host_str()
                .unwrap_or_default()
        );
    }
    if let Some(warning) = plain_http_warning(&url, allow_http) {
        eprintln!("{warning}");
    }
    Ok(normalized)
}

/// Warning to print when a saved connection points at plain `http://` on a
/// host other than this machine, since its token crosses the network
/// unencrypted on every command.
pub fn saved_host_http_warning(host: &str) -> Option<String> {
    let url = url::Url::parse(host).ok()?;
    plain_http_warning(&url, true).map(|warning| format!("{warning}; log in again with an https host to fix this"))
}

fn plain_http_warning(
    url: &url::Url,
    allow_http: bool,
) -> Option<String> {
    if url.scheme() != "http" || !allow_http || is_loopback_host(url) {
        return None;
    }
    Some(format!(
        "warning: using plain http with {}, the session token will be sent unencrypted",
        url.host_str()
            .unwrap_or_default()
    ))
}

fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// The file the Agent Gateway connections are saved in. It predates the Agent
/// Stream file, so it carries no product name.
pub(crate) fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(Product::AgentGateway.config_file_name()))
}

/// The file the Agent Stream connections are saved in, beside the Agent
/// Gateway one, so a connection named `default` in one never touches the
/// other, and a CLI from before this file ignores it.
#[cfg(feature = "agent-stream")]
pub(crate) fn agent_stream_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(Product::AgentStream.config_file_name()))
}

/// The `fabric` directory under the user configuration directory.
fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("could not determine the user configuration directory")?;
    Ok(base.join("fabric"))
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| format!("secure {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Default)]
    struct MemoryCredentials(Mutex<HashMap<String, String>>);

    struct FailingCredentials;

    impl CredentialStore for MemoryCredentials {
        fn product(&self) -> Product {
            Product::AgentGateway
        }

        fn get_token(
            &self,
            connection: &str,
        ) -> Result<Option<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(connection)
                .cloned())
        }

        fn set_token(
            &self,
            connection: &str,
            token: &str,
        ) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(connection.to_owned(), token.to_owned());
            Ok(())
        }

        fn delete_token(
            &self,
            connection: &str,
        ) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .remove(connection);
            Ok(())
        }
    }

    impl CredentialStore for FailingCredentials {
        fn product(&self) -> Product {
            Product::AgentGateway
        }

        fn get_token(
            &self,
            _connection: &str,
        ) -> Result<Option<String>> {
            Ok(None)
        }

        fn set_token(
            &self,
            _connection: &str,
            _token: &str,
        ) -> Result<()> {
            bail!("credential store unavailable")
        }

        fn delete_token(
            &self,
            _connection: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_connection_name_with_a_hash_gets_a_warning() {
        let mut config = Config::default();
        config
            .connections
            .insert("prod".into(), Connection::new("https://gateway.example".into()));
        assert!(
            config
                .hash_name_warnings()
                .is_empty()
        );

        config
            .connections
            .insert("prod#bound-host".into(), Connection::new("https://other.example".into()));
        let warnings = config.hash_name_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("prod#bound-host"), "{warnings:?}");
    }

    #[test]
    fn config_round_trip_and_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = Config {
            current: Some("local".into()),
            ..Config::default()
        };
        config
            .connections
            .insert("local".into(), Connection::new("http://localhost:8080".into()));

        config.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        let (name, connection) = loaded.resolve(None).unwrap();

        assert_eq!(name, "local");
        assert_eq!(connection.host, "http://localhost:8080");
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains("token")
        );
    }

    /// A `config.toml` as the 0.1.4 CLI wrote it: a `current` name and
    /// `[connections.<name>]` tables holding only a `host`.
    const V0_1_4_CONFIG: &str = r#"current = "default"

[connections.default]
host = "https://gateway.example"

[connections.staging]
host = "https://staging.example"
"#;

    #[test]
    fn a_config_file_written_by_version_0_1_4_still_loads_and_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, V0_1_4_CONFIG).unwrap();

        let config = Config::load_from(&path).unwrap();

        let (name, connection) = config.resolve(None).unwrap();
        assert_eq!(name, "default");
        assert_eq!(connection.host, "https://gateway.example");
        let (name, connection) = config
            .resolve(Some("staging"))
            .unwrap();
        assert_eq!(name, "staging");
        assert_eq!(connection.host, "https://staging.example");
        config.save_to(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), V0_1_4_CONFIG);
    }

    #[cfg(feature = "agent-stream")]
    #[test]
    fn the_agent_stream_file_sits_beside_the_gateway_file_under_its_own_name() {
        let gateway = config_path().unwrap();
        let stream = agent_stream_config_path().unwrap();

        assert_eq!(gateway.parent(), stream.parent());
        assert_eq!(gateway.file_name().unwrap(), "config.toml");
        assert_eq!(stream.file_name().unwrap(), "agent-stream.toml");
    }

    #[cfg(feature = "agent-stream")]
    #[test]
    fn a_default_connection_in_each_product_file_leaves_the_other_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let gateway_path = dir.path().join("config.toml");
        let stream_path = dir
            .path()
            .join("agent-stream.toml");
        std::fs::write(&gateway_path, V0_1_4_CONFIG).unwrap();
        let mut stream = Config {
            current: Some("default".into()),
            ..Config::default()
        };
        stream
            .connections
            .insert("default".into(), Connection::new("https://stream.example".into()));

        stream
            .save_to(&stream_path)
            .unwrap();
        stream
            .connections
            .remove("default");
        stream.current = None;
        stream
            .save_to(&stream_path)
            .unwrap();

        assert_eq!(std::fs::read_to_string(&gateway_path).unwrap(), V0_1_4_CONFIG);
        let (name, connection) = Config::load_from(&gateway_path)
            .unwrap()
            .resolve(None)
            .map(|(name, connection)| (name.to_owned(), connection.host.clone()))
            .unwrap();
        assert_eq!((name.as_str(), connection.as_str()), ("default", "https://gateway.example"));
        assert!(
            Config::load_from(&stream_path)
                .unwrap()
                .connections
                .is_empty()
        );
    }

    #[test]
    fn migrates_legacy_tokens_and_scrubs_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"current = "local"

[connections.local]
host = "https://gateway.example"
token = "legacy-secret"
"#,
        )
        .unwrap();
        let credentials = MemoryCredentials::default();
        let mut config = Config::load_from(&path).unwrap();

        config
            .migrate_legacy_tokens_to(&credentials, &path)
            .unwrap();

        assert_eq!(
            credentials
                .get_token("local")
                .unwrap()
                .as_deref(),
            Some("legacy-secret")
        );
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains("legacy-secret")
        );
        assert_eq!(
            credentials
                .get_bound_host("local")
                .unwrap()
                .as_deref(),
            Some("https://gateway.example")
        );
    }

    #[test]
    fn preserves_legacy_token_when_keyring_migration_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"current = "local"

[connections.local]
host = "https://gateway.example"
token = "only-copy"
"#,
        )
        .unwrap();
        let mut config = Config::load_from(&path).unwrap();

        assert!(
            config
                .migrate_legacy_tokens_to(&FailingCredentials, &path)
                .is_err()
        );
        assert!(
            std::fs::read_to_string(path)
                .unwrap()
                .contains("only-copy")
        );
    }

    /// A credential store on a Linux machine with no D-Bus session, where
    /// every keyring call fails the way the Secret Service client reports it.
    #[cfg(target_os = "linux")]
    struct NoSecretService;

    #[cfg(target_os = "linux")]
    impl CredentialStore for NoSecretService {
        fn product(&self) -> Product {
            Product::AgentGateway
        }

        fn get_token(
            &self,
            _connection: &str,
        ) -> Result<Option<String>> {
            Err(keyring::Error::PlatformFailure(Box::new(secret_service::Error::Unavailable)).into())
        }

        fn set_token(
            &self,
            _connection: &str,
            _token: &str,
        ) -> Result<()> {
            Err(keyring::Error::PlatformFailure(Box::new(secret_service::Error::Unavailable)).into())
        }

        fn delete_token(
            &self,
            _connection: &str,
        ) -> Result<()> {
            Err(keyring::Error::PlatformFailure(Box::new(secret_service::Error::Unavailable)).into())
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_migration_with_no_reachable_keyring_names_the_connection_and_host_to_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"current = "local"

[connections.local]
host = "https://local.example"

[connections.prod]
host = "prod.example/"
token = "prod-only-copy"
"#,
        )
        .unwrap();
        let mut config = Config::load_from(&path).unwrap();

        let error = config
            .migrate_legacy_tokens_to(&NoSecretService, &path)
            .expect_err("the keyring can't be reached");

        let text = format!("{error:#}");
        assert!(text.contains(&format!("plaintext token of connection 'prod' saved in {}", path.display())), "{text}");
        assert!(text.contains("set FABRIC_HOST to https://prod.example,"), "{text}");
        assert!(text.contains("delete that `token` line from the file"), "{text}");
        assert!(!text.contains("local.example"), "{text}");
        assert!(!text.contains("prod-only-copy"), "{text}");
    }

    #[test]
    fn host_normalization_rejects_non_http_urls() {
        assert_eq!(normalize_host("https://gateway.example/api/").unwrap(), "https://gateway.example/api");
        assert_eq!(normalize_host("gateway.example").unwrap(), "https://gateway.example");
        assert_eq!(normalize_host("localhost:8080").unwrap(), "https://localhost:8080");
        assert!(normalize_host("file:///tmp/gateway").is_err());
        assert!(normalize_host(" ").is_err());
        assert_eq!(normalize_host("http://gateway.example").unwrap(), "http://gateway.example");
    }

    #[test]
    fn user_host_allows_plain_http_to_loopback_without_the_flag() {
        for host in ["http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"] {
            assert_eq!(normalize_user_host(host, false).unwrap(), host);
        }
    }

    #[test]
    fn user_host_refuses_plain_http_to_a_remote_host_without_the_flag() {
        let error = normalize_user_host("http://gateway.example.com", false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("gateway.example.com"), "{error}");
        assert!(error.contains("--allow-http"), "{error}");
    }

    #[test]
    fn user_host_allows_plain_http_to_a_remote_host_with_the_flag() {
        assert_eq!(normalize_user_host("http://gateway.example.com", true).unwrap(), "http://gateway.example.com");
    }

    #[test]
    fn plain_http_warning_is_shown_for_a_remote_host_with_the_flag() {
        let url = url::Url::parse("http://gateway.example.com").unwrap();
        let warning = plain_http_warning(&url, true).unwrap();
        assert!(warning.starts_with("warning: "), "{warning}");
        assert!(warning.contains("gateway.example.com"), "{warning}");
        assert!(warning.contains("unencrypted"), "{warning}");
    }

    #[test]
    fn plain_http_warning_is_not_shown_for_loopback_hosts() {
        for host in ["http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"] {
            let url = url::Url::parse(host).unwrap();
            assert_eq!(plain_http_warning(&url, true), None, "{host}");
            assert_eq!(plain_http_warning(&url, false), None, "{host}");
        }
    }

    #[test]
    fn a_saved_plain_http_host_gets_a_warning_unless_it_is_local_or_https() {
        let warning = saved_host_http_warning("http://gateway.example.com").unwrap();
        assert!(warning.contains("gateway.example.com"), "{warning}");
        assert!(warning.contains("log in again with an https host"), "{warning}");
        for host in ["http://localhost:8080", "http://127.0.0.1:8080", "https://gateway.example.com", "not a url"] {
            assert_eq!(saved_host_http_warning(host), None, "{host}");
        }
    }

    #[test]
    fn plain_http_warning_is_not_shown_for_https() {
        let url = url::Url::parse("https://gateway.example.com").unwrap();
        assert_eq!(plain_http_warning(&url, true), None);
        assert_eq!(plain_http_warning(&url, false), None);
    }

    #[test]
    fn user_host_allows_https_and_defaults_a_bare_host_to_https() {
        assert_eq!(normalize_user_host("https://gateway.example.com", false).unwrap(), "https://gateway.example.com");
        assert_eq!(normalize_user_host("gateway.example.com", false).unwrap(), "https://gateway.example.com");
    }
}
