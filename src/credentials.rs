use anyhow::{Context, Result};

const SERVICE_NAME: &str = "affinidi-trust-fabric-cli";

pub trait CredentialStore {
    fn get_token(
        &self,
        connection: &str,
    ) -> Result<Option<String>>;
    fn set_token(
        &self,
        connection: &str,
        token: &str,
    ) -> Result<()>;
    fn delete_token(
        &self,
        connection: &str,
    ) -> Result<()>;

    /// The host a connection's token was issued for, which login saves beside
    /// the token so the token is only ever sent back there. `None` for a
    /// connection saved before this was recorded.
    fn get_bound_host(
        &self,
        connection: &str,
    ) -> Result<Option<String>> {
        self.get_token(&bound_host_key(connection))
    }

    fn set_bound_host(
        &self,
        connection: &str,
        host: &str,
    ) -> Result<()> {
        self.set_token(&bound_host_key(connection), host)
    }

    fn delete_bound_host(
        &self,
        connection: &str,
    ) -> Result<()> {
        self.delete_token(&bound_host_key(connection))
    }
}

/// Account key the bound host of `connection` is kept under, next to its token.
fn bound_host_key(connection: &str) -> String {
    format!("{connection}#bound-host")
}

pub struct OsCredentialStore;

impl OsCredentialStore {
    pub fn new() -> Self {
        Self
    }

    fn entry(connection: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, connection)
            .with_context(|| format!("open OS keyring entry for connection '{connection}'"))
    }
}

/// Opening of every hint for an error from a Linux machine where no Secret
/// Service keyring can be reached over D-Bus, such as a server with no
/// desktop session.
const NO_KEYRING: &str = "no OS keyring can be reached over D-Bus here, as on a server with no desktop session";

/// `error` with a hint to set FABRIC_HOST and FABRIC_TOKEN added when it
/// comes from a Linux keyring call that failed because D-Bus or the Secret
/// Service could not be reached. Every other error, including a locked
/// keyring or a dismissed unlock prompt, is returned as it is.
pub fn add_no_keyring_hint(error: anyhow::Error) -> anyhow::Error {
    if comes_from_unreachable_keyring(&error) {
        error.context(format!(
            "{NO_KEYRING}, so saved connections can't be used; set FABRIC_HOST and FABRIC_TOKEN to run a command \
             without one"
        ))
    } else {
        error
    }
}

/// `error` from moving the plaintext token of `connection` in `config_file`
/// into the keyring, with a hint added when that failed because D-Bus or the
/// Secret Service could not be reached. The move runs again on every command
/// that may use the keyring until the tokens are gone from the file, and it
/// covers every saved connection, not only the current one, so the hint names
/// `connection` and its saved `host` and says to copy that connection's token
/// into FABRIC_TOKEN, set FABRIC_HOST to `host`, and delete the token line.
/// The token value itself is never part of the hint. Every other error is
/// returned as it is.
pub fn add_no_keyring_migration_hint(
    error: anyhow::Error,
    config_file: &std::path::Path,
    connection: &str,
    host: &str,
) -> anyhow::Error {
    if comes_from_unreachable_keyring(&error) {
        let connection = crate::client::sanitize_whole(connection);
        let host = crate::client::sanitize_whole(host);
        error.context(format!(
            "{NO_KEYRING}, so the plaintext token of connection '{connection}' saved in {} can't be moved into one; \
             to run commands as '{connection}' without the keyring, copy that connection's `token` value into \
             FABRIC_TOKEN, set FABRIC_HOST to {host}, and delete that `token` line from the file",
            config_file.display()
        ))
    } else {
        error
    }
}

/// Whether any cause in `error` is a keyring error that
/// [`is_unreachable_keyring`] accepts.
fn comes_from_unreachable_keyring(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<keyring::Error>())
        .any(is_unreachable_keyring)
}

/// D-Bus error name the message bus answers with when no program provides,
/// or can be started to provide, the Secret Service.
#[cfg(target_os = "linux")]
const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";

/// Whether `error` says the Secret Service itself could not be reached:
/// either there is no D-Bus session to connect to (`Unavailable`), or the
/// session's message bus answered `org.freedesktop.DBus.Error.ServiceUnknown`
/// because nothing provides the Secret Service. Any other D-Bus failure,
/// such as a running keyring refusing access, is not.
#[cfg(target_os = "linux")]
fn is_unreachable_keyring(error: &keyring::Error) -> bool {
    let keyring::Error::PlatformFailure(cause) = error else {
        return false;
    };
    match cause.downcast_ref::<secret_service::Error>() {
        Some(secret_service::Error::Unavailable) => true,
        Some(secret_service::Error::Zbus(error)) => is_service_unknown(error),
        Some(secret_service::Error::ZbusFdo(error)) => is_fdo_service_unknown(error),
        _ => false,
    }
}

/// Whether a zbus `error` is the message bus's ServiceUnknown reply, either
/// as a raw method error or wrapped as a standard D-Bus error.
#[cfg(target_os = "linux")]
fn is_service_unknown(error: &zbus::Error) -> bool {
    match error {
        zbus::Error::MethodError(name, _, _) => name.as_str() == SERVICE_UNKNOWN,
        zbus::Error::FDO(error) => is_fdo_service_unknown(error),
        _ => false,
    }
}

/// Whether a standard D-Bus `error` is the message bus's ServiceUnknown reply.
#[cfg(target_os = "linux")]
fn is_fdo_service_unknown(error: &zbus::fdo::Error) -> bool {
    match error {
        zbus::fdo::Error::ServiceUnknown(_) => true,
        zbus::fdo::Error::ZBus(error) => is_service_unknown(error),
        _ => false,
    }
}

/// The Linux D-Bus hint never applies to macOS Keychain or Windows Credential
/// Manager errors.
#[cfg(not(target_os = "linux"))]
fn is_unreachable_keyring(_error: &keyring::Error) -> bool {
    false
}

impl CredentialStore for OsCredentialStore {
    fn get_token(
        &self,
        connection: &str,
    ) -> Result<Option<String>> {
        match Self::entry(connection)?.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).with_context(|| format!("read connection '{connection}' token from OS keyring")),
        }
    }

    fn set_token(
        &self,
        connection: &str,
        token: &str,
    ) -> Result<()> {
        Self::entry(connection)?
            .set_password(token)
            .with_context(|| format!("store connection '{connection}' token in OS keyring"))
    }

    fn delete_token(
        &self,
        connection: &str,
    ) -> Result<()> {
        match Self::entry(connection)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).with_context(|| format!("delete connection '{connection}' token from OS keyring")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Default)]
    struct MemoryStore(Mutex<HashMap<String, String>>);

    impl CredentialStore for MemoryStore {
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

    #[test]
    fn a_bound_host_is_kept_apart_from_the_token() {
        let store = MemoryStore::default();
        store
            .set_token("prod", "token-1")
            .unwrap();
        assert_eq!(
            store
                .get_bound_host("prod")
                .unwrap(),
            None
        );
        store
            .set_bound_host("prod", "https://gateway.example.com")
            .unwrap();
        assert_eq!(
            store
                .get_bound_host("prod")
                .unwrap()
                .as_deref(),
            Some("https://gateway.example.com")
        );
        assert_eq!(
            store
                .get_token("prod")
                .unwrap()
                .as_deref(),
            Some("token-1")
        );
        store
            .delete_bound_host("prod")
            .unwrap();
        assert_eq!(
            store
                .get_bound_host("prod")
                .unwrap(),
            None
        );
        assert!(
            store
                .get_token("prod")
                .unwrap()
                .is_some()
        );
    }

    fn store_failure(cause: keyring::Error) -> anyhow::Error {
        anyhow::Error::new(cause)
            .context("store connection 'default' token in OS keyring")
            .context("log in")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unreachable_secret_service_suggests_the_host_and_token_variables() {
        let unreachable = keyring::Error::PlatformFailure(Box::new(secret_service::Error::Unavailable));

        let text = format!("{:#}", add_no_keyring_hint(store_failure(unreachable)));

        assert!(text.contains("set FABRIC_HOST and FABRIC_TOKEN"), "{text}");
        assert!(text.contains("store connection 'default' token in OS keyring"), "{text}");
    }

    /// A D-Bus error reply named `name`, as the message bus sends it back.
    #[cfg(target_os = "linux")]
    fn method_error(name: &str) -> zbus::Error {
        let call = zbus::message::Message::method("/org/freedesktop/secrets", "OpenSession")
            .unwrap()
            .build(&())
            .unwrap();
        let reply = zbus::message::Message::method_error(&call, name)
            .unwrap()
            .build(&("no such service",))
            .unwrap();
        zbus::Error::from(reply)
    }

    #[cfg(target_os = "linux")]
    fn platform_failure(cause: secret_service::Error) -> keyring::Error {
        keyring::Error::PlatformFailure(Box::new(cause))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_secret_service_the_bus_does_not_know_suggests_the_host_and_token_variables() {
        for cause in [
            secret_service::Error::Zbus(method_error(SERVICE_UNKNOWN)),
            secret_service::Error::Zbus(zbus::Error::FDO(Box::new(zbus::fdo::Error::ServiceUnknown(
                "no such service".to_owned(),
            )))),
            secret_service::Error::ZbusFdo(zbus::fdo::Error::ServiceUnknown("no such service".to_owned())),
        ] {
            let text = format!("{:#}", add_no_keyring_hint(store_failure(platform_failure(cause))));
            assert!(text.contains("set FABRIC_HOST and FABRIC_TOKEN"), "{text}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_secret_service_that_answered_gets_no_hint() {
        for cause in [
            keyring::Error::NoStorageAccess(Box::new(secret_service::Error::Prompt)),
            keyring::Error::NoStorageAccess(Box::new(secret_service::Error::Locked)),
            platform_failure(secret_service::Error::Crypto("bad padding")),
            platform_failure(secret_service::Error::Zbus(method_error("org.freedesktop.DBus.Error.AccessDenied"))),
            platform_failure(secret_service::Error::ZbusFdo(zbus::fdo::Error::AccessDenied("not allowed".to_owned()))),
            platform_failure(secret_service::Error::Zbus(zbus::Error::Failure("broken reply".to_owned()))),
        ] {
            let text = format!("{:#}", add_no_keyring_hint(store_failure(cause)));
            assert!(!text.contains("FABRIC_TOKEN"), "{text}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_token_migration_names_the_connection_and_its_host() {
        let config_file = std::path::Path::new("/home/ops/.config/fabric/config.toml");
        let error = anyhow::Error::new(platform_failure(secret_service::Error::Unavailable))
            .context("migrate connection 'prod' token to OS keyring");

        let text = format!("{:#}", add_no_keyring_migration_hint(error, config_file, "prod", "https://prod.example"));

        assert!(
            text.contains("plaintext token of connection 'prod' saved in /home/ops/.config/fabric/config.toml"),
            "{text}"
        );
        assert!(text.contains("to run commands as 'prod' without the keyring"), "{text}");
        assert!(text.contains("copy that connection's `token` value into FABRIC_TOKEN"), "{text}");
        assert!(text.contains("set FABRIC_HOST to https://prod.example,"), "{text}");
        assert!(text.contains("migrate connection 'prod' token to OS keyring"), "{text}");
    }

    #[test]
    fn a_failed_token_migration_from_outside_the_keyring_gets_no_hint() {
        let error = anyhow::anyhow!("permission denied");

        let text = format!(
            "{:#}",
            add_no_keyring_migration_hint(
                error,
                std::path::Path::new("/home/ops/.config/fabric/config.toml"),
                "prod",
                "https://prod.example"
            )
        );

        assert_eq!(text, "permission denied");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_platform_keyring_failure_gets_no_hint_outside_linux() {
        for cause in [
            keyring::Error::PlatformFailure("User canceled the operation.".into()),
            keyring::Error::NoStorageAccess("locked".into()),
        ] {
            let text = format!("{:#}", add_no_keyring_hint(store_failure(cause)));
            assert!(!text.contains("FABRIC_TOKEN"), "{text}");
        }
    }

    #[test]
    fn an_error_from_outside_the_keyring_gets_no_hint() {
        let error = anyhow::anyhow!("gateway returned 401 Unauthorized");

        assert_eq!(format!("{:#}", add_no_keyring_hint(error)), "gateway returned 401 Unauthorized");
    }

    #[test]
    #[ignore = "writes a temporary credential to the operating system keyring"]
    fn os_keyring_round_trip() {
        let store = OsCredentialStore::new();
        let connection = format!("test-{}", std::process::id());
        store
            .delete_token(&connection)
            .unwrap();
        store
            .set_token(&connection, "temporary-test-token")
            .unwrap();
        assert_eq!(
            store
                .get_token(&connection)
                .unwrap()
                .as_deref(),
            Some("temporary-test-token")
        );
        store
            .delete_token(&connection)
            .unwrap();
        assert!(
            store
                .get_token(&connection)
                .unwrap()
                .is_none()
        );
    }
}
