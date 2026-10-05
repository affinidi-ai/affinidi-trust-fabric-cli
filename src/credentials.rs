use anyhow::{Context, Result};

const SERVICE_NAME: &str = "affinidi-fabric-cli";

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
