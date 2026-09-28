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
    use super::*;

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
