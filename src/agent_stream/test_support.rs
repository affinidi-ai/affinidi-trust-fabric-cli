//! What the tests of the `fabric agent-stream` command groups share.

use std::{collections::HashMap, sync::Mutex};

use anyhow::Result;

use crate::credentials::CredentialStore;

/// A credential store kept in memory, so a test never reads or writes the OS
/// keyring.
#[derive(Default)]
pub struct MemoryCredentials(Mutex<HashMap<String, String>>);

impl CredentialStore for MemoryCredentials {
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

/// A credential store whose every call fails as the OS keyring does on a
/// Linux machine with no D-Bus session to reach a Secret Service over, such
/// as a server with no desktop session.
#[cfg(target_os = "linux")]
pub struct NoKeyring;

#[cfg(target_os = "linux")]
impl NoKeyring {
    fn unreachable<T>(action: &str) -> Result<T> {
        Err(anyhow::Error::new(keyring::Error::PlatformFailure(Box::new(secret_service::Error::Unavailable)))
            .context(format!("{action} in OS keyring")))
    }
}

#[cfg(target_os = "linux")]
impl CredentialStore for NoKeyring {
    fn get_token(
        &self,
        connection: &str,
    ) -> Result<Option<String>> {
        Self::unreachable(&format!("read connection '{connection}' token"))
    }

    fn set_token(
        &self,
        connection: &str,
        _token: &str,
    ) -> Result<()> {
        Self::unreachable(&format!("store connection '{connection}' token"))
    }

    fn delete_token(
        &self,
        connection: &str,
    ) -> Result<()> {
        Self::unreachable(&format!("delete connection '{connection}' token"))
    }
}
