use crate::authentication::Authenticator;
use crate::{authentication, log_utils};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use serde::Deserialize;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::RwLock;

/// A client descriptor
#[derive(Deserialize)]
pub struct Client {
    /// The client username
    pub username: String,
    /// The client password
    pub password: String,
    /// Maximum number of simultaneous HTTP/1 and HTTP/2 connections for this client.
    /// Overrides `default_max_http2_conns_per_client` from the main config.
    /// If absent, the global default applies (or unlimited if no default is set).
    pub max_http2_conns: Option<u32>,
    /// Maximum number of simultaneous HTTP/3 (QUIC) connections for this client.
    /// Overrides `default_max_http3_conns_per_client` from the main config.
    /// If absent, the global default applies (or unlimited if no default is set).
    pub max_http3_conns: Option<u32>,
}

/// The [`Authenticator`] implementation which checks presence of a client in the list.
/// Is only able to authenticate a client using the Proxy basic authorization.
pub struct RegistryBasedAuthenticator {
    clients: RwLock<HashSet<Cow<'static, str>>>,
}

impl RegistryBasedAuthenticator {
    pub fn new(clients: &[Client]) -> Self {
        Self {
            clients: RwLock::new(Self::encode_clients(clients)),
        }
    }

    fn encode_clients(clients: &[Client]) -> HashSet<Cow<'static, str>> {
        clients
            .iter()
            .map(|x| BASE64_ENGINE.encode(format!("{}:{}", x.username, x.password)))
            .map(Cow::Owned)
            .collect()
    }
}

impl Authenticator for RegistryBasedAuthenticator {
    fn authenticate(
        &self,
        source: &authentication::Source<'_>,
        _log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        let creds = match &source {
            authentication::Source::ProxyBasic(str) => str,
            authentication::Source::Sni(str) => str,
        };
        if self.clients.read().unwrap().contains(creds.as_ref()) {
            authentication::Status::Pass
        } else {
            authentication::Status::Reject
        }
    }

    fn uses_client_registry(&self) -> bool {
        true
    }

    fn reload_clients(&self, clients: &[Client]) {
        *self.clients.write().unwrap() = Self::encode_clients(clients);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_rejects_all_credentials() {
        let authenticator = RegistryBasedAuthenticator::new(&[]);
        let source = authentication::Source::ProxyBasic("anything".into());
        let id = log_utils::IdChain::<u64>::empty();

        assert!(matches!(
            authenticator.authenticate(&source, &id),
            authentication::Status::Reject
        ));
    }

    #[test]
    fn reload_replaces_registry() {
        let old = Client {
            username: "old".into(),
            password: "password".into(),
            max_http2_conns: None,
            max_http3_conns: None,
        };
        let new = Client {
            username: "new".into(),
            password: "password".into(),
            max_http2_conns: None,
            max_http3_conns: None,
        };
        let authenticator = RegistryBasedAuthenticator::new(&[old]);
        let id = log_utils::IdChain::<u64>::empty();

        authenticator.reload_clients(&[new]);
        assert!(matches!(
            authenticator.authenticate(
                &authentication::Source::ProxyBasic(BASE64_ENGINE.encode("old:password").into()),
                &id,
            ),
            authentication::Status::Reject
        ));
        assert!(matches!(
            authenticator.authenticate(
                &authentication::Source::ProxyBasic(BASE64_ENGINE.encode("new:password").into()),
                &id,
            ),
            authentication::Status::Pass
        ));
    }

    #[test]
    fn reload_can_add_first_client_to_empty_registry() {
        let authenticator = RegistryBasedAuthenticator::new(&[]);
        let client = Client {
            username: "new".into(),
            password: "password".into(),
            max_http2_conns: None,
            max_http3_conns: None,
        };
        let id = log_utils::IdChain::<u64>::empty();

        authenticator.reload_clients(&[client]);

        assert!(matches!(
            authenticator.authenticate(
                &authentication::Source::ProxyBasic(BASE64_ENGINE.encode("new:password").into()),
                &id,
            ),
            authentication::Status::Pass
        ));
    }
}
