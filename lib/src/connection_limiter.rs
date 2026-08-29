use crate::authentication::registry_based::Client;
use crate::tls_demultiplexer::Protocol;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

struct ClientEntry {
    max_http2: Option<u32>,
    max_http3: Option<u32>,
    http2_count: u32,
    http3_count: u32,
    revoked: watch::Sender<bool>,
    generation: Arc<()>,
}

struct State {
    clients: HashMap<String, ClientEntry>,
    default_max_http2: Option<u32>,
    default_max_http3: Option<u32>,
}

/// Tracks authenticated client sessions, enforces limits, and signals revocation.
pub(crate) struct ConnectionLimiter {
    state: Mutex<State>,
}

/// RAII guard that decrements the connection count when dropped.
pub(crate) struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    creds: String,
    protocol: Protocol,
    revoked: watch::Receiver<bool>,
    generation: Arc<()>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter
            .release(&self.creds, self.protocol, &self.generation);
    }
}

impl ConnectionLimiter {
    /// Creates a new ConnectionLimiter.
    pub fn new(
        clients: &[Client],
        default_max_http2: Option<u32>,
        default_max_http3: Option<u32>,
    ) -> Self {
        let clients = clients
            .iter()
            .map(|c| {
                let key = BASE64_ENGINE.encode(format!("{}:{}", c.username, c.password));
                let (revoked, _receiver) = watch::channel(false);
                (
                    key,
                    ClientEntry {
                        max_http2: c.max_http2_conns,
                        max_http3: c.max_http3_conns,
                        http2_count: 0,
                        http3_count: 0,
                        revoked,
                        generation: Arc::new(()),
                    },
                )
            })
            .collect();

        Self {
            state: Mutex::new(State {
                clients,
                default_max_http2,
                default_max_http3,
            }),
        }
    }

    pub fn reload(
        &self,
        clients: &[Client],
        default_max_http2: Option<u32>,
        default_max_http3: Option<u32>,
    ) {
        let mut state = self.state.lock().unwrap();
        let mut old = std::mem::take(&mut state.clients);
        let mut next = HashMap::with_capacity(clients.len());

        for client in clients {
            let credentials =
                BASE64_ENGINE.encode(format!("{}:{}", client.username, client.password));
            let entry = match old.remove(&credentials) {
                Some(mut entry) => {
                    entry.max_http2 = client.max_http2_conns;
                    entry.max_http3 = client.max_http3_conns;
                    entry
                }
                None => {
                    let (revoked, _receiver) = watch::channel(false);
                    ClientEntry {
                        max_http2: client.max_http2_conns,
                        max_http3: client.max_http3_conns,
                        http2_count: 0,
                        http3_count: 0,
                        revoked,
                        generation: Arc::new(()),
                    }
                }
            };
            next.insert(credentials, entry);
        }

        for entry in old.into_values() {
            entry.revoked.send_replace(true);
        }

        state.clients = next;
        state.default_max_http2 = default_max_http2;
        state.default_max_http3 = default_max_http3;
    }

    /// Try to acquire a connection slot for the given credentials and protocol.
    ///
    /// Returns `Some(guard)` on success — the guard releases the slot on drop.
    /// Returns `None` if the per-client limit is exceeded.
    /// Returns `None` for unknown credentials (should not happen after authentication).
    pub fn try_acquire(
        self: &Arc<Self>,
        creds: &str,
        protocol: Protocol,
    ) -> Option<ConnectionGuard> {
        let mut state = self.state.lock().unwrap();
        let default_max_http2 = state.default_max_http2;
        let default_max_http3 = state.default_max_http3;

        let entry = state.clients.get_mut(creds)?;

        let (current, limit) = match protocol {
            Protocol::Http1 | Protocol::Http2 => {
                let limit = entry.max_http2.or(default_max_http2);
                (&mut entry.http2_count, limit)
            }
            Protocol::Http3 => {
                let limit = entry.max_http3.or(default_max_http3);
                (&mut entry.http3_count, limit)
            }
        };

        if let Some(max) = limit {
            if *current >= max {
                return None;
            }
        }

        *current += 1;
        let revoked = entry.revoked.subscribe();
        let generation = entry.generation.clone();
        Some(ConnectionGuard {
            limiter: self.clone(),
            creds: creds.to_owned(),
            protocol,
            revoked,
            generation,
        })
    }

    fn release(&self, creds: &str, protocol: Protocol, generation: &Arc<()>) {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.clients.get_mut(creds) {
            if !Arc::ptr_eq(&entry.generation, generation) {
                return;
            }
            match protocol {
                Protocol::Http1 | Protocol::Http2 => {
                    entry.http2_count = entry.http2_count.saturating_sub(1);
                }
                Protocol::Http3 => {
                    entry.http3_count = entry.http3_count.saturating_sub(1);
                }
            }
        }
    }
}

impl ConnectionGuard {
    pub fn matches_credentials(&self, source: &crate::authentication::Source<'_>) -> bool {
        match source {
            crate::authentication::Source::ProxyBasic(credentials)
            | crate::authentication::Source::Sni(credentials) => self.creds == credentials.as_ref(),
        }
    }

    pub fn revocation_receiver(&self) -> watch::Receiver<bool> {
        self.revoked.clone()
    }

    pub async fn wait_for_revocation(receiver: &mut watch::Receiver<bool>) {
        loop {
            if *receiver.borrow() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::registry_based::Client;

    fn make_client(username: &str, password: &str) -> Client {
        Client {
            username: username.into(),
            password: password.into(),
            max_http2_conns: None,
            max_http3_conns: None,
        }
    }

    fn make_client_with_limits(
        username: &str,
        password: &str,
        h2: Option<u32>,
        h3: Option<u32>,
    ) -> Client {
        Client {
            username: username.into(),
            password: password.into(),
            max_http2_conns: h2,
            max_http3_conns: h3,
        }
    }

    fn creds(username: &str, password: &str) -> String {
        BASE64_ENGINE.encode(format!("{}:{}", username, password))
    }

    #[test]
    fn no_limits_always_passes() {
        let limiter = Arc::new(ConnectionLimiter::new(&[make_client("u", "p")], None, None));
        let key = creds("u", "p");
        let g1 = limiter.try_acquire(&key, Protocol::Http2).unwrap();
        let g2 = limiter.try_acquire(&key, Protocol::Http2).unwrap();
        let g3 = limiter.try_acquire(&key, Protocol::Http3).unwrap();
        drop((g1, g2, g3));
    }

    #[test]
    fn global_http2_limit_enforced() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("u", "p")],
            Some(2),
            None,
        ));
        let key = creds("u", "p");

        let g1 = limiter.try_acquire(&key, Protocol::Http2).unwrap();
        let g2 = limiter.try_acquire(&key, Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire(&key, Protocol::Http2).is_none(),
            "must be denied at limit=2"
        );

        drop(g1);
        let g3 = limiter.try_acquire(&key, Protocol::Http2).unwrap();
        drop((g2, g3));
    }

    #[test]
    fn global_http3_limit_enforced() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("u", "p")],
            None,
            Some(1),
        ));
        let key = creds("u", "p");

        let g1 = limiter.try_acquire(&key, Protocol::Http3).unwrap();
        assert!(
            limiter.try_acquire(&key, Protocol::Http3).is_none(),
            "must be denied at limit=1"
        );

        drop(g1);
        limiter.try_acquire(&key, Protocol::Http3).unwrap();
    }

    #[test]
    fn http2_and_http3_counters_are_independent() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("u", "p")],
            Some(1),
            Some(1),
        ));
        let key = creds("u", "p");

        let _g2 = limiter.try_acquire(&key, Protocol::Http2).unwrap();
        let _g3 = limiter.try_acquire(&key, Protocol::Http3).unwrap();
        assert!(
            limiter.try_acquire(&key, Protocol::Http2).is_none(),
            "http2 must be at limit"
        );
        assert!(
            limiter.try_acquire(&key, Protocol::Http3).is_none(),
            "http3 must be at limit"
        );
    }

    #[test]
    fn per_client_override_takes_precedence_over_global() {
        let clients = vec![
            make_client_with_limits("alice", "pass", Some(5), None),
            make_client("bob", "pass"),
        ];
        let limiter = Arc::new(ConnectionLimiter::new(&clients, Some(1), None));

        let alice = creds("alice", "pass");
        let bob = creds("bob", "pass");

        let _a1 = limiter.try_acquire(&alice, Protocol::Http2).unwrap();
        let _a2 = limiter.try_acquire(&alice, Protocol::Http2).unwrap();
        let _a3 = limiter.try_acquire(&alice, Protocol::Http2).unwrap();
        let _a4 = limiter.try_acquire(&alice, Protocol::Http2).unwrap();
        let _a5 = limiter.try_acquire(&alice, Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire(&alice, Protocol::Http2).is_none(),
            "alice: must be denied at override limit=5"
        );

        let _b1 = limiter.try_acquire(&bob, Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire(&bob, Protocol::Http2).is_none(),
            "bob: must be denied at global limit=1"
        );
    }

    #[test]
    fn limits_are_per_client_not_shared() {
        let clients = vec![make_client("alice", "pass"), make_client("bob", "pass")];
        let limiter = Arc::new(ConnectionLimiter::new(&clients, Some(1), None));

        let alice = creds("alice", "pass");
        let bob = creds("bob", "pass");

        let _ga = limiter.try_acquire(&alice, Protocol::Http2).unwrap();
        let _gb = limiter.try_acquire(&bob, Protocol::Http2).unwrap();
        assert!(
            limiter.try_acquire(&alice, Protocol::Http2).is_none(),
            "alice at limit"
        );
        assert!(
            limiter.try_acquire(&bob, Protocol::Http2).is_none(),
            "bob at limit"
        );
    }

    #[test]
    fn unknown_credentials_denied() {
        let limiter = Arc::new(ConnectionLimiter::new(&[make_client("u", "p")], None, None));
        assert!(limiter
            .try_acquire("unknown_creds", Protocol::Http2)
            .is_none());
    }

    #[tokio::test]
    async fn removing_client_revokes_existing_guards() {
        let limiter = Arc::new(ConnectionLimiter::new(&[make_client("u", "p")], None, None));
        let guard = limiter
            .try_acquire(&creds("u", "p"), Protocol::Http2)
            .unwrap();
        let mut revoked = guard.revocation_receiver();

        limiter.reload(&[], None, None);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            ConnectionGuard::wait_for_revocation(&mut revoked),
        )
        .await
        .unwrap();
    }

    #[test]
    fn reload_can_add_first_client_to_empty_registry() {
        let limiter = Arc::new(ConnectionLimiter::new(&[], Some(1), Some(1)));
        let key = creds("u", "p");

        assert!(limiter.try_acquire(&key, Protocol::Http2).is_none());
        limiter.reload(&[make_client("u", "p")], Some(1), Some(1));

        assert!(limiter.try_acquire(&key, Protocol::Http2).is_some());
    }

    #[tokio::test]
    async fn changing_password_revokes_old_credentials_and_allows_new_credentials() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("u", "old")],
            Some(1),
            None,
        ));
        let old_guard = limiter
            .try_acquire(&creds("u", "old"), Protocol::Http2)
            .unwrap();
        let mut revoked = old_guard.revocation_receiver();

        limiter.reload(&[make_client("u", "new")], Some(1), None);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            ConnectionGuard::wait_for_revocation(&mut revoked),
        )
        .await
        .unwrap();
        assert!(limiter
            .try_acquire(&creds("u", "old"), Protocol::Http2)
            .is_none());
        assert!(limiter
            .try_acquire(&creds("u", "new"), Protocol::Http2)
            .is_some());
    }

    #[tokio::test]
    async fn removing_one_client_does_not_revoke_retained_client() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("kept", "p"), make_client("removed", "p")],
            Some(1),
            None,
        ));
        let kept_guard = limiter
            .try_acquire(&creds("kept", "p"), Protocol::Http2)
            .unwrap();
        let removed_guard = limiter
            .try_acquire(&creds("removed", "p"), Protocol::Http2)
            .unwrap();
        let mut removed = removed_guard.revocation_receiver();

        limiter.reload(&[make_client("kept", "p")], Some(1), None);

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            ConnectionGuard::wait_for_revocation(&mut removed),
        )
        .await
        .unwrap();
        assert!(!*kept_guard.revocation_receiver().borrow());
        assert!(limiter
            .try_acquire(&creds("kept", "p"), Protocol::Http2)
            .is_none());
    }

    #[test]
    fn retaining_client_preserves_active_count_and_session() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("u", "p")],
            Some(1),
            None,
        ));
        let guard = limiter
            .try_acquire(&creds("u", "p"), Protocol::Http2)
            .unwrap();

        limiter.reload(&[make_client("u", "p")], Some(1), None);

        assert!(!*guard.revocation_receiver().borrow());
        assert!(limiter
            .try_acquire(&creds("u", "p"), Protocol::Http2)
            .is_none());
    }

    #[test]
    fn old_guard_does_not_release_readded_client_slot() {
        let limiter = Arc::new(ConnectionLimiter::new(
            &[make_client("u", "p")],
            Some(1),
            None,
        ));
        let old_guard = limiter
            .try_acquire(&creds("u", "p"), Protocol::Http2)
            .unwrap();
        limiter.reload(&[], Some(1), None);
        limiter.reload(&[make_client("u", "p")], Some(1), None);
        let new_guard = limiter
            .try_acquire(&creds("u", "p"), Protocol::Http2)
            .unwrap();

        drop(old_guard);

        assert!(limiter
            .try_acquire(&creds("u", "p"), Protocol::Http2)
            .is_none());
        drop(new_guard);
    }
}
