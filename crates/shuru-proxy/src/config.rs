use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A host port exposed to the guest via host.shuru.internal.
#[derive(Debug, Clone)]
pub struct ExposeHostMapping {
    /// Port on the host (127.0.0.1:host_port).
    pub host_port: u16,
    /// Port the guest connects to (host.shuru.internal:guest_port).
    pub guest_port: u16,
}

/// Configuration for the proxy engine.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// IPv4 DNS server used for upstream queries.
    pub dns_resolver: Ipv4Addr,
    /// Secrets to inject. Key is the env var name visible to the guest.
    /// The guest gets a random placeholder token; the proxy substitutes
    /// the real value only when the request targets an allowed host.
    pub secrets: HashMap<String, SecretConfig>,
    /// Network access rules.
    pub network: NetworkConfig,
    /// Host ports exposed to the guest via host.shuru.internal.
    pub expose_host: Vec<ExposeHostMapping>,
    /// Additional CA bundle for upstream TLS validation.
    ///
    /// If unset, `SHURU_CA_BUNDLE` is also consulted. On macOS, the special
    /// value `system` exports the system roots with the `security` tool.
    pub ca_bundle: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            dns_resolver: Ipv4Addr::new(8, 8, 8, 8),
            secrets: HashMap::new(),
            network: NetworkConfig::default(),
            expose_host: Vec::new(),
        }
    }
}

/// A secret that the proxy injects into HTTP requests.
#[derive(Debug, Clone)]
pub struct SecretConfig {
    /// Host environment variable to read the real value from.
    pub from: String,
    /// Domain patterns where this secret may be sent (e.g., "api.openai.com").
    /// The proxy only substitutes the placeholder on requests to these hosts.
    pub hosts: Vec<String>,
    /// If set, use this value directly instead of reading from the host env var.
    pub value: Option<String>,
}

/// Network access policy.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// Allowed domain patterns. Empty = allow all.
    /// Supports wildcards: "*.openai.com", "registry.npmjs.org".
    pub allow: Vec<String>,
}

impl NetworkConfig {
    /// Returns true if a domain allowlist is configured.
    pub fn has_allowlist(&self) -> bool {
        !self.allow.is_empty()
    }
}

impl ProxyConfig {
    /// Check if a domain is allowed by the network policy.
    /// Empty allowlist means all domains are allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if self.network.allow.is_empty() {
            return true;
        }
        self.network
            .allow
            .iter()
            .any(|pattern| domain_matches(pattern, domain))
    }

    /// Look up whether a connection to the gateway IP on `guest_port` should
    /// be forwarded to a host port. Returns the host port if matched.
    pub fn exposed_host_port(&self, dst_ip: Ipv4Addr, guest_port: u16) -> Option<u16> {
        const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
        if dst_ip != GATEWAY {
            return None;
        }
        self.expose_host
            .iter()
            .find(|m| m.guest_port == guest_port)
            .map(|m| m.host_port)
    }

    /// Get all secret placeholder→real value mappings for a given domain.
    pub fn secrets_for_domain(
        &self,
        domain: &str,
        placeholders: &HashMap<String, String>,
    ) -> Vec<(String, String)> {
        let mut substitutions = Vec::new();
        for (name, secret) in &self.secrets {
            if secret
                .hosts
                .iter()
                .any(|pattern| domain_matches(pattern, domain))
            {
                if let Some(placeholder) = placeholders.get(name) {
                    let real_value = secret
                        .value
                        .clone()
                        .or_else(|| std::env::var(&secret.from).ok());
                    if let Some(real_value) = real_value {
                        substitutions.push((placeholder.clone(), real_value));
                    }
                }
            }
        }
        substitutions
    }
}

/// Simple wildcard domain matching.
/// "*" matches any domain (catch-all).
/// "*.example.com" matches "api.example.com" but not "example.com".
/// "example.com" matches exactly "example.com".
fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        true
    } else if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.ends_with(suffix)
            && domain.len() > suffix.len()
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
    } else {
        pattern == domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exposed_host_port() {
        use std::net::Ipv4Addr;
        let config = ProxyConfig {
            expose_host: vec![
                ExposeHostMapping {
                    host_port: 3000,
                    guest_port: 8080,
                },
                ExposeHostMapping {
                    host_port: 5432,
                    guest_port: 5432,
                },
            ],
            ..Default::default()
        };
        // Gateway IP match
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(10, 0, 0, 1), 8080),
            Some(3000)
        );
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(10, 0, 0, 1), 5432),
            Some(5432)
        );
        // No mapping for this port
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(10, 0, 0, 1), 9999),
            None
        );
        // Non-gateway IP
        assert_eq!(
            config.exposed_host_port(Ipv4Addr::new(1, 2, 3, 4), 8080),
            None
        );
    }

    #[test]
    fn test_domain_matching() {
        assert!(domain_matches("*", "anything.com"));
        assert!(domain_matches("*", "api.example.com"));
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("example.com", "api.example.com"));
        assert!(domain_matches("*.example.com", "api.example.com"));
        assert!(domain_matches("*.example.com", "deep.api.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
        assert!(!domain_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn test_has_allowlist() {
        let empty = NetworkConfig::default();
        assert!(!empty.has_allowlist());

        let with_entries = NetworkConfig {
            allow: vec!["api.example.com".into()],
        };
        assert!(with_entries.has_allowlist());
    }

    #[test]
    fn default_dns_resolver_is_google_public_dns() {
        assert_eq!(
            ProxyConfig::default().dns_resolver,
            Ipv4Addr::new(8, 8, 8, 8)
        );
    }
}
