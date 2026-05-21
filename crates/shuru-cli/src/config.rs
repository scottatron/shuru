use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Deserialize;

#[derive(Default, Deserialize)]
pub(crate) struct ShuruConfig {
    pub cpus: Option<usize>,
    pub memory: Option<u64>,
    pub disk_size: Option<u64>,
    pub allow_net: Option<bool>,
    pub allow_host_writes: Option<bool>,
    pub ports: Option<Vec<String>>,
    pub mounts: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    pub secrets: Option<HashMap<String, SecretEntry>>,
    pub network: Option<NetworkEntry>,
    /// Additional CA bundle for proxy upstream TLS ("system" on macOS, or a PEM path).
    pub ca_bundle: Option<String>,
    /// Host ports to expose to the guest (e.g. "3000:8080" or "5432").
    pub expose_host: Option<Vec<String>>,
}

/// A secret to inject via the proxy.
/// Example: `{ "from": "OPENAI_API_KEY", "hosts": ["api.openai.com"] }`
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SecretEntry {
    /// Host environment variable containing the real value.
    pub from: String,
    /// Domains where this secret may be sent.
    pub hosts: Vec<String>,
}

/// Network access policy.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct NetworkEntry {
    /// Allowed domain patterns. Empty or absent = allow all.
    pub allow: Option<Vec<String>>,
}

impl ShuruConfig {
    /// Convert config sections into a ProxyConfig for shuru-proxy.
    pub fn to_proxy_config(&self) -> shuru_proxy::config::ProxyConfig {
        let mut proxy = shuru_proxy::config::ProxyConfig::default();

        if let Some(ref secrets) = self.secrets {
            for (name, entry) in secrets {
                proxy.secrets.insert(
                    name.clone(),
                    shuru_proxy::config::SecretConfig {
                        from: entry.from.clone(),
                        hosts: entry.hosts.clone(),
                        value: None,
                    },
                );
            }
        }

        if let Some(ref network) = self.network {
            if let Some(ref allow) = network.allow {
                proxy.network.allow = allow.clone();
            }
        }

        proxy.ca_bundle = self.ca_bundle.clone();

        if let Some(ref expose) = self.expose_host {
            for s in expose {
                if let Ok(mapping) = parse_expose_host(s) {
                    proxy.expose_host.push(mapping);
                }
            }
        }

        proxy
    }
}

/// Parse "HOST_PORT:GUEST_PORT" or "PORT" into an ExposeHostMapping.
pub(crate) fn parse_expose_host(s: &str) -> Result<shuru_proxy::config::ExposeHostMapping> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => {
            let port: u16 = parts[0]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port: '{}'", parts[0]))?;
            Ok(shuru_proxy::config::ExposeHostMapping {
                host_port: port,
                guest_port: port,
            })
        }
        2 => {
            let host_port: u16 = parts[0]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid host port: '{}'", parts[0]))?;
            let guest_port: u16 = parts[1]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid guest port: '{}'", parts[1]))?;
            Ok(shuru_proxy::config::ExposeHostMapping {
                host_port,
                guest_port,
            })
        }
        _ => bail!("expected HOST_PORT:GUEST_PORT or PORT format"),
    }
}

pub(crate) fn load_config(config_flag: Option<&str>) -> Result<ShuruConfig> {
    let path = match config_flag {
        Some(p) => std::path::PathBuf::from(p),
        None => std::path::PathBuf::from("shuru.json"),
    };

    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let cfg: ShuruConfig = serde_json::from_str(&contents)
                .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
            Ok(cfg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if config_flag.is_some() {
                bail!("Config file not found: {}", path.display());
            }
            Ok(ShuruConfig::default())
        }
        Err(e) => bail!("Failed to read {}: {}", path.display(), e),
    }
}
