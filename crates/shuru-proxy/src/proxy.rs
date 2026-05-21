use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::Arc;

use anyhow::Context;
use boring::ssl::{SslConnector, SslMethod};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::ProxyConfig;
use crate::dns;
use crate::stack::{ConnectionId, StackCommand, StackEvent, TcpConnection};
use crate::stream::ChannelStream;
use crate::tls::CertificateAuthority;
use crate::AllowedIps;

/// The async proxy engine.
///
/// Receives events from the smoltcp NetworkStack and proxies TCP connections
/// to the real internet, with optional MITM for secret injection.
///
/// Uses BoringSSL (Chrome's TLS stack) for upstream connections so that
/// Cloudflare-protected sites accept the TLS fingerprint. The client-side
/// (guest <-> proxy) uses rustls with our generated CA cert.
pub struct ProxyEngine {
    config: Arc<ProxyConfig>,
    event_rx: mpsc::UnboundedReceiver<StackEvent>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    connections: HashMap<ConnectionId, mpsc::UnboundedSender<Vec<u8>>>,
    placeholders: Arc<HashMap<String, String>>,
    ca: Arc<tokio::sync::Mutex<CertificateAuthority>>,
    upstream_ssl: SslConnector,
    allowed_ips: AllowedIps,
}

impl ProxyEngine {
    pub fn new(
        config: ProxyConfig,
        event_rx: mpsc::UnboundedReceiver<StackEvent>,
        cmd_tx: mpsc::UnboundedSender<StackCommand>,
        ca: CertificateAuthority,
        placeholders: HashMap<String, String>,
        allowed_ips: AllowedIps,
        upstream_ssl: SslConnector,
    ) -> Self {
        ProxyEngine {
            config: Arc::new(config),
            event_rx,
            cmd_tx,
            connections: HashMap::new(),
            placeholders: Arc::new(placeholders),
            ca: Arc::new(tokio::sync::Mutex::new(ca)),
            upstream_ssl,
            allowed_ips,
        }
    }

    /// Run the proxy event loop.
    pub async fn run(&mut self) {
        info!("proxy engine started");
        while let Some(event) = self.event_rx.recv().await {
            match event {
                StackEvent::NewConnection(conn) => {
                    self.handle_new_connection(conn);
                }
                StackEvent::Data { id, payload } => {
                    if let Some(tx) = self.connections.get(&id) {
                        if tx.send(payload).is_err() {
                            self.connections.remove(&id);
                        }
                    }
                }
                StackEvent::Closed { id } => {
                    self.connections.remove(&id);
                }
                StackEvent::DnsQuery { src, payload } => {
                    let cmd_tx = self.cmd_tx.clone();
                    let config = self.config.clone();
                    let allowed_ips = self.allowed_ips.clone();
                    tokio::spawn(async move {
                        dns::handle_dns_query(src, payload, cmd_tx, &config, &allowed_ips).await;
                    });
                }
            }
        }
    }

    fn handle_new_connection(&mut self, conn: TcpConnection) {
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.connections.insert(conn.id, data_tx);

        let cmd_tx = self.cmd_tx.clone();
        let config = self.config.clone();
        let ca = self.ca.clone();
        let placeholders = self.placeholders.clone();
        let upstream_ssl = self.upstream_ssl.clone();
        let allowed_ips = self.allowed_ips.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                conn.id,
                conn.dst,
                data_rx,
                cmd_tx,
                &config,
                ca,
                &placeholders,
                upstream_ssl,
                &allowed_ips,
            )
            .await
            {
                debug!("connection to {} ended: {e}", conn.dst);
            }
        });
    }
}

/// Build the BoringSSL upstream connector.
///
/// This is only used when Shuru MITMs a TLS connection for secret injection;
/// blind-tunneled TLS remains end-to-end between the guest process and the
/// remote server.
pub(crate) fn build_upstream_ssl_connector(config: &ProxyConfig) -> anyhow::Result<SslConnector> {
    // BoringSSL upstream connector — Chrome's TLS stack so Cloudflare
    // doesn't reject our MITM connections based on JA3/JA4 fingerprint.
    let mut builder = SslConnector::builder(SslMethod::tls()).context("SslConnector")?;
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .context("set ALPN")?;

    if let Some(bundle) = config
        .ca_bundle
        .clone()
        .or_else(|| std::env::var("SHURU_CA_BUNDLE").ok())
    {
        let bundle_path = resolve_ca_bundle_path(&bundle)?;
        builder
            .set_ca_file(&bundle_path)
            .with_context(|| format!("load CA bundle {}", bundle_path.display()))?;
    }

    Ok(builder.build())
}

pub fn resolve_ca_bundle_path(value: &str) -> anyhow::Result<PathBuf> {
    if value == "system" {
        export_macos_system_ca_bundle()
    } else {
        Ok(PathBuf::from(value))
    }
}

#[cfg(target_os = "macos")]
fn export_macos_system_ca_bundle() -> anyhow::Result<PathBuf> {
    let mut pem = Vec::new();
    for keychain in macos_ca_keychains() {
        if !keychain.exists() {
            continue;
        }
        let output = Command::new("/usr/bin/security")
            .args(["find-certificate", "-a", "-p"])
            .arg(&keychain)
            .output()
            .with_context(|| format!("export certificates from {}", keychain.display()))?;
        if !output.status.success() {
            debug!(
                "failed to export certificates from {}: {}",
                keychain.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            continue;
        }
        pem.extend_from_slice(&output.stdout);
    }

    if pem.is_empty() {
        return Err(anyhow::anyhow!(
            "no certificates exported from macOS keychains"
        ));
    }

    let path = std::env::temp_dir().join(format!("shuru-system-ca-{}.pem", std::process::id()));
    std::fs::write(&path, pem).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

#[cfg(target_os = "macos")]
fn macos_ca_keychains() -> Vec<PathBuf> {
    let mut keychains = vec![
        Path::new("/System/Library/Keychains/SystemRootCertificates.keychain").to_path_buf(),
        Path::new("/Library/Keychains/System.keychain").to_path_buf(),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        keychains.push(
            Path::new(&home)
                .join("Library")
                .join("Keychains")
                .join("login.keychain-db"),
        );
    }
    keychains
}

#[cfg(not(target_os = "macos"))]
fn export_macos_system_ca_bundle() -> anyhow::Result<PathBuf> {
    Err(anyhow::anyhow!(
        "SHURU_CA_BUNDLE=system is currently only supported on macOS"
    ))
}

/// Handle a single proxied TCP connection.
async fn handle_connection(
    id: ConnectionId,
    dst: SocketAddr,
    mut data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    config: &ProxyConfig,
    ca: Arc<tokio::sync::Mutex<CertificateAuthority>>,
    placeholders: &HashMap<String, String>,
    upstream_ssl: SslConnector,
    allowed_ips: &AllowedIps,
) -> anyhow::Result<()> {
    // Check if this is a connection to an exposed host port (host.shuru.internal).
    if let std::net::IpAddr::V4(ipv4) = dst.ip() {
        if let Some(host_port) = config.exposed_host_port(ipv4, dst.port()) {
            debug!(
                "expose-host: guest :{} -> localhost:{}",
                dst.port(),
                host_port
            );
            let local_dst = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                host_port,
            );
            let upstream = TcpStream::connect(local_dst).await?;
            let (mut upstream_rd, mut upstream_wr) = upstream.into_split();
            return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
        }
    }

    // When a domain allowlist is active, only allow connections to IPs that
    // were resolved via the DNS handler. This prevents bypass via hardcoded IPs.
    // Gateway IP is always allowed so the expose-host fallback path still works;
    // unexposed gateway ports will fail later at connect().
    //
    // Uses write lock + get() so the LRU bumps recency for active IPs, keeping
    // them warm against eviction when the cache is full.
    if config.network.has_allowlist() {
        if let std::net::IpAddr::V4(ipv4) = dst.ip() {
            const GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
            let is_allowed = ipv4 == GATEWAY
                || allowed_ips
                    .write()
                    .expect("allowed_ips lock poisoned")
                    .get(&ipv4)
                    .is_some();
            if !is_allowed {
                debug!("IP not in DNS-pinned set, rejecting: {dst}");
                let _ = cmd_tx.send(StackCommand::Close { id });
                return Err(anyhow::anyhow!(
                    "connection to {dst} blocked: IP not resolved via allowed DNS"
                ));
            }
        }
    }

    let is_tls = dst.port() == 443;

    if is_tls {
        // Buffer data until we have a complete TLS ClientHello record.
        // The ClientHello may span multiple TCP segments.
        let mut tls_buf = data_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed before data"))?;

        // TLS record header: type(1) + version(2) + length(2) = 5 bytes
        // Keep reading until we have the full record
        while tls_buf.len() >= 5 {
            let record_len = u16::from_be_bytes([tls_buf[3], tls_buf[4]]) as usize;
            if tls_buf.len() >= 5 + record_len {
                break; // have the complete record
            }
            match data_rx.recv().await {
                Some(chunk) => tls_buf.extend_from_slice(&chunk),
                None => break, // connection closed
            }
        }

        let sni = extract_sni(&tls_buf);
        debug!("TLS to {dst}, SNI: {sni:?}");

        // When a domain allowlist is active, verify the SNI matches an
        // allowed domain. This prevents connecting to non-allowed services
        // that happen to share an IP with an allowed domain (e.g. CDN/Cloudflare).
        if config.network.has_allowlist() {
            match &sni {
                Some(domain) if !config.is_domain_allowed(domain) => {
                    debug!("SNI not in allowlist, rejecting: {domain}");
                    let _ = cmd_tx.send(StackCommand::Close { id });
                    return Err(anyhow::anyhow!(
                        "TLS to {dst} blocked: SNI '{domain}' not in allowlist"
                    ));
                }
                None => {
                    debug!("no SNI in ClientHello, rejecting connection to {dst}");
                    let _ = cmd_tx.send(StackCommand::Close { id });
                    return Err(anyhow::anyhow!("TLS to {dst} blocked: no SNI"));
                }
                _ => {}
            }
        }

        if let Some(domain) = sni {
            let substitutions = config.secrets_for_domain(&domain, placeholders);
            if !substitutions.is_empty() {
                debug!("MITM: {domain}");
                return handle_mitm(
                    id,
                    dst,
                    domain,
                    tls_buf,
                    data_rx,
                    cmd_tx,
                    ca,
                    substitutions,
                    upstream_ssl,
                )
                .await;
            }
        }

        // Blind tunnel: forward the buffered data and relay the rest
        debug!("blind tunnel to {dst}");
        let upstream = TcpStream::connect(dst).await?;
        let (mut upstream_rd, mut upstream_wr) = upstream.into_split();

        // Send the buffered TLS data
        upstream_wr.write_all(&tls_buf).await?;

        return blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await;
    }

    // Non-TLS: blind tunnel
    debug!("TCP tunnel to {dst}");
    let upstream = TcpStream::connect(dst).await?;
    let (mut upstream_rd, mut upstream_wr) = upstream.into_split();

    blind_relay(id, &mut upstream_rd, &mut upstream_wr, data_rx, cmd_tx).await
}

/// Blind bidirectional relay (no inspection).
async fn blind_relay(
    id: ConnectionId,
    upstream_rd: &mut tokio::net::tcp::OwnedReadHalf,
    upstream_wr: &mut tokio::net::tcp::OwnedWriteHalf,
    mut data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
) -> anyhow::Result<()> {
    let cmd_tx_clone = cmd_tx.clone();
    let upstream_to_guest = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match upstream_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if cmd_tx_clone
                        .send(StackCommand::Send {
                            id,
                            payload: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    };

    let guest_to_upstream = async {
        while let Some(payload) = data_rx.recv().await {
            if upstream_wr.write_all(&payload).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = upstream_to_guest => {},
        _ = guest_to_upstream => {},
    }

    let _ = cmd_tx.send(StackCommand::Close { id });
    Ok(())
}

/// MITM: terminate TLS on both sides, relay HTTP/1.1 with secret substitution.
async fn handle_mitm(
    id: ConnectionId,
    dst: SocketAddr,
    domain: String,
    first_chunk: Vec<u8>,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    cmd_tx: mpsc::UnboundedSender<StackCommand>,
    ca: Arc<tokio::sync::Mutex<CertificateAuthority>>,
    substitutions: Vec<(String, String)>,
    upstream_ssl: SslConnector,
) -> anyhow::Result<()> {
    let acceptor = {
        let mut ca = ca.lock().await;
        ca.acceptor_for_domain(&domain)?
    };

    let mut guest_stream = ChannelStream::new(id, data_rx, cmd_tx.clone());
    guest_stream.prepend(first_chunk);

    // Client-side: rustls with our generated CA cert
    let guest_tls = acceptor.accept(guest_stream).await?;

    // Upstream: BoringSSL — Chrome's TLS fingerprint passes Cloudflare
    let upstream_tcp = TcpStream::connect(dst).await?;
    let upstream_tls = tokio_boring::connect(upstream_ssl.configure()?, &domain, upstream_tcp)
        .await
        .map_err(|e| anyhow::anyhow!("BoringSSL connect to {domain}: {e}"))?;

    // HTTP/1.1 text-based relay with secret substitution
    let (mut guest_rd, mut guest_wr) = tokio::io::split(guest_tls);
    let (mut upstream_rd, mut upstream_wr) = tokio::io::split(upstream_tls);

    let guest_to_upstream = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match guest_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut data = buf[..n].to_vec();
                    for (placeholder, real_value) in &substitutions {
                        data = replace_bytes(&data, placeholder.as_bytes(), real_value.as_bytes());
                    }
                    if upstream_wr.write_all(&data).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let upstream_to_guest = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match upstream_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if guest_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    tokio::select! {
        _ = guest_to_upstream => {},
        _ = upstream_to_guest => {},
    }

    let _ = cmd_tx.send(StackCommand::Close { id });
    Ok(())
}

/// Replace all occurrences of `from` with `to` in a byte slice.
fn replace_bytes(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() || data.len() < from.len() {
        return data.to_vec();
    }

    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;

    while i <= data.len() - from.len() {
        if &data[i..i + from.len()] == from {
            result.extend_from_slice(to);
            i += from.len();
        } else {
            result.push(data[i]);
            i += 1;
        }
    }

    // Append remaining bytes that can't contain the pattern
    result.extend_from_slice(&data[i..]);
    result
}

/// Extract SNI from a TLS ClientHello.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None;
    }

    if hs.len() < 38 {
        return None;
    }
    let mut pos = 38;

    // Session ID
    if pos >= hs.len() {
        return None;
    }
    let session_id_len = hs[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods
    if pos >= hs.len() {
        return None;
    }
    let cm_len = hs[pos] as usize;
    pos += 1 + cm_len;

    // Extensions
    if pos + 2 > hs.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            if ext_data_len >= 5 && pos + ext_data_len <= hs.len() {
                let name_type = hs[pos + 2];
                if name_type == 0x00 {
                    let name_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;
                    if pos + 5 + name_len <= hs.len() {
                        return String::from_utf8(hs[pos + 5..pos + 5 + name_len].to_vec()).ok();
                    }
                }
            }
            return None;
        }

        pos += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_none_for_non_tls() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn test_replace_bytes() {
        assert_eq!(
            replace_bytes(b"hello world", b"world", b"rust"),
            b"hello rust"
        );
        assert_eq!(
            replace_bytes(
                b"key=shuru_tok_abc123&other=val",
                b"shuru_tok_abc123",
                b"real_secret"
            ),
            b"key=real_secret&other=val"
        );
        assert_eq!(replace_bytes(b"no match", b"xyz", b"abc"), b"no match");
        assert_eq!(replace_bytes(b"", b"x", b"y"), b"");
    }
}
