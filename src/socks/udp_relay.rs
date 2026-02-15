//! SOCKS5 UDP relay module (RFC 1928 section 7)
//!
//! When a client sends CMD_UDP_ASSOCIATE, the server binds a UDP socket
//! and relays datagrams between the client and remote hosts.
//! The TCP control connection is kept open; when it closes, the relay stops.

use crate::socks::protocol::{TargetAddr, UdpHeader};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Maximum UDP datagram size we handle (64 KiB is the theoretical UDP max)
const MAX_DATAGRAM_SIZE: usize = 65535;

/// A UDP relay session handles bidirectional UDP forwarding.
pub struct UdpRelaySession {
    /// The local UDP socket bound for this relay session.
    pub local_socket: Arc<UdpSocket>,
    /// The address the local socket is bound to (sent to client in reply).
    pub bind_addr: SocketAddr,
    /// The expected client address for this relay.
    pub client_addr: SocketAddr,
    /// Cancellation token to stop the relay when TCP closes.
    pub cancel: CancellationToken,
}

impl UdpRelaySession {
    /// Create a new UDP relay session.
    /// Binds a UDP socket on the same IP as the TCP listener.
    pub async fn new(bind_ip: std::net::IpAddr, client_addr: SocketAddr) -> Result<Self> {
        // Bind on port 0 to get an ephemeral port
        let bind_addr = SocketAddr::new(bind_ip, 0);
        let socket = UdpSocket::bind(bind_addr).await?;
        let actual_addr = socket.local_addr()?;

        Ok(Self {
            local_socket: Arc::new(socket),
            bind_addr: actual_addr,
            client_addr,
            cancel: CancellationToken::new(),
        })
    }

    /// Run the relay loop. Returns when cancelled or on error.
    /// `idle_timeout` controls how long to wait without datagrams before stopping.
    pub async fn run(
        self,
        idle_timeout: Duration,
        username: String,
        metrics: Option<Arc<crate::metrics::MetricsRegistry>>,
    ) {
        let socket = self.local_socket.clone();
        let client_addr = self.client_addr;
        let cancel = self.cancel.clone();

        // We use a single socket for both client and remote communication.
        // Client datagrams arrive with the SOCKS5 UDP header.
        // Remote datagrams arrive without the header and need to be encapsulated.
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

        // Track the remote address for the last forwarded datagram
        // (simplified: we only support one remote endpoint at a time for responses)
        let mut last_remote: Option<SocketAddr> = None;

        loop {
            let recv_result = tokio::select! {
                _ = cancel.cancelled() => {
                    debug!(user = %username, "UDP relay cancelled (TCP closed)");
                    return;
                }
                result = tokio::time::timeout(idle_timeout, socket.recv_from(&mut buf)) => {
                    match result {
                        Ok(r) => r,
                        Err(_) => {
                            debug!(user = %username, "UDP relay idle timeout");
                            return;
                        }
                    }
                }
            };

            match recv_result {
                Ok((n, src)) => {
                    if src.ip() == client_addr.ip() {
                        // Datagram from client: parse header, forward payload to remote
                        match UdpHeader::parse(&buf[..n]) {
                            Ok((header, header_len)) => {
                                // Drop fragmented datagrams (RFC allows this)
                                if header.frag != 0 {
                                    debug!(user = %username, frag = header.frag, "Dropping fragmented UDP datagram");
                                    continue;
                                }

                                let payload = &buf[header_len..n];
                                let remote_host = header.target.host_string();
                                let remote_port = header.target.port();

                                // S-3: Validate domain names in UDP datagrams before DNS resolution
                                if let crate::socks::protocol::TargetAddr::Domain(ref domain, _) =
                                    header.target
                                {
                                    if let Err(reason) =
                                        crate::socks::protocol::validate_domain(domain)
                                    {
                                        warn!(user = %username, domain = %domain, reason = %reason, "UDP relay rejected: invalid domain");
                                        continue;
                                    }
                                }

                                // Resolve and forward
                                match tokio::net::lookup_host(format!(
                                    "{}:{}",
                                    remote_host, remote_port
                                ))
                                .await
                                {
                                    Ok(mut addrs) => {
                                        if let Some(remote_addr) = addrs.next() {
                                            if let Err(e) =
                                                socket.send_to(payload, remote_addr).await
                                            {
                                                warn!(user = %username, error = %e, "UDP relay send to remote failed");
                                            } else {
                                                last_remote = Some(remote_addr);
                                                if let Some(ref m) = metrics {
                                                    m.record_bytes_transferred(
                                                        &username,
                                                        payload.len() as u64,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(user = %username, target = %format!("{}:{}", remote_host, remote_port), error = %e, "UDP relay DNS resolution failed");
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(user = %username, error = %e, "Invalid UDP header from client");
                            }
                        }
                    } else if last_remote == Some(src) {
                        // Datagram from remote: encapsulate with header, send to client
                        let payload = &buf[..n];
                        let header = UdpHeader {
                            frag: 0,
                            target: match src {
                                SocketAddr::V4(a) => TargetAddr::Ipv4(a.ip().octets(), a.port()),
                                SocketAddr::V6(a) => TargetAddr::Ipv6(a.ip().octets(), a.port()),
                            },
                        };

                        let mut encapsulated = header.serialize();
                        encapsulated.extend_from_slice(payload);

                        if let Err(e) = socket.send_to(&encapsulated, client_addr).await {
                            warn!(user = %username, error = %e, "UDP relay send to client failed");
                        } else if let Some(ref m) = metrics {
                            m.record_bytes_transferred(&username, payload.len() as u64);
                        }
                    } else {
                        // Ignore datagrams from unknown sources
                        debug!(user = %username, src = %src, "Ignoring UDP datagram from unknown source");
                    }
                }
                Err(e) => {
                    warn!(user = %username, error = %e, "UDP relay recv error");
                    return;
                }
            }
        }
    }
}
