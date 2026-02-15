pub mod types;

use crate::config::types::WebhookConfig;
use crate::proxy::ip_guard;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, warn};
use types::WebhookPayload;

/// Maximum concurrent webhook deliveries
const MAX_CONCURRENT_DELIVERIES: usize = 100;

/// Async webhook dispatcher with retry and DNS rebinding protection
pub struct WebhookDispatcher {
    configs: Vec<WebhookConfig>,
    client: reqwest::Client,
    semaphore: Arc<Semaphore>,
}

impl WebhookDispatcher {
    pub fn new(configs: Vec<WebhookConfig>) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            configs,
            client,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
        }
    }

    /// Send webhook event (fire and forget with retry)
    pub fn dispatch(&self, event_type: &str, data: serde_json::Value) {
        let payload = WebhookPayload {
            event_type: event_type.to_string(),
            timestamp: chrono::Utc::now(),
            data,
        };

        for config in &self.configs {
            if !config.events.is_empty() && !config.events.contains(&event_type.to_string()) {
                continue;
            }

            let client = self.client.clone();
            let url = config.url.clone();
            let secret = config.secret.clone();
            let payload = payload.clone();
            let max_retries = config.max_retries;
            let retry_delay_ms = config.retry_delay_ms;
            let max_retry_delay_ms = config.max_retry_delay_ms;
            let allow_private_ips = config.allow_private_ips;
            let semaphore = self.semaphore.clone();

            tokio::spawn(async move {
                // Acquire semaphore permit (bounded concurrency)
                let _permit = match semaphore.acquire().await {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(url = %url, "Webhook semaphore closed, dropping delivery");
                        return;
                    }
                };

                // P2-4: DNS rebinding protection — resolve, check, and pin IP
                let pinned_ip = match check_webhook_dns(&url, allow_private_ips).await {
                    Ok(pin) => pin,
                    Err(e) => {
                        warn!(url = %url, error = %e, "Webhook DNS rebinding check failed");
                        return;
                    }
                };

                // If we have a pinned IP, build a per-request client that resolves
                // the hostname to the validated IP, preventing DNS rebinding TOCTOU.
                let pinned_client = if let Some((ref host, addr)) = pinned_ip {
                    match reqwest::Client::builder()
                        .connect_timeout(std::time::Duration::from_secs(5))
                        .timeout(std::time::Duration::from_secs(10))
                        .redirect(reqwest::redirect::Policy::none())
                        .resolve(host, addr)
                        .build()
                    {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(url = %url, error = %e, "Failed to build pinned HTTP client");
                            return;
                        }
                    }
                } else {
                    client.clone()
                };

                // Retry loop with exponential backoff
                let mut attempt = 0u32;
                loop {
                    match send_webhook(&pinned_client, &url, &secret, &payload).await {
                        Ok(()) => {
                            debug!(url = %url, event = %payload.event_type, attempt = attempt, "Webhook delivered");
                            return;
                        }
                        Err(e) => {
                            if attempt >= max_retries {
                                warn!(url = %url, error = %e, attempts = attempt + 1, "Webhook delivery failed after retries");
                                return;
                            }
                            let delay_ms =
                                (retry_delay_ms * 2u64.pow(attempt)).min(max_retry_delay_ms);
                            warn!(url = %url, error = %e, attempt = attempt, next_retry_ms = delay_ms, "Webhook delivery failed, retrying");
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            attempt += 1;
                        }
                    }
                }
            });
        }
    }
}

/// P2-4: Resolve webhook URL hostname and verify all IPs against ip_guard.
/// Returns the first validated IP address for connection pinning (TOCTOU prevention).
async fn check_webhook_dns(
    url_str: &str,
    allow_private_ips: bool,
) -> anyhow::Result<Option<(String, std::net::SocketAddr)>> {
    if allow_private_ips {
        return Ok(None);
    }

    let parsed = url::Url::parse(url_str)?;
    let host = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return Ok(None),
    };

    // If it's already an IP, check directly
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        if ip_guard::is_dangerous_ip(&ip) {
            anyhow::bail!("webhook target IP {} is private/reserved", ip);
        }
        return Ok(None); // No pinning needed for direct IP URLs
    }

    // Resolve hostname and check all addresses
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addr_str = format!("{}:{}", host, port);

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map(|iter| iter.collect())
        .unwrap_or_default();

    for addr in &addrs {
        if ip_guard::is_dangerous_ip(&addr.ip()) {
            anyhow::bail!(
                "webhook hostname {} resolved to private/reserved IP {}",
                host,
                addr.ip()
            );
        }
    }

    // Return the host and first validated address for connection pinning
    if let Some(addr) = addrs.first() {
        Ok(Some((host, *addr)))
    } else {
        Ok(None)
    }
}

async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    secret: &Option<String>,
    payload: &WebhookPayload,
) -> anyhow::Result<()> {
    let body = serde_json::to_string(payload)?;

    let mut request = client.post(url).header("Content-Type", "application/json");

    if let Some(secret) = secret {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
        mac.update(body.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        request = request.header("X-Signature-256", format!("sha256={}", signature));
    }

    let response = request.body(body).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("webhook returned status {}", response.status());
    }

    Ok(())
}
