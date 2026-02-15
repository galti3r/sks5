use crate::audit::AuditLogger;
use crate::proxy::LiveSession;
use crate::quota::{QuotaConfig, QuotaTracker, UserBandwidthState};
use anyhow::Result;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

/// Buffer size for relay read operations (8 KiB)
const RELAY_BUFFER_SIZE: usize = 8192;

/// Conversion factor from kilobits/s to bytes/s: 1 kbps = 1000 bits/s = 125 bytes/s
const KILOBITS_TO_BYTES_PER_SEC: f64 = 1000.0 / 8.0;

/// Configuration for a relay session, consolidating all throttle/quota parameters.
pub struct RelayConfig {
    pub idle_timeout: Duration,
    pub context: String,
    pub per_conn_bandwidth_kbps: u64,
    pub aggregate_bandwidth_kbps: u64,
    pub quota_tracker: Option<Arc<QuotaTracker>>,
    pub username: Option<String>,
    pub quotas: Option<QuotaConfig>,
    pub audit: Option<Arc<AuditLogger>>,
    pub session: Option<Arc<LiveSession>>,
}

/// Parameters for one direction of a relay, owned by the spawned task.
struct DirectionParams {
    timeout: Duration,
    context: String,
    per_conn_bw: u64,
    agg_bw: u64,
    quota_tracker: Option<Arc<QuotaTracker>>,
    username: Option<String>,
    quotas: Option<Arc<QuotaConfig>>,
    direction: &'static str,
    audit: Option<Arc<AuditLogger>>,
    session: Option<Arc<LiveSession>>,
    direction_is_upload: bool,
    /// Pre-fetched user bandwidth state to avoid DashMap lookup per chunk.
    cached_user_state: Option<Arc<UserBandwidthState>>,
}

/// Relay data in one direction: reader → writer, with idle timeout, throttling, and quota enforcement.
async fn relay_one_direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    params: DirectionParams,
) -> u64 {
    let mut total = 0u64;
    let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
    loop {
        match tokio::time::timeout(
            params.timeout,
            tokio::io::AsyncReadExt::read(&mut reader, &mut buf),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if tokio::io::AsyncWriteExt::write_all(&mut writer, &buf[..n])
                    .await
                    .is_err()
                {
                    break;
                }
                total += n as u64;

                // Update live session byte counters
                if let Some(ref session) = params.session {
                    if params.direction_is_upload {
                        session.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                    } else {
                        session.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }

                let delay = if let (Some(qt), Some(cached_state)) =
                    (&params.quota_tracker, &params.cached_user_state)
                {
                    match qt.record_bytes_cached(
                        cached_state,
                        n as u64,
                        params.per_conn_bw,
                        params.agg_bw,
                        params.quotas.as_deref(),
                    ) {
                        crate::quota::QuotaResult::Ok(d) => d,
                        crate::quota::QuotaResult::Exceeded(reason) => {
                            debug!(context = %params.context, reason = %reason, direction = params.direction, "Quota exceeded, terminating relay");
                            if let (Some(ref audit), Some(ref username)) =
                                (&params.audit, &params.username)
                            {
                                audit.log_quota_exceeded(username, &reason, 0, 0);
                            }
                            break;
                        }
                    }
                } else if params.per_conn_bw > 0 {
                    let bytes_per_sec = params.per_conn_bw as f64 * KILOBITS_TO_BYTES_PER_SEC;
                    let delay_secs = n as f64 / bytes_per_sec;
                    if delay_secs > 0.001 {
                        Duration::from_secs_f64(delay_secs)
                    } else {
                        Duration::ZERO
                    }
                } else {
                    Duration::ZERO
                };

                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {
                debug!(context = %params.context, direction = params.direction, "Relay idle timeout");
                break;
            }
        }
    }
    total
}

/// Bidirectional relay between two streams with idle timeout, bandwidth throttling, and quota enforcement.
/// Returns (bytes_uploaded, bytes_downloaded) — upload = A→B, download = B→A.
pub async fn relay<A, B>(stream_a: A, stream_b: B, config: RelayConfig) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let effective_timeout = if config.idle_timeout.is_zero() {
        Duration::from_secs(365 * 24 * 3600)
    } else {
        config.idle_timeout
    };
    let start = Instant::now();

    let (a_read, a_write) = tokio::io::split(stream_a);
    let (b_read, b_write) = tokio::io::split(stream_b);

    // Wrap quotas in Arc once, shared between both relay directions to avoid cloning
    let shared_quotas = config.quotas.map(Arc::new);

    // Pre-fetch user bandwidth state to avoid DashMap lookup per 8KiB chunk
    let cached_user_state = match (&config.quota_tracker, &config.username) {
        (Some(qt), Some(username)) => Some(qt.get_user(username)),
        _ => None,
    };

    let ab_params = DirectionParams {
        timeout: effective_timeout,
        context: config.context.clone(),
        per_conn_bw: config.per_conn_bandwidth_kbps,
        agg_bw: config.aggregate_bandwidth_kbps,
        quota_tracker: config.quota_tracker.clone(),
        username: config.username.clone(),
        quotas: shared_quotas.clone(),
        direction: "a->b",
        audit: config.audit.clone(),
        session: config.session.clone(),
        direction_is_upload: true,
        cached_user_state: cached_user_state.clone(),
    };

    let ba_params = DirectionParams {
        timeout: effective_timeout,
        context: config.context.clone(),
        per_conn_bw: config.per_conn_bandwidth_kbps,
        agg_bw: config.aggregate_bandwidth_kbps,
        quota_tracker: config.quota_tracker,
        username: config.username,
        quotas: shared_quotas,
        direction: "b->a",
        audit: config.audit,
        session: config.session,
        direction_is_upload: false,
        cached_user_state,
    };

    let a_to_b = tokio::spawn(relay_one_direction(a_read, b_write, ab_params));
    let b_to_a = tokio::spawn(relay_one_direction(b_read, a_write, ba_params));

    let (ab_result, ba_result) = tokio::join!(a_to_b, b_to_a);

    let bytes_up = match ab_result {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, context = %config.context, "Relay panic (a->b)");
            0
        }
    };
    let bytes_down = match ba_result {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, context = %config.context, "Relay panic (b->a)");
            0
        }
    };
    let duration_ms = start.elapsed().as_millis() as u64;

    info!(
        bytes_up = bytes_up,
        bytes_down = bytes_down,
        duration_ms = duration_ms,
        context = %config.context,
        "Relay completed"
    );

    Ok((bytes_up, bytes_down))
}
