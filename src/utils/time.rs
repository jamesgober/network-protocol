use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Returns current UNIX timestamp (seconds)
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Returns UNIX timestamp (milliseconds)
pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_millis(0))
        .as_millis()
}

/// Check if TTL has expired
pub fn expired(since: u64, ttl_secs: u64) -> bool {
    now_secs() > (since + ttl_secs)
}
