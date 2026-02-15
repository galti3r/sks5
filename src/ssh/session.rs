/// Per-client session state tracking
#[derive(Debug, Default)]
pub struct ClientSession {
    pub username: Option<String>,
    pub authenticated: bool,
    pub auth_method: String,
    pub ssh_key_fingerprint: Option<String>,
}

impl ClientSession {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_default_auth_method() {
        let session = ClientSession::new();
        assert!(session.auth_method.is_empty());
    }

    #[test]
    fn test_session_default_fingerprint() {
        let session = ClientSession::new();
        assert!(session.ssh_key_fingerprint.is_none());
    }
}
