//! The single egress chokepoint.
//!
//! Every adapter routes network through one shared `Egress`. The allowlist is
//! the union of active adapters' declared endpoints. The in-process host check
//! here is the only enforcement today and the source of the trust-panel request
//! log. A CI network sandbox that fails the build on any connection outside the
//! allowlist is planned, not built.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

/// How long a response may stay silent. A long download keeps resetting it, while
/// a stalled one fails instead of holding a run past its stop button.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long opening a connection may take. A network that drops packets otherwise
/// holds each attempt until the read timeout ends it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("blocked: host '{0}' is not on the egress allowlist")]
    Blocked(String),
    #[error("request has no host")]
    NoHost,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct EgressRecord {
    pub host: String,
    pub method: String,
    pub allowed: bool,
    pub at_epoch_secs: u64,
}

pub struct Egress {
    client: reqwest::Client,
    allow: HashSet<String>,
    log: Mutex<Vec<EgressRecord>>,
}

impl Egress {
    pub fn new(allow: impl IntoIterator<Item = String>) -> Self {
        Self::with_timeouts(allow, CONNECT_TIMEOUT, READ_TIMEOUT)
    }

    fn with_timeouts(
        allow: impl IntoIterator<Item = String>,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("lethe/", env!("CARGO_PKG_VERSION")))
            .use_rustls_tls()
            .connect_timeout(connect_timeout)
            .read_timeout(read_timeout)
            .build()
            .expect("reqwest client");
        Self {
            client,
            allow: allow.into_iter().collect(),
            log: Mutex::new(Vec::new()),
        }
    }

    pub fn allows(&self, host: &str) -> bool {
        self.allow.contains(host)
    }

    /// Hand a shared client to an SDK that insists on its own (e.g. atrium's
    /// `ReqwestClient`). Prefer `execute`: requests sent on this client skip the
    /// allowlist check. TODO(net): wrap in a host-enforcing tower middleware so the
    /// in-process guarantee matches the sandbox.
    pub fn client(&self) -> reqwest::Client {
        self.client.clone()
    }

    /// Allowlist-checked send. Logs every attempt (allowed or blocked) for the
    /// trust panel.
    pub async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, EgressError> {
        let host = req
            .url()
            .host_str()
            .ok_or(EgressError::NoHost)?
            .to_owned();
        let allowed = self.allows(&host);
        self.log.lock().push(EgressRecord {
            host: host.clone(),
            method: req.method().to_string(),
            allowed,
            at_epoch_secs: now_secs(),
        });
        if !allowed {
            return Err(EgressError::Blocked(host));
        }
        Ok(self.client.execute(req).await?)
    }

    /// Snapshot of the request log (trust-panel data source).
    pub fn log(&self) -> Vec<EgressRecord> {
        self.log.lock().clone()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Sends `reply` to the first connection, then goes silent without closing it.
    async fn server_going_silent_after(reply: &'static [u8]) -> std::net::SocketAddr {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = server.accept().await.unwrap();
            socket.write_all(reply).await.unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        addr
    }

    /// A listener that never accepts, with its queue full, so Linux drops new
    /// connection attempts unanswered, as a network that loses packets does. It keeps
    /// dropping them while it lives.
    #[cfg(target_os = "linux")]
    struct ServerDroppingNewConnections {
        addr: std::net::SocketAddr,
        _listener: tokio::net::TcpListener,
        _queued: Vec<tokio::net::TcpStream>,
    }

    #[cfg(target_os = "linux")]
    impl ServerDroppingNewConnections {
        async fn start() -> Self {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = socket.local_addr().unwrap();
            let listener = socket.listen(0).unwrap();
            let connect = || tokio::time::timeout(Duration::from_millis(200), tokio::net::TcpStream::connect(addr));
            let mut queued = Vec::new();
            for _ in 0..64 {
                match connect().await {
                    Ok(Ok(stream)) => queued.push(stream),
                    _ => return Self { addr, _listener: listener, _queued: queued },
                }
            }
            panic!("the listener's queue never filled");
        }
    }

    fn local_egress(connect_timeout: Duration, read_timeout: Duration) -> Egress {
        Egress::with_timeouts(["127.0.0.1".to_owned()], connect_timeout, read_timeout)
    }

    fn impatient_egress() -> Egress {
        local_egress(Duration::from_millis(100), Duration::from_millis(100))
    }

    #[tokio::test]
    async fn a_host_off_the_allowlist_is_logged_and_never_contacted() {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let egress = Egress::new(["bsky.social".to_owned()]);
        let request = egress.client().get(format!("http://{addr}/")).build().unwrap();

        let outcome = egress.execute(request).await;

        assert!(matches!(outcome, Err(EgressError::Blocked(host)) if host == "127.0.0.1"));
        let log = egress.log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].host, "127.0.0.1");
        assert!(!log[0].allowed);
        let contacted = tokio::time::timeout(Duration::from_millis(200), server.accept()).await;
        assert!(contacted.is_err(), "a blocked request must not open a connection");
    }

    #[tokio::test]
    async fn a_server_that_never_answers_ends_in_an_error() {
        let addr = server_going_silent_after(b"").await;
        let egress = impatient_egress();
        let request = egress.client().get(format!("http://{addr}/")).build().unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(5), egress.execute(request)).await;

        assert!(outcome.expect("the request must not hang").is_err());
    }

    /// Linux only: Windows refuses a connection to a full queue instead of dropping it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_connection_that_cannot_be_opened_times_out() {
        let server = ServerDroppingNewConnections::start().await;
        // The read timeout ends a hanging connection attempt too, so it stays long:
        // a short one would pass this test without a connect timeout.
        let egress = local_egress(Duration::from_millis(100), READ_TIMEOUT);
        let request = egress.client().get(format!("http://{}/", server.addr)).build().unwrap();

        let outcome = tokio::time::timeout(Duration::from_secs(5), egress.execute(request)).await;

        let error = outcome.expect("the connection attempt must not hang").unwrap_err();
        assert!(matches!(error, EgressError::Http(e) if e.is_connect() && e.is_timeout()));
    }

    #[tokio::test]
    async fn a_download_that_stalls_halfway_ends_in_an_error() {
        let addr = server_going_silent_after(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc").await;
        let egress = impatient_egress();
        let request = egress.client().get(format!("http://{addr}/")).build().unwrap();
        let response = egress.execute(request).await.unwrap();

        let body = tokio::time::timeout(Duration::from_secs(5), response.bytes()).await;

        assert!(body.expect("the download must not hang").is_err());
    }
}
