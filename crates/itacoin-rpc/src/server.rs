//! The HTTP side of the RPC (sections 4.2 and 4.4 of
//! `docs/NODE_PROPOSAL.md`).

use std::{
    collections::HashSet,
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::Value;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::JoinHandle,
};

use crate::{
    auth::{Credentials, IpNet},
    methods::{Context, dispatch},
    request::{Body, RpcError, code, parse_body, response},
};

/// Largest request body.
pub const MAX_BODY: usize = 2_000_000;
/// Connections served at once; further ones wait in the accept queue.
pub const MAX_CONNECTIONS: usize = 16;
/// Time allowed for one request, from headers to response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Delay before answering a failed authentication.
pub const AUTH_FAILURE_DELAY: Duration = Duration::from_millis(250);
/// Time requests in progress get to finish on shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Server configuration.
#[derive(Debug, Default)]
pub struct RpcConfig {
    /// Addresses to listen on.
    pub binds: Vec<SocketAddr>,
    /// Networks allowed to connect besides loopback.
    pub allow: Vec<IpNet>,
    /// Accepted credentials.
    pub credentials: Credentials,
}

/// Why the server did not start.
#[derive(Debug)]
pub enum ServeError {
    /// Binding failed.
    Io(io::Error),
    /// A non-loopback address was given without `--rpc-allow-ip`.
    ExposedWithoutAllowList(SocketAddr),
    /// No credential is configured.
    NoCredentials,
    /// No address to listen on.
    NoBind,
}

impl core::fmt::Display for ServeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "RPC bind failed: {error}"),
            Self::ExposedWithoutAllowList(addr) => write!(
                formatter,
                "RPC address {addr} is not loopback; it also needs --rpc-allow-ip"
            ),
            Self::NoCredentials => formatter.write_str("the RPC has no credentials"),
            Self::NoBind => formatter.write_str("the RPC has no address to listen on"),
        }
    }
}

impl std::error::Error for ServeError {}

struct Shared {
    context: Context,
    credentials: Credentials,
    hosts: HashSet<String>,
    wildcard_ports: HashSet<u16>,
}

/// A running RPC server.
pub struct RpcServer {
    addrs: Vec<SocketAddr>,
    closing: watch::Sender<bool>,
    accept_tasks: Vec<JoinHandle<()>>,
    connections: Arc<Semaphore>,
}

impl core::fmt::Debug for RpcServer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RpcServer")
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

impl RpcServer {
    /// The addresses the server listens on.
    #[must_use]
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Stops accepting connections and gives requests in progress
    /// [`SHUTDOWN_GRACE`] to finish.
    pub async fn shutdown(self) {
        let _ = self.closing.send(true);
        for task in self.accept_tasks {
            let _ = task.await;
        }
        let all = u32::try_from(MAX_CONNECTIONS).unwrap_or(u32::MAX);
        let _ = tokio::time::timeout(SHUTDOWN_GRACE, self.connections.acquire_many(all)).await;
    }
}

fn host_names(addr: &SocketAddr) -> Vec<String> {
    let port = addr.port();
    let mut names = vec![addr.to_string()];
    if addr.ip().is_loopback() {
        names.push(format!("localhost:{port}"));
        names.push(format!("127.0.0.1:{port}"));
        names.push(format!("[::1]:{port}"));
    }
    names
}

/// Starts the server on the current tokio runtime.
pub async fn serve(config: RpcConfig, mut context: Context) -> Result<RpcServer, ServeError> {
    if config.binds.is_empty() {
        return Err(ServeError::NoBind);
    }
    if config.credentials.cookie.is_none() && config.credentials.fixed.is_empty() {
        return Err(ServeError::NoCredentials);
    }
    if config.allow.is_empty()
        && let Some(exposed) = config.binds.iter().find(|addr| !addr.ip().is_loopback())
    {
        return Err(ServeError::ExposedWithoutAllowList(*exposed));
    }
    let mut listeners = Vec::new();
    for bind in &config.binds {
        listeners.push(TcpListener::bind(bind).await.map_err(ServeError::Io)?);
    }
    let addrs: Vec<SocketAddr> = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<_, _>>()
        .map_err(ServeError::Io)?;
    context.rpc_addrs.clone_from(&addrs);

    let mut hosts = HashSet::new();
    let mut wildcard_ports = HashSet::new();
    for addr in &addrs {
        if addr.ip().is_unspecified() {
            wildcard_ports.insert(addr.port());
        }
        hosts.extend(host_names(addr));
    }
    let allow = Arc::new(config.allow);
    let shared = Arc::new(Shared {
        context,
        credentials: config.credentials,
        hosts,
        wildcard_ports,
    });
    let (closing, _) = watch::channel(false);
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let accept_tasks = listeners
        .into_iter()
        .map(|listener| {
            tokio::spawn(accept_loop(
                listener,
                Arc::clone(&shared),
                Arc::clone(&allow),
                Arc::clone(&connections),
                closing.subscribe(),
            ))
        })
        .collect();
    Ok(RpcServer {
        addrs,
        closing,
        accept_tasks,
        connections,
    })
}

fn allowed(ip: IpAddr, allow: &[IpNet]) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    };
    ip.is_loopback() || allow.iter().any(|net| net.contains(&ip))
}

async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    allow: Arc<Vec<IpNet>>,
    connections: Arc<Semaphore>,
    mut closing: watch::Receiver<bool>,
) {
    loop {
        let permit = tokio::select! {
            permit = Arc::clone(&connections).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return,
            },
            _ = closing.changed() => return,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(_) => continue,
            },
            _ = closing.changed() => return,
        };
        if !allowed(peer.ip(), &allow) {
            tracing::debug!("RPC connection from {peer} refused by the allow list");
            continue;
        }
        let shared = Arc::clone(&shared);
        let mut closing = closing.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // The last Authorization header that passed, so a fixed
            // credential is hashed once per connection, not per request.
            let accepted_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
            let service = service_fn(move |request| {
                let shared = Arc::clone(&shared);
                let accepted_auth = Arc::clone(&accepted_auth);
                async move {
                    let response = tokio::time::timeout(
                        REQUEST_TIMEOUT,
                        handle(&shared, &accepted_auth, request),
                    )
                    .await
                    .unwrap_or_else(|_| plain(StatusCode::REQUEST_TIMEOUT, "request timed out"));
                    Ok::<_, Infallible>(response)
                }
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(REQUEST_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service);
            let mut connection = std::pin::pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => {}
                _ = closing.changed() => {
                    connection.as_mut().graceful_shutdown();
                    let _ = tokio::time::timeout(SHUTDOWN_GRACE, connection).await;
                }
            }
        });
    }
}

fn plain(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

fn json_response(value: &Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    let mut response = Response::new(Full::new(Bytes::from(body)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn host_ok(shared: &Shared, host: &str) -> bool {
    if shared.hosts.contains(host) {
        return true;
    }
    // On a wildcard bind, accept IP literals on the bound port, never names.
    host.parse::<SocketAddr>()
        .is_ok_and(|addr| shared.wildcard_ports.contains(&addr.port()))
}

async fn handle(
    shared: &Arc<Shared>,
    accepted_auth: &Arc<Mutex<Option<String>>>,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    if request.method() != hyper::Method::POST {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "only POST is accepted");
    }
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|host| host.to_str().ok());
    if !host.is_some_and(|host| host_ok(shared, host)) {
        return plain(StatusCode::FORBIDDEN, "unexpected Host header");
    }
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json {
        return plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        );
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_BODY as u64) {
        return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }

    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if !authorized(shared, accepted_auth, authorization).await {
        tokio::time::sleep(AUTH_FAILURE_DELAY).await;
        let mut response = plain(StatusCode::UNAUTHORIZED, "unauthorized");
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"itacoin\""),
        );
        return response;
    }

    let Ok(body) = Limited::new(request.into_body(), MAX_BODY).collect().await else {
        return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    };
    let body = body.to_bytes();
    match parse_body(&body) {
        Err(error) => json_response(&response(None, Err(error))),
        Ok(Body::Single(call)) => match call {
            Err(error) => json_response(&response(None, Err(error))),
            Ok(call) => {
                let result = run(shared, &call.method, &call.params).await;
                match call.id {
                    None => {
                        let mut response = Response::new(Full::new(Bytes::new()));
                        *response.status_mut() = StatusCode::NO_CONTENT;
                        response
                    }
                    Some(id) => json_response(&response(Some(id), result)),
                }
            }
        },
        Ok(Body::Batch(calls)) => {
            let mut responses = Vec::with_capacity(calls.len());
            for call in calls {
                match call {
                    Err(error) => responses.push(response(None, Err(error))),
                    Ok(call) => {
                        let result = run(shared, &call.method, &call.params).await;
                        if let Some(id) = call.id {
                            responses.push(response(Some(id), result));
                        }
                    }
                }
            }
            json_response(&Value::Array(responses))
        }
    }
}

async fn run(shared: &Shared, method: &str, params: &[Value]) -> Result<Value, RpcError> {
    tracing::debug!("RPC {method}");
    let result = dispatch(&shared.context, method, params).await;
    if let Err(error) = &result
        && error.code == code::INTERNAL_ERROR
    {
        tracing::warn!("RPC {method} failed: {}", error.message);
    }
    result
}

async fn authorized(
    shared: &Arc<Shared>,
    accepted_auth: &Arc<Mutex<Option<String>>>,
    authorization: Option<String>,
) -> bool {
    let Some(authorization) = authorization else {
        return false;
    };
    let cached = accepted_auth
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .is_some_and(|accepted| {
            crate::auth::constant_time_eq(accepted.as_bytes(), authorization.as_bytes())
        });
    if cached {
        return true;
    }
    let checker = Arc::clone(shared);
    let header = authorization.clone();
    // Fixed credentials cost an Argon2id hash: keep it off the runtime.
    let ok = tokio::task::spawn_blocking(move || checker.credentials.check(&header))
        .await
        .unwrap_or(false);
    if ok {
        *accepted_auth.lock().unwrap_or_else(PoisonError::into_inner) = Some(authorization);
    }
    ok
}
