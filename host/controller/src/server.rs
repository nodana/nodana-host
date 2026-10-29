use crate::{
    host::{Fault, Host, fail},
    protocol::*,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode},
    routing::any,
};
use serde_json::{Value, json};
use std::{
    io::Cursor,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor};
use tower::ServiceExt;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Control,
    Legacy,
    Public,
}
#[cfg(test)]
pub async fn fixture_listener(host: Arc<Host>, listener: TcpListener, public: bool) -> Result<()> {
    let certificate = String::from_utf8(read_file(&host.args.tls_certificate, 32768)?)?;
    let config = None;
    accept(
        host,
        listener,
        if public { Kind::Public } else { Kind::Control },
        config,
        certificate,
    )
    .await
}
#[derive(Clone)]
struct Connection {
    kind: Kind,
    hostname: Option<String>,
    certificate: String,
    client_fingerprint: Option<String>,
}

pub async fn serve(host: Arc<Host>) -> Result<()> {
    let legacy = load_tls(&host.args.tls_certificate, &host.args.tls_key, None, false)?;
    let certificate = String::from_utf8(read_file(&host.args.tls_certificate, 32768)?)?;
    tokio::try_join!(
        listener(
            host.clone(),
            host.args.port,
            Kind::Control,
            None,
            certificate.clone()
        ),
        listener(host.clone(), 8444, Kind::Legacy, Some(legacy), certificate),
        listener(host, 9740, Kind::Public, None, String::new())
    )?;
    Ok(())
}
fn load_tls(
    certificate: &std::path::Path,
    key: &std::path::Path,
    roots: Option<Arc<rustls::RootCertStore>>,
    public: bool,
) -> Result<Arc<rustls::ServerConfig>> {
    let cert = read_file(certificate, 32768)?;
    let key = read_file(key, 16384)?;
    let chain =
        rustls_pemfile::certs(&mut Cursor::new(cert)).collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))?.context("missing TLS key")?;
    let versions: Vec<_> = if public {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        vec![&rustls::version::TLS13]
    };
    let builder = rustls::ServerConfig::builder_with_protocol_versions(&versions);
    let mut config = if let Some(roots) = roots {
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots).build()?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)?
    } else {
        builder.with_no_client_auth().with_single_cert(chain, key)?
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
async fn listener(
    host: Arc<Host>,
    port: u16,
    kind: Kind,
    config: Option<Arc<rustls::ServerConfig>>,
    certificate: String,
) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    accept(host, listener, kind, config, certificate).await
}
async fn accept(
    host: Arc<Host>,
    listener: TcpListener,
    kind: Kind,
    config: Option<Arc<rustls::ServerConfig>>,
    certificate: String,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(32));
    let quotes = Arc::new(Semaphore::new(2));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let host = host.clone();
        let config = config.clone();
        let certificate = certificate.clone();
        let quotes = quotes.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let task = async {
                // New control handshakes use the current trust policy. Requests
                // also check the leaf pin so revocation covers existing sessions.
                let config = if kind == Kind::Control {
                    Some(load_tls(
                        &host.args.tls_certificate,
                        &host.args.tls_key,
                        Some(host.control_identity.roots()?),
                        false,
                    )?)
                } else {
                    config
                };
                let (stream, connection) = if kind == Kind::Public {
                    let hello = tokio::time::timeout(
                        Duration::from_secs(5),
                        LazyConfigAcceptor::new(rustls::server::Acceptor::default(), socket),
                    )
                    .await??;
                    let hostname = hello
                        .client_hello()
                        .server_name()
                        .context("missing SNI")?
                        .to_owned();
                    ensure!(
                        crate::protocol::hostname(&hostname).is_some(),
                        "invalid SNI"
                    );
                    let host_for_cert = host.clone();
                    let (config, certificate) =
                        tokio::task::spawn_blocking(move || -> Result<_> {
                            ensure!(
                                host_for_cert.certificates.ready(),
                                "certificate unavailable"
                            );
                            let current = host_for_cert
                                .certificates
                                .current()?
                                .context("certificate unavailable")?;
                            let (cert, key) = host_for_cert.certificates.files(&current);
                            let config = load_tls(&cert, &key, None, true)?;
                            let pem = String::from_utf8(read_file(&cert, 32768)?)?;
                            Ok((config, pem))
                        })
                        .await??;
                    (
                        tokio::time::timeout(Duration::from_secs(5), hello.into_stream(config))
                            .await??,
                        Connection {
                            kind,
                            hostname: Some(hostname),
                            certificate,
                            client_fingerprint: None,
                        },
                    )
                } else {
                    let stream = tokio::time::timeout(
                        Duration::from_secs(5),
                        TlsAcceptor::from(config.context("missing TLS configuration")?)
                            .accept(socket),
                    )
                    .await??;
                    let client_fingerprint = if kind == Kind::Control {
                        Some(crate::control_identity::fingerprint(
                            stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|chain| chain.first())
                                .context("missing client certificate")?
                                .as_ref(),
                        ))
                    } else {
                        None
                    };
                    (
                        stream,
                        Connection {
                            kind,
                            hostname: None,
                            certificate,
                            client_fingerprint,
                        },
                    )
                };
                let router = Router::new().fallback(any(move |request: Request<Body>| {
                    let host = host.clone();
                    let connection = connection.clone();
                    let quotes = quotes.clone();
                    async move { dispatch(host, connection, quotes, request).await }
                }));
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        router.clone().oneshot(request.map(Body::new))
                    });
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .timer(hyper_util::rt::TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(10))
                    .max_buf_size(16384)
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await?;
                Ok::<(), anyhow::Error>(())
            };
            // Includes handshake/body/response time. No parser or socket errors
            // (which can contain request contents) are printed to the console.
            let _ = tokio::time::timeout(Duration::from_secs(120), task).await;
        });
    }
}
async fn dispatch(
    host: Arc<Host>,
    connection: Connection,
    quotes: Arc<Semaphore>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let maximum = if connection.kind == Kind::Control
        && (parts.uri.path().starts_with("/v1/certificates/")
            || parts.uri.path() == "/v1/control-identities")
    {
        196608
    } else {
        16384
    };
    if parts.headers.contains_key("transfer-encoding")
        || parts.headers.get_all("content-length").iter().count() > 1
    {
        return error(connection.kind, fail(400, "invalid_request"));
    }
    let bytes = match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, maximum)).await {
        Ok(Ok(bytes)) => bytes,
        _ => return error(connection.kind, fail(413, "request_too_large")),
    };
    let quote = parts.uri.path().ends_with("/attestation");
    let _quote = if quote {
        match quotes.try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => return error(connection.kind, fail(429, "busy")),
        }
    } else {
        None
    };
    let kind = connection.kind;
    let result = tokio::task::spawn_blocking(move || {
        if kind == Kind::Control {
            control(
                &host,
                &parts,
                &bytes,
                connection
                    .client_fingerprint
                    .as_deref()
                    .context("missing client identity")?,
            )
        } else {
            public(&host, &connection, &parts, &bytes)
        }
    })
    .await;
    match result {
        Ok(Ok(response)) => response,
        Ok(Err(fault)) => error(kind, fault),
        Err(_) => error(kind, fail(503, "host_unavailable")),
    }
}
fn response(status: u16, value: Value) -> Result<Response<Body>> {
    raw(status, "application/json", canonical(&value))
}
fn raw(status: u16, content_type: &str, bytes: Vec<u8>) -> Result<Response<Body>> {
    let builder = Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .header("Content-Length", bytes.len());
    Ok(builder.body(Body::from(bytes))?)
}
fn error(kind: Kind, error: anyhow::Error) -> Response<Body> {
    let (status, code) = error
        .downcast_ref::<Fault>()
        .map(|e| (e.status, e.code))
        .unwrap_or((
            if kind == Kind::Control { 503 } else { 502 },
            if kind == Kind::Control {
                "host_unavailable"
            } else {
                "node_unavailable"
            },
        ));
    response(
        status,
        if kind == Kind::Control {
            json!({"code":code})
        } else {
            json!({"error":code})
        },
    )
    .unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::empty())
            .unwrap()
    })
}
fn json_body(parts: &axum::http::request::Parts, bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty()
        || parts
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next() != Some("application/json"))
    {
        return Err(fail(400, "json_required"));
    }
    parse_json(bytes).map_err(|_| fail(400, "invalid_request"))
}
fn control(
    host: &Host,
    parts: &axum::http::request::Parts,
    bytes: &[u8],
    client_fingerprint: &str,
) -> Result<Response<Body>> {
    use crate::control_identity::Role;
    let role = host
        .control_identity
        .role(client_fingerprint)
        .ok_or_else(|| fail(401, "client_identity_revoked"))?;
    if parts.uri.query().is_some() {
        return Err(fail(400, "invalid_path"));
    }
    let path = parts.uri.path();
    let method = parts.method.as_str();
    if path == "/v1/control-identities" {
        if role != Role::Administrator {
            return Err(fail(403, "administrator_identity_required"));
        }
        return match method {
            "GET" => response(200, host.control_identity.status()?),
            "POST" => response(
                200,
                host.control_identity.replace(json_body(parts, bytes)?)?,
            ),
            _ => Err(fail(405, "method_not_allowed")),
        };
    }
    if role != Role::Api {
        return Err(fail(403, "api_identity_required"));
    }
    match (method, path) {
        ("POST", "/v1/releases") => {
            return response(
                200,
                host.runtime
                    .releases
                    .as_ref()
                    .context("release store unavailable")?
                    .prepare(json_body(parts, bytes)?)?,
            );
        }
        ("GET", "/v1/resources") => return response(200, host.resources()?),
        ("POST", "/v1/capacity") => {
            return response(200, host.configure_capacity(json_body(parts, bytes)?)?);
        }
        ("POST", "/v1/deployments") => {
            let value = json_body(parts, bytes)?;
            let mut metadata = value.clone();
            if let Some(fields) = metadata.as_object_mut() {
                fields.remove("credentials");
            }
            let job: Job =
                serde_json::from_value(metadata).map_err(|_| fail(400, "invalid_request"))?;
            job.validate().map_err(|_| fail(400, "invalid_request"))?;
            return response(202, host.provision(value)?);
        }
        ("POST", "/v1/deletions") => return response(200, host.delete(json_body(parts, bytes)?)?),
        _ => {}
    }
    if let Some(action) = path.strip_prefix("/v1/certificates/") {
        if method == "GET" && action == "status" {
            return response(200, host.certificates.status()?);
        }
        if method != "POST" {
            return Err(fail(404, "not_found"));
        }
        let value = json_body(parts, bytes)?;
        let result = match action {
            "configure" => host.certificates.configure(value),
            "retry" => host.certificates.retry(value),
            "recipient" => host.certificates.recipient(value),
            "export" => host.certificates.export(value),
            "receive" => host.certificates.receive(value),
            _ => return Err(fail(404, "not_found")),
        };
        return response(200, result?);
    }
    if let Some(tail) = path.strip_prefix("/v1/deployments/") {
        let (deployment, action) = tail.split_once('/').unwrap_or((tail, ""));
        id(deployment, "deployment", 24).map_err(|_| fail(400, "invalid_identifier"))?;
        if method == "GET" && action.is_empty() {
            return response(200, host.deployment(deployment)?);
        }
        if method == "POST" && action == "lifecycle" {
            return response(200, host.lifecycle(deployment, json_body(parts, bytes)?)?);
        }
        if method == "POST" && action == "update" {
            return response(200, host.update(deployment, json_body(parts, bytes)?)?);
        }
        if method == "GET" && action == "release" {
            let job = host.ready_job(deployment)?;
            return response(200, host.runtime.release_identity(&job.node_id)?);
        }
        if method == "POST" && action == "release-attestation" {
            return response(
                200,
                host.release_attestation(deployment, json_body(parts, bytes)?)?,
            );
        }
        let (job, status) = host.job(deployment)?;
        if action != "logs" && status != "ready" {
            return Err(fail(409, "node_not_ready"));
        }
        match (method, action) {
            ("POST", "invoices") => {
                let request: crate::runtime::CreateInvoice =
                    serde_json::from_value(json_body(parts, bytes)?)
                        .map_err(|_| fail(400, "invalid_request"))?;
                request
                    .validate()
                    .map_err(|_| fail(400, "invalid_request"))?;
                return response(200, host.runtime.create_invoice(&job.node_id, &request)?);
            }
            ("GET", "listchannels") => return response(200, host.list_channels(deployment)?),
            ("POST", "closechannel") => {
                let request: crate::runtime::CloseChannel =
                    serde_json::from_value(json_body(parts, bytes)?)
                        .map_err(|_| fail(400, "invalid_request"))?;
                request
                    .validate()
                    .map_err(|_| fail(400, "invalid_request"))?;
                return response(200, host.close_channel(deployment, &request)?);
            }
            ("POST", "offers") => {
                let request: crate::runtime::CreateOffer =
                    serde_json::from_value(json_body(parts, bytes)?)
                        .map_err(|_| fail(400, "invalid_request"))?;
                request
                    .validate()
                    .map_err(|_| fail(400, "invalid_request"))?;
                return response(200, host.runtime.create_offer(&job.node_id, &request)?);
            }
            ("GET", "dashboard") => return response(200, host.runtime.dashboard(&job)?),
            ("POST", "incoming") => {
                let v = json_body(parts, bytes)?;
                crate::certificates::fields(&v, &["offset", "to"])?;
                let offset = v["offset"]
                    .as_u64()
                    .filter(|v| *v <= i64::MAX as u64)
                    .context("invalid offset")?;
                let to = v["to"]
                    .as_u64()
                    .filter(|v| *v <= i64::MAX as u64)
                    .context("invalid to")?;
                return response(200, host.runtime.incoming(&job.node_id, offset, to)?);
            }
            ("POST", "logs") => {
                let query = serde_json::from_value(json_body(parts, bytes)?)
                    .map_err(|_| fail(400, "invalid_request"))?;
                let page = host
                    .logs
                    .lock()
                    .unwrap()
                    .page(&job.node_id, query)
                    .map_err(|_| fail(400, "invalid_request"))?;
                return response(200, serde_json::to_value(page)?);
            }
            _ => {}
        }
    }
    Err(fail(404, "not_found"))
}
fn public(
    host: &Host,
    connection: &Connection,
    parts: &axum::http::request::Parts,
    bytes: &[u8],
) -> Result<Response<Body>> {
    let path = parts.uri.path();
    let method = parts.method.as_str();
    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        return Err(fail(400, "invalid_request"));
    }
    let (node, operation) = if connection.kind == Kind::Public {
        let name = connection.hostname.as_deref().context("missing hostname")?;
        let hosts = parts
            .headers
            .get_all("host")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>();
        if hosts.len() != 1
            || !(hosts[0] == name
                || hosts[0] == format!("{name}:443")
                || hosts[0] == format!("{name}:9740"))
        {
            return Err(fail(421, "hostname_mismatch"));
        }
        if path.starts_with("/v1/") {
            return Err(fail(404, "not_found"));
        }
        (hostname(name).context("invalid hostname")?, path)
    } else {
        let tail = path
            .strip_prefix("/v1/nodes/")
            .ok_or_else(|| fail(404, "not_found"))?;
        let (node, operation) = tail.split_once('/').ok_or_else(|| fail(404, "not_found"))?;
        (node.to_owned(), &path[path.len() - operation.len() - 1..])
    };
    let job = host.public_job(&node, connection.hostname.as_deref())?;
    let started = Instant::now();
    let result = public_operation(host, connection, parts, bytes, &job, operation);
    let status = result
        .as_ref()
        .map(|r| r.status().as_u16())
        .unwrap_or_else(|e| e.downcast_ref::<Fault>().map(|f| f.status).unwrap_or(502));
    host.logs.lock().unwrap().record(
        &node,
        method,
        operation,
        status,
        started.elapsed().as_millis().try_into().unwrap_or(600_000),
    );
    result
}
fn public_operation(
    host: &Host,
    connection: &Connection,
    parts: &axum::http::request::Parts,
    bytes: &[u8],
    job: &Job,
    operation: &str,
) -> Result<Response<Body>> {
    let method = parts.method.as_str();
    if operation == "/attestation" {
        if method != "POST"
            || parts.uri.query().is_some()
            || parts.headers.contains_key("authorization")
        {
            return Err(fail(400, "invalid_request"));
        }
        let value = json_body(parts, bytes)?;
        crate::certificates::fields(&value, &["nonce"])?;
        let nonce = decode(value["nonce"].as_str().context("missing nonce")?, 32)
            .map_err(|_| fail(400, "invalid_encoding"))?;
        let mut identity = json!({"version":2,"nodeId":job.node_id,"ownerPublicKey":job.owner_public_key,"nodePublicKey":host.runtime.public_key(&job.node_id)?,"certificateSha256":hex::encode(digest(connection.certificate.as_bytes())),"release":host.runtime.release_identity(&job.node_id)?});
        if let Some(hostname) = &connection.hostname {
            identity["hostname"] = json!(hostname);
        }
        let prefix = if connection.kind == Kind::Public {
            b"nodana-public-tls-v1\0".as_slice()
        } else {
            b"nodana-user-tls-v1\0".as_slice()
        };
        let document = attest(&host.args, &nonce, &binding(prefix, &identity, None))?;
        let mut result =
            json!({"certificate":connection.certificate,"attestationDocument":encode(document)});
        if connection.kind == Kind::Public {
            result["identity"] = identity;
        }
        return response(200, result);
    }
    if connection.kind == Kind::Legacy
        && !((method == "GET"
            && (operation == "/getinfo"
                || operation == "/getbalance"
                || operation == "/payments/incoming"
                || regex::Regex::new(r"^/payments/incoming/[a-f0-9]{64}$")?.is_match(operation)))
            || (method == "POST" && ["/createinvoice", "/payinvoice"].contains(&operation)))
    {
        return Err(fail(404, "not_found"));
    }
    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/x-www-form-urlencoded");
    if !["application/json", "application/x-www-form-urlencoded"].contains(&content_type) {
        return Err(fail(400, "invalid_content_type"));
    }
    let path = if let Some(query) = parts.uri.query() {
        format!("{operation}?{query}")
    } else {
        operation.to_owned()
    };
    let body = if bytes.is_empty() {
        None
    } else {
        Some(bytes.to_vec())
    };
    let (status, headers, bytes) = host.runtime.proxy(
        &job.node_id,
        method,
        &path,
        parts.headers.get("authorization"),
        body,
        content_type,
        131072,
    )?;
    upstream_response(status, headers, bytes)
}

fn upstream_response(
    status: u16,
    headers: axum::http::HeaderMap,
    bytes: Vec<u8>,
) -> Result<Response<Body>> {
    // Connection may name additional hop-by-hop fields. Never carry these across
    // connections, and regenerate framing after buffering the bounded body.
    let connection_fields: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .collect();
    let mut response = Response::builder().status(status);
    for (name, value) in &headers {
        if ![
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "content-length",
            "cache-control",
        ]
        .contains(&name.as_str())
            && !connection_fields.iter().any(|v| v == name.as_str())
        {
            response = response.header(name, value);
        }
    }
    Ok(response
        .header("Cache-Control", "no-store")
        .header("Content-Length", bytes.len())
        .body(Body::from(bytes))?)
}
