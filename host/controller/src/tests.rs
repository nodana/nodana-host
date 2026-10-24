use crate::{Args, host::Host, protocol::*};
use hpke::{Kem, Serializable};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn fixture() -> (tempfile::TempDir, Args) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    crate::test_material::generate(root);
    let attest = root.join("attest");
    std::fs::write(&attest,format!("#!/bin/sh\ncp \"$2\" '{}/last-nonce'\ncp \"$4\" '{}/last-binding'\nprintf fixture-evidence\n",root.display(),root.display())).unwrap();
    std::fs::set_permissions(&attest, std::fs::Permissions::from_mode(0o700)).unwrap();
    let certbot = root.join("certbot");
    std::fs::write(&certbot, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&certbot, std::fs::Permissions::from_mode(0o700)).unwrap();
    let args = Args {
        data: root.join("data"),
        runtime_dir: root.to_owned(),
        release_public_key: root.join("release-key.pem"),
        release_origin:
            "https://nodana-staging-436908791052-node-releases.s3.us-east-1.amazonaws.com".into(),
        release_store: root.join("data/releases"),
        attest_binary: attest,
        tls_certificate: root.join("control.pem"),
        tls_key: root.join("control.key"),
        client_ca: root.join("ca.pem"),
        client_certificate: root.join("client.pem"),
        admin_ca: root.join("ca.pem"),
        admin_certificate: root.join("admin.pem"),
        port: 8443,
        certbot,
        mock_releases: true,
    };
    std::fs::create_dir_all(&args.data).unwrap();
    (folder, args)
}
fn job() -> Job {
    let (_, public) = K::gen_keypair(&mut rand::rngs::OsRng);
    Job {
        release_sha256: "a".repeat(64),
        deployment_id: format!("deployment-{}", "1".repeat(24)),
        account_id: "account-12345678".into(),
        node_id: "node-a1b2".into(),
        auto_liquidity: "2m".into(),
        owner_public_key: encode(public.to_bytes()),
        public_hostname: Some(format!("heron-a1b2.{DOMAIN}")),
        webhook: None,
    }
}

#[test]
fn capacity_is_unconfigured_until_api_sets_it_and_survives_restart() {
    let (_folder, args) = fixture();
    let host = Host::open(args.clone()).unwrap();
    assert_eq!(host.capacity().unwrap(), 0);
    for value in [
        json!({}),
        json!({"capacity":0}),
        json!({"capacity":-1}),
        json!({"capacity":1.5}),
        json!({"capacity":45537}),
        json!({"capacity":8,"extra":true}),
    ] {
        assert!(host.configure_capacity(value).is_err());
        assert_eq!(host.capacity().unwrap(), 0);
    }
    host.configure_capacity(json!({"capacity":8})).unwrap();
    let job = job();
    host.test_job(&job, 7);
    host.configure_capacity(json!({"capacity":1})).unwrap();
    assert!(host.job(&job.deployment_id).is_ok());
    drop(host);
    // Concurrent subprocess tests can briefly inherit the lock descriptor before exec.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while args.data.join("control/host.lock").exists() {
        let file = std::fs::File::open(args.data.join("control/host.lock")).unwrap();
        if fs2::FileExt::try_lock_exclusive(&file).is_ok() {
            fs2::FileExt::unlock(&file).unwrap();
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "host lock not released"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let reopened = Host::open(args).unwrap();
    assert_eq!(reopened.capacity().unwrap(), 1);
    assert!(reopened.job(&job.deployment_id).is_ok());
}

#[test]
fn hpke_wire_format_matches_independent_fixture_and_rejects_bad_keys() {
    use base64::Engine;
    use hpke::Deserializable;
    assert!(parse_json(br#"{\"nodeId\":\"node-a1b2\",\"nodeId\":\"node-c3d4\"}"#).is_err());
    let fixture: Value = serde_json::from_str(include_str!("../fixtures/hpke.json")).unwrap();
    let key =
        <K as Kem>::PrivateKey::from_bytes(&decode(fixture["key"].as_str().unwrap(), 32).unwrap())
            .unwrap();
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(fixture["ciphertext"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        open(&key, &ciphertext, b"test-context").unwrap(),
        b"cross-implementation-credentials"
    );
    assert!(open(&key, &ciphertext, b"wrong-context").is_err());
    let mut invalid = job();
    invalid.owner_public_key = encode([0u8; 32]);
    assert!(invalid.validate().is_err());
    invalid.owner_public_key = encode([1u8; 32]);
    invalid.public_hostname = Some(format!("swan-zzzz.{DOMAIN}"));
    assert!(invalid.validate().is_err());
}

#[test]
fn native_update_preserves_wallet_selection_and_survives_a_host_restart() {
    let (folder, args) = fixture();
    let host = Host::open(args.clone()).unwrap();
    let job = job();
    host.test_job(&job, 0);
    let wallet = host.runtime.nodes.join(&job.node_id);
    std::fs::create_dir_all(&wallet).unwrap();
    std::fs::write(wallet.join("seed.dat"), b"wallet fixture").unwrap();
    std::fs::write(wallet.join("channels.db"), b"channel fixture").unwrap();
    let child = Command::new("sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    host.runtime.test_process(&job.node_id, 0, child);
    let request = |sha: &str| json!({"operationId":format!("operation-{}","1".repeat(32)),"nodeId":job.node_id,"accountId":job.account_id,"releaseSha256":sha});
    assert!(
        host.update(&job.deployment_id, request(&"f".repeat(64)))
            .is_err()
    );
    assert!(host.runtime.healthy(&job.node_id));
    let accepted = host
        .update(&job.deployment_id, request(&"b".repeat(64)))
        .unwrap();
    assert_eq!(accepted["status"], "starting");
    assert!(!host.runtime.healthy(&job.node_id));
    assert_eq!(
        std::fs::read(wallet.join("seed.dat")).unwrap(),
        b"wallet fixture"
    );
    assert_eq!(
        std::fs::read(wallet.join("channels.db")).unwrap(),
        b"channel fixture"
    );
    assert_eq!(
        host.job(&job.deployment_id).unwrap().0.release_sha256,
        "b".repeat(64)
    );
    // An applied retry neither stops a newer process nor selects the old bundle.
    host.update(&job.deployment_id, request(&"b".repeat(64)))
        .unwrap();
    assert!(
        host.update(&job.deployment_id, request(&"a".repeat(64)))
            .is_err()
    );
    drop(host);
    // Simulate loss of power after durable target selection, before queuing.
    let db = rusqlite::Connection::open(args.data.join("control/control.db")).unwrap();
    db.execute("UPDATE deployments SET status='stopping'", [])
        .unwrap();
    db.execute("UPDATE native_updates SET applied=0", [])
        .unwrap();
    drop(db);
    let reopened = Host::open(args).unwrap();
    let (selected, status) = reopened.job(&job.deployment_id).unwrap();
    assert_eq!(selected.release_sha256, "b".repeat(64));
    assert_eq!(status, "queued");
    drop(reopened);
    drop(folder);
}

#[cfg(target_os = "linux")]
#[test]
fn native_runtime_identity_checks_the_live_loader_and_payload() {
    let Ok(store) = std::env::var("NODANA_TEST_NATIVE_STORE") else {
        return;
    };
    let sha = std::env::var("NODANA_TEST_NATIVE_SHA256").unwrap();
    let (_folder, mut args) = fixture();
    args.release_store = store.into();
    args.mock_releases = false;
    args.release_public_key = std::env::var("NODANA_TEST_NATIVE_KEY").unwrap().into();
    let mut runtime =
        crate::runtime::Runtime::new(&args.data, std::env::current_exe().unwrap()).unwrap();
    runtime.releases = Some(crate::releases::Releases::new(&args));
    let root = args.release_store.join(&sha);
    let child = Command::new(root.join("lib/ld.so"))
        .args(["--inhibit-cache", "--library-path"])
        .arg(root.join("lib"))
        .arg(root.join("libexec/phoenixd"))
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    runtime.test_native_process("node-test", child, sha.clone());
    assert_eq!(
        runtime.release_identity("node-test").unwrap()["releaseSha256"],
        sha
    );
    runtime.stop("node-test");
    let substituted = Command::new("/bin/sleep")
        .arg("60")
        .process_group(0)
        .spawn()
        .unwrap();
    runtime.test_native_process("node-test", substituted, sha);
    assert!(runtime.release_identity("node-test").is_err());
    runtime.stop_all();
}

#[test]
fn certificate_attempts_are_manual_persistent_and_environment_scoped() {
    let (folder, args) = fixture();
    let manager = crate::certificates::Certificates::new(args.clone()).unwrap();
    manager.configure(json!({"role":"issuer","email":"test@example.com","environment":"staging","cloudflareToken":"syntheticToken12345678901234567890","cloudflareZoneId":"a".repeat(32)})).unwrap();
    manager.tick().unwrap();
    assert_eq!(
        manager.status().unwrap()["error"],
        "certificate_issuance_failed"
    );
    assert_eq!(manager.status().unwrap()["retryRequired"], true);
    assert_eq!(manager.status().unwrap()["failureReason"], "certbot_failed");
    let attempt = std::fs::read(manager.root.join("attempt-staging.json")).unwrap();
    manager.tick().unwrap();
    assert_eq!(
        std::fs::read(manager.root.join("attempt-staging.json")).unwrap(),
        attempt
    );
    let reopened = crate::certificates::Certificates::new(args).unwrap();
    assert_eq!(reopened.status().unwrap()["retryRequired"], true);
    reopened.retry(json!({})).unwrap();
    assert_eq!(reopened.status().unwrap()["retryRequired"], false);
    let cert = std::fs::read(folder.path().join("wildcard.pem")).unwrap();
    let key = std::fs::read(folder.path().join("wildcard.key")).unwrap();
    manager.install(&cert, &key, "staging").unwrap();
    assert_eq!(manager.status().unwrap()["status"], "staging_ready");
    manager.configure(json!({"role":"issuer","email":"test@example.com","environment":"production","cloudflareToken":"syntheticToken12345678901234567890","cloudflareZoneId":"a".repeat(32)})).unwrap();
    assert!(!manager.ready());
    manager.install(&cert, &key, "production").unwrap();
    assert!(manager.ready());
    assert!(
        manager
            .install(
                &std::fs::read(folder.path().join("wrong.pem")).unwrap(),
                &std::fs::read(folder.path().join("wrong.key")).unwrap(),
                "production"
            )
            .is_err()
    );
}

struct Backend {
    address: std::net::SocketAddr,
    offers: Arc<std::sync::Mutex<Vec<String>>>,
    closes: Arc<std::sync::Mutex<Vec<String>>>,
    channels: Arc<std::sync::Mutex<Value>>,
    stopping: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Backend {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.port() > 20000);
        listener.set_nonblocking(true).unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let flag = stopping.clone();
        let offers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_offers = offers.clone();
        let closes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_closes = closes.clone();
        let channels = Arc::new(std::sync::Mutex::new(
            json!([{"type":"Normal","commitments":{"params":{"channelId":"11".repeat(32)}},"shortChannelId":"0x7410060x0"}]),
        ));
        let channel_response = channels.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets can inherit the listener's nonblocking
                        // mode. Read the complete fixture request with the timeout.
                        stream.set_nonblocking(false).unwrap();
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut bytes = vec![0; 16384];
                        let mut count = stream.read(&mut bytes).unwrap_or(0);
                        while count < bytes.len()
                            && !bytes[..count].windows(4).any(|v| v == b"\r\n\r\n")
                        {
                            let read = stream.read(&mut bytes[count..]).unwrap_or(0);
                            if read == 0 {
                                break;
                            }
                            count += read;
                        }
                        while let Some(header_end) =
                            bytes[..count].windows(4).position(|v| v == b"\r\n\r\n")
                        {
                            let length: usize = String::from_utf8_lossy(&bytes[..header_end])
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse().unwrap())
                                })
                                .unwrap_or(0);
                            if count >= header_end + 4 + length {
                                break;
                            }
                            let read = stream.read(&mut bytes[count..]).unwrap_or(0);
                            if read == 0 {
                                break;
                            }
                            count += read;
                        }
                        let request = String::from_utf8_lossy(&bytes[..count]);
                        let authorization = request.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("authorization")
                                .then_some(value.trim())
                        });
                        if ![
                            format!("Basic {}", encode(":secret")),
                            format!("Basic {}", encode(":restricted")),
                            format!("Basic {}", encode("alice:secret")),
                        ]
                        .iter()
                        .any(|v| Some(v.as_str()) == authorization)
                        {
                            let body = "backend authentication required";
                            let _ = write!(
                                stream,
                                "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nWWW-Authenticate: Basic realm=\"Backend fixture\"\r\nX-Backend: phoenixd\r\nConnection: close, X-Hop\r\nX-Hop: remove-me\r\nContent-Length: {}\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            continue;
                        }
                        if request.starts_with("GET /listchannels ") {
                            assert_eq!(
                                authorization,
                                Some(format!("Basic {}", encode(":secret")).as_str())
                            );
                            let body = channel_response.lock().unwrap().to_string();
                            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
                            continue;
                        }
                        if request.starts_with("POST /closechannel ") {
                            assert_eq!(
                                authorization,
                                Some(format!("Basic {}", encode(":secret")).as_str())
                            );
                            let form = request.split_once("\r\n\r\n").unwrap().1;
                            recorded_closes.lock().unwrap().push(form.to_owned());
                            let values: std::collections::HashMap<String, String> =
                                url::form_urlencoded::parse(form.as_bytes())
                                    .into_owned()
                                    .collect();
                            let body = if values["channelId"] == "11".repeat(32) {
                                "ab".repeat(32)
                            } else {
                                "no channel available".to_string()
                            };
                            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
                            continue;
                        }
                        if request.starts_with("POST /createoffer ") {
                            assert_eq!(
                                authorization,
                                Some(format!("Basic {}", encode(":secret")).as_str())
                            );
                            recorded_offers
                                .lock()
                                .unwrap()
                                .push(request.split_once("\r\n\r\n").unwrap().1.to_string());
                            let body = "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
                            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                            continue;
                        }
                        let body = if request.contains("/payments/incoming?") {
                            json!([{ "paymentHash":"ab".repeat(32),"isPaid":true,"receivedSat":123,"createdAt":1700000000000u64,"seed":"never expose"}])
                        } else if request.contains("/getbalance") {
                            json!({"balanceSat":123,"feeCreditSat":10,"password":"never expose"})
                        } else if request.contains("/estimateliquidityfees") {
                            json!({"miningFeeSat":2,"serviceFeeSat":3})
                        } else {
                            json!({"nodeId":format!("02{}","ab".repeat(32)),"chain":"mainnet","version":"0.9.3","channels":[]})
                        };
                        let body = body.to_string();
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            address,
            offers,
            closes,
            channels,
            stopping,
            thread: Some(thread),
        }
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn real_tls_routes_authenticates_attests_and_fetches_private_recent_logs() {
    let (folder, args) = tokio::task::spawn_blocking(fixture).await.unwrap();
    let root = folder.path().to_owned();
    let backend = Backend::start();
    let slot = (backend.address.port() - 20000) as usize;
    let setup_args = args.clone();
    let (host, job, node_pid) = tokio::task::spawn_blocking(move || {
        let host = Arc::new(Host::open(setup_args).unwrap());
        let job = job();
        host.test_job(&job, slot);
        let node = host.runtime.nodes.join(&job.node_id);
        std::fs::create_dir_all(&node).unwrap();
        std::fs::write(
            node.join("phoenix.conf"),
            "http-password=secret\nhttp-password-limited-access=restricted\n",
        )
        .unwrap();
        let child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let node_pid = child.id();
        host.runtime.test_process(&job.node_id, slot, child);
        host.certificates
            .configure(json!({"role":"replica","environment":"staging"}))
            .unwrap();
        host.certificates
            .install(
                &std::fs::read(host.args.runtime_dir.join("wildcard.pem")).unwrap(),
                &std::fs::read(host.args.runtime_dir.join("wildcard.key")).unwrap(),
                "staging",
            )
            .unwrap();
        (host, job, node_pid)
    })
    .await
    .unwrap();
    let public = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_address = public.local_addr().unwrap();
    let control = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_address = control.local_addr().unwrap();
    let public_host = host.clone();
    let public_server = Server(tokio::spawn(async move {
        crate::server::fixture_listener(public_host, public, true)
            .await
            .unwrap();
    }));
    let control_host = host.clone();
    let control_server = Server(tokio::spawn(async move {
        crate::server::fixture_listener(control_host, control, false)
            .await
            .unwrap();
    }));
    let ca = reqwest::Certificate::from_pem(&std::fs::read(root.join("ca.pem")).unwrap()).unwrap();
    let hostname = job.public_hostname.as_ref().unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(ca.clone())
        .resolve(hostname, public_address)
        .build()
        .unwrap();
    let origin = format!("https://{hostname}:{}", public_address.port());
    // The public gateway uses port 443. Send that Host while resolving locally.
    let request = || {
        client
            .get(format!("{origin}/getinfo?password=DO_NOT_LOG"))
            .header("Host", hostname)
    };
    for authorization in [
        None,
        Some("Basic not-base64".to_owned()),
        Some(format!("Basic {}", encode(":wrong"))),
    ] {
        let mut call = request();
        if let Some(value) = authorization {
            call = call.header("Authorization", value);
        }
        let response = call.send().await.unwrap();
        assert_eq!(response.status(), 401);
        assert_eq!(
            response.headers()["www-authenticate"],
            "Basic realm=\"Backend fixture\""
        );
        assert_eq!(response.headers()["content-type"], "text/plain");
        assert_eq!(response.headers()["x-backend"], "phoenixd");
        assert!(!response.headers().contains_key("x-hop"));
        assert_eq!(
            response.text().await.unwrap(),
            "backend authentication required"
        );
    }
    for (username, password) in [("", "restricted"), ("alice", "secret")] {
        assert_eq!(
            request()
                .basic_auth(username, Some(password))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    assert_eq!(
        request()
            .basic_auth("", Some("secret"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{origin}/getinfo"))
            .header("Host", format!("swan-a1b2.{DOMAIN}"))
            .basic_auth("", Some("secret"))
            .send()
            .await
            .unwrap()
            .status(),
        421
    );
    let proof: Value = client
        .post(format!("{origin}/attestation"))
        .header("Host", hostname)
        .json(&json!({"nonce":encode([9u8;32])}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(proof["identity"]["hostname"], hostname.as_str());
    assert_eq!(
        std::fs::read(root.join("last-nonce")).unwrap(),
        vec![9u8; 32]
    );
    assert_eq!(
        std::fs::read(root.join("last-binding")).unwrap(),
        binding(b"nodana-public-tls-v1\0", &proof["identity"], None)
    );
    let mut identity = std::fs::read(root.join("client.pem")).unwrap();
    identity.extend(std::fs::read(root.join("client.key")).unwrap());
    let control_client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca.clone())
        .identity(reqwest::Identity::from_pem(&identity).unwrap())
        .resolve("protected-host.nodana.internal", control_address)
        .build()
        .unwrap();
    let control_origin = format!(
        "https://protected-host.nodana.internal:{}/v1/deployments/{}",
        control_address.port(),
        job.deployment_id
    );
    let logs: Value = control_client
        .post(format!("{control_origin}/logs"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(logs["total"], 7);
    let text = logs.to_string();
    assert!(
        !text.contains("secret")
            && !text.contains("DO_NOT_LOG")
            && !text.contains("password")
            && !text.contains("clientIp")
    );
    assert!(
        logs["logs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["statusCode"] == 401)
    );
    let incoming: Value = control_client
        .post(format!("{control_origin}/incoming"))
        .json(&json!({"offset":0,"to":1700000000000u64}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(incoming[0]["receivedSat"], 123);
    assert!(incoming[0].get("seed").is_none());
    let dashboard: Value = control_client
        .get(format!("{control_origin}/dashboard"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(dashboard["balance"]["balanceSat"], 123);
    assert!(dashboard["balance"].get("password").is_none());
    for input in [
        json!({}),
        json!({"amountSat":1000}),
        json!({"description":"Coffee & tips ☕", "amountSat":123}),
    ] {
        let response = control_client
            .post(format!("{control_origin}/offers"))
            .json(&input)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let offer: Value = response.json().await.unwrap();
        assert!(offer["offer"].as_str().unwrap().starts_with("lno1"));
        assert_eq!(offer.as_object().unwrap().len(), 1);
    }
    let requests = backend.offers.lock().unwrap().clone();
    let forms: Vec<std::collections::HashMap<String, String>> = requests
        .iter()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .collect();
    assert_eq!(forms[0].get("description").unwrap(), "Nodana offer");
    assert!(!forms[0].contains_key("amountSat"));
    assert_eq!(forms[1].get("description").unwrap(), "Nodana offer");
    assert_eq!(forms[1].get("amountSat").unwrap(), "1000");
    assert_eq!(forms[2].get("description").unwrap(), "Coffee & tips ☕");
    for input in [
        json!({"amountSat":0}),
        json!({"amountSat":-1}),
        json!({"amountSat":1.5}),
        json!({"description":"x".repeat(129)}),
        json!({"password":"forbidden"}),
    ] {
        assert_eq!(
            control_client
                .post(format!("{control_origin}/offers"))
                .json(&input)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    assert_eq!(backend.offers.lock().unwrap().len(), 3);
    let channels_url = format!("{control_origin}/listchannels");
    let close_url = format!("{control_origin}/closechannel");
    let channels: Value = control_client
        .get(&channels_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        channels[0]["commitments"]["params"]["channelId"],
        "11".repeat(32)
    );
    *backend.channels.lock().unwrap() = json!([]);
    let empty: Value = control_client
        .get(&channels_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty, json!([]));
    *backend.channels.lock().unwrap() = json!({"not":"an array"});
    assert_eq!(
        control_client
            .get(&channels_url)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    *backend.channels.lock().unwrap() = json!([]);
    let close_input = json!({"channelId":"11".repeat(32),"address":"bc1qexampledestination000000000000000000000", "feerateSatByte":12});
    let close: Value = control_client
        .post(&close_url)
        .json(&close_input)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(close, json!({"txId":"ab".repeat(32)}));
    let recorded = backend.closes.lock().unwrap()[0].clone();
    let form: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(recorded.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(form.len(), 3);
    assert_eq!(
        form["channelId"],
        close_input["channelId"].as_str().unwrap()
    );
    assert_eq!(form["address"], close_input["address"].as_str().unwrap());
    assert_eq!(form["feerateSatByte"], "12");
    let mut failed_close = close_input.clone();
    failed_close["channelId"] = json!("22".repeat(32));
    let failure = control_client
        .post(&close_url)
        .json(&failed_close)
        .send()
        .await
        .unwrap();
    assert_eq!(failure.status(), 409);
    assert!(!failure.text().await.unwrap().contains("txId"));
    for (field, value) in [
        ("channelId", json!("bad")),
        ("address", json!("x&address=evil")),
        ("feerateSatByte", json!(0)),
        ("feerateSatByte", json!(-1)),
        ("feerateSatByte", json!(1.5)),
        ("feerateSatByte", json!(i64::MAX)),
        ("password", json!("injected")),
    ] {
        let mut invalid = close_input.clone();
        invalid[field] = value;
        assert_eq!(
            control_client
                .post(&close_url)
                .json(&invalid)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    let mut missing = close_input.clone();
    missing.as_object_mut().unwrap().remove("address");
    assert_eq!(
        control_client
            .post(&close_url)
            .json(&missing)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(backend.closes.lock().unwrap().len(), 2);
    let anonymous = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca.clone())
        .resolve("protected-host.nodana.internal", control_address)
        .build()
        .unwrap();
    assert!(
        anonymous
            .post(format!("{control_origin}/logs"))
            .json(&json!({}))
            .send()
            .await
            .is_err()
    );
    let client_for = |label: &str| {
        let mut pem = std::fs::read(root.join(format!("{label}.pem"))).unwrap();
        pem.extend(std::fs::read(root.join(format!("{label}.key"))).unwrap());
        reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(ca.clone())
            .identity(reqwest::Identity::from_pem(&pem).unwrap())
            .resolve("protected-host.nodana.internal", control_address)
            .build()
            .unwrap()
    };
    let admin = client_for("admin");
    let next = client_for("client-next");
    let unauthorized = client_for("unauthorized");
    assert!(anonymous.get(&channels_url).send().await.is_err());
    assert!(
        anonymous
            .post(&close_url)
            .json(&close_input)
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        unauthorized
            .post(&close_url)
            .json(&close_input)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        admin
            .post(&close_url)
            .json(&close_input)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(backend.closes.lock().unwrap().len(), 2);
    let base = format!(
        "https://protected-host.nodana.internal:{}",
        control_address.port()
    );
    let policy_url = format!("{base}/v1/control-identities");
    let resources_url = format!("{base}/v1/certificates/status");
    let capacity_url = format!("{base}/v1/capacity");
    assert!(
        anonymous
            .post(&capacity_url)
            .json(&json!({"capacity":8}))
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        unauthorized
            .post(&capacity_url)
            .json(&json!({"capacity":8}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        admin
            .post(&capacity_url)
            .json(&json!({"capacity":8}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let capacity: Value = control_client
        .post(&capacity_url)
        .json(&json!({"capacity":8}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(capacity["capacity"], 8);
    assert_eq!(
        control_client
            .get(&policy_url)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        admin.get(&resources_url).send().await.unwrap().status(),
        403
    );
    assert_eq!(
        unauthorized
            .get(&resources_url)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert!(next.get(&resources_url).send().await.is_err());
    let entry = |label: &str, ca: &str| {
        json!({
            "certificate":std::fs::read_to_string(root.join(format!("{label}.pem"))).unwrap(),
            "ca":std::fs::read_to_string(root.join(ca)).unwrap(),
        })
    };
    let old_entry = entry("client", "ca.pem");
    let next_entry = entry("client-next", "next-ca.pem");
    assert_eq!(
        admin
            .post(&policy_url)
            .json(&json!({"expectedRevision":1,"apiCertificates":[entry("admin","ca.pem")]}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(admin.post(&policy_url).json(&json!({"expectedRevision":1,"apiCertificates":[old_entry.clone(),old_entry.clone()]}))
        .send().await.unwrap().status(),400);
    let unchanged_credentials =
        std::fs::read(host.runtime.nodes.join(&job.node_id).join("phoenix.conf")).unwrap();
    // Finish an old client's TLS handshake, then revoke it before its HTTP request.
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(
        std::fs::read(root.join("ca.pem")).unwrap(),
    )) {
        roots.add(cert.unwrap()).unwrap();
    }
    let chain = rustls_pemfile::certs(&mut std::io::Cursor::new(
        std::fs::read(root.join("client.pem")).unwrap(),
    ))
    .collect::<std::io::Result<Vec<_>>>()
    .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(
        std::fs::read(root.join("client.key")).unwrap(),
    ))
    .unwrap()
    .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
    let mut old_session = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("protected-host.nodana.internal").unwrap(),
            tokio::net::TcpStream::connect(control_address)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
    let update = |revision, entries| json!({"expectedRevision":revision,"apiCertificates":entries});
    assert_eq!(
        admin
            .post(&policy_url)
            .json(&update(1, vec![old_entry.clone(), next_entry.clone()]))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(next.get(&resources_url).send().await.unwrap().status(), 200);
    assert_eq!(
        control_client
            .get(&resources_url)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        admin
            .post(&policy_url)
            .json(&update(1, vec![next_entry.clone()]))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        admin
            .post(&policy_url)
            .json(&update(2, vec![next_entry.clone()]))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        control_client
            .get(&resources_url)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    old_session.write_all(b"GET /v1/resources HTTP/1.1\r\nHost: protected-host.nodana.internal\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    old_session.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 401"));
    // Emergency revocation leaves the independent recovery identity usable.
    assert_eq!(
        admin
            .post(&policy_url)
            .json(&update(3, Vec::<Value>::new()))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(next.get(&resources_url).send().await.is_err());
    assert_eq!(admin.get(&policy_url).send().await.unwrap().status(), 200);
    assert_eq!(
        admin
            .post(&policy_url)
            .json(&update(4, vec![next_entry]))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(next.get(&resources_url).send().await.unwrap().status(), 200);
    assert_eq!(
        request()
            .basic_auth("", Some("secret"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        std::fs::read(host.runtime.nodes.join(&job.node_id).join("phoenix.conf")).unwrap(),
        unchanged_credentials
    );
    assert_eq!(unsafe { libc::kill(node_pid as i32, 0) }, 0);
    let persisted = crate::control_identity::ControlIdentity::open(&host.args).unwrap();
    assert_eq!(persisted.status().unwrap()["revision"], 5);
    let old_fingerprint = crate::control_identity::fingerprint(
        rustls_pemfile::certs(&mut std::io::Cursor::new(
            std::fs::read(root.join("client.pem")).unwrap(),
        ))
        .next()
        .unwrap()
        .unwrap()
        .as_ref(),
    );
    assert!(persisted.role(&old_fingerprint).is_none());
    let control_client = next;
    assert!(crate::protocol::hostname("heron-a1b2.other.example").is_none());
    let lifecycle = |id: &str, action: &str| json!({"operationId":format!("operation-{}",id.repeat(32)),"nodeId":job.node_id,"accountId":job.account_id,"action":action});
    let stop: Value = control_client
        .post(format!("{control_origin}/lifecycle"))
        .json(&lifecycle("a", "stop"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stop["status"], "stopped");
    assert_eq!(
        control_client
            .get(&channels_url)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        control_client
            .post(&close_url)
            .json(&close_input)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(backend.closes.lock().unwrap().len(), 2);
    let stopped_logs: Value = control_client
        .post(format!("{control_origin}/logs"))
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stopped_logs["total"], 8);
    let start: Value = control_client
        .post(format!("{control_origin}/lifecycle"))
        .json(&lifecycle("b", "start"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(start["status"], "starting");
    // A delayed retry of the previous Stop cannot undo the newer Start.
    let replay: Value = control_client
        .post(format!("{control_origin}/lifecycle"))
        .json(&lifecycle("a", "stop"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay["status"], "queued");
    assert!(
        host.runtime
            .nodes
            .join(&job.node_id)
            .join("phoenix.conf")
            .exists()
    );
    let final_stop: Value = control_client
        .post(format!("{control_origin}/lifecycle"))
        .json(&lifecycle("c", "stop"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(final_stop["status"], "stopped");
    drop(public_server);
    drop(control_server);
    let cleanup = host.clone();
    tokio::task::spawn_blocking(move || cleanup.runtime.stop_all())
        .await
        .unwrap();
    drop(client);
    drop(control_client);
    drop(anonymous);
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::task::spawn_blocking(move || drop(host))
        .await
        .unwrap();
    drop(backend);
    // Boot keeps an explicitly stopped wallet stopped and its reserved slot.
    tokio::task::spawn_blocking(move || {
        let reopened = Host::open(args).unwrap();
        assert_eq!(
            reopened.deployment(&job.deployment_id).unwrap()["status"],
            "stopped"
        );
        assert!(
            reopened
                .runtime
                .nodes
                .join(&job.node_id)
                .join("phoenix.conf")
                .exists()
        );
    })
    .await
    .unwrap();
    drop(folder);
}
