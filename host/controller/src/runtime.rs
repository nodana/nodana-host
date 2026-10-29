use crate::{host::fail, protocol::*};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateInvoice {
    pub amount_sat: u64,
    pub description: String,
    pub expiry_seconds: Option<u32>,
    pub external_id: Option<String>,
}

impl CreateInvoice {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.amount_sat > 0 && self.amount_sat <= 9_007_199_254_740_991,
            "invalid amount"
        );
        ensure!(
            !self.description.trim().is_empty() && self.description.chars().count() <= 128,
            "invalid description"
        );
        ensure!(self.expiry_seconds != Some(0), "invalid expiry");
        ensure!(
            self.external_id
                .as_ref()
                .is_none_or(|v| !v.trim().is_empty() && v.chars().count() <= 128),
            "invalid external id"
        );
        Ok(())
    }
}

#[derive(serde::Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedInvoice {
    pub amount_sat: u64,
    pub payment_hash: String,
    pub serialized: String,
}

impl CreatedInvoice {
    pub fn validate(&self, request: &CreateInvoice) -> Result<()> {
        ensure!(
            self.amount_sat == request.amount_sat,
            "invalid invoice amount"
        );
        ensure!(
            self.payment_hash.len() == 64
                && self
                    .payment_hash
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
            "invalid payment hash"
        );
        ensure!(
            (self.serialized.starts_with("lnbc") || self.serialized.starts_with("lntb"))
                && self.serialized.len() > 6
                && self.serialized.len() <= 16384
                && self
                    .serialized
                    .bytes()
                    .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit()),
            "invalid invoice"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateOffer {
    pub description: Option<String>,
    pub amount_sat: Option<u64>,
}

impl CreateOffer {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.description
                .as_ref()
                .is_none_or(|v| !v.trim().is_empty() && v.chars().count() <= 128),
            "invalid description"
        );
        ensure!(
            self.amount_sat
                .is_none_or(|v| v > 0 && v <= 9_007_199_254_740_991),
            "invalid amount"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloseChannel {
    pub channel_id: String,
    pub address: String,
    pub feerate_sat_byte: u64,
}

impl CloseChannel {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.channel_id.len() == 64 && self.channel_id.bytes().all(|v| v.is_ascii_hexdigit()),
            "invalid channel id"
        );
        // Phoenixd validates the address and network. Bound the wire value here;
        // never reinterpret it or choose a destination on the caller's behalf.
        ensure!(
            (14..=90).contains(&self.address.len())
                && self.address.bytes().all(|v| v.is_ascii_alphanumeric()),
            "invalid address"
        );
        ensure!(
            self.feerate_sat_byte > 0 && self.feerate_sat_byte <= i64::MAX as u64 / 250,
            "invalid fee rate"
        );
        Ok(())
    }
}

struct Process {
    child: Child,
    slot: usize,
    release: Option<String>,
}
pub struct Runtime {
    pub nodes: PathBuf,
    binary: PathBuf,
    pub releases: Option<crate::releases::Releases>,
    processes: Mutex<BTreeMap<String, Process>>,
    client: reqwest::blocking::Client,
    minimum: Mutex<u64>,
    startup: Mutex<BTreeMap<String, &'static str>>,
}
impl Runtime {
    pub fn install_credentials(&self, node: &str, slot: usize, value: &Value) -> Result<()> {
        let uid = 20000 + slot as u32;
        self.install_credentials_as(node, value, uid, uid)
    }
    fn install_credentials_as(&self, node: &str, value: &Value, uid: u32, gid: u32) -> Result<()> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Credentials {
            seed: String,
            password: String,
            restricted_password: String,
        }
        let credentials: Credentials = serde_json::from_value(value.clone())?;
        ensure!(
            credentials.seed.split_whitespace().count() == 12
                && credentials
                    .seed
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b' ')
                && [&credentials.password, &credentials.restricted_password]
                    .iter()
                    .all(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                && credentials.password != credentials.restricted_password,
            "invalid creation credentials"
        );
        let root = self.nodes.join(node);
        std::fs::create_dir_all(&root)?;
        ensure!(
            !root.symlink_metadata()?.file_type().is_symlink(),
            "invalid node directory"
        );
        if root.join("seed.dat").exists() || root.join("phoenix.conf").exists() {
            ensure!(
                self.credentials(node)? == *value,
                "existing credentials conflict"
            );
            return Ok(());
        }
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        atomic(&root.join("seed.dat"), credentials.seed.as_bytes())?;
        atomic(
            &root.join("phoenix.conf"),
            format!(
                "http-password={}\nhttp-password-limited-access={}\n",
                credentials.password, credentials.restricted_password
            )
            .as_bytes(),
        )?;
        for path in [&root, &root.join("seed.dat"), &root.join("phoenix.conf")] {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
        }
        std::fs::File::open(&root)?.sync_all()?;
        Ok(())
    }
    #[cfg(test)]
    pub fn test_process(&self, node: &str, slot: usize, child: Child) {
        self.processes.lock().unwrap().insert(
            node.into(),
            Process {
                child,
                slot,
                release: None,
            },
        );
    }
    #[cfg(all(test, target_os = "linux"))]
    pub fn test_native_process(&self, node: &str, child: Child, release: String) {
        self.processes.lock().unwrap().insert(
            node.into(),
            Process {
                child,
                slot: 0,
                release: Some(release),
            },
        );
    }
    pub fn new(data: &Path, binary: PathBuf) -> Result<Self> {
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o711))?;
        let nodes = data.join("nodes");
        std::fs::create_dir_all(&nodes)?;
        std::fs::set_permissions(&nodes, std::fs::Permissions::from_mode(0o711))?;
        Ok(Self {
            nodes,
            binary: binary.canonicalize()?,
            releases: None,
            processes: Mutex::new(BTreeMap::new()),
            client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()?,
            minimum: Mutex::new(u64::MAX),
            startup: Mutex::new(BTreeMap::new()),
        })
    }
    pub fn passwords(&self, node: &str) -> Result<(String, String)> {
        id(node, "node", 8)?;
        let text = String::from_utf8(read_file(
            &self.nodes.join(node).join("phoenix.conf"),
            8192,
        )?)?;
        let find = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .context("credentials pending")
        };
        Ok((
            find("http-password")?,
            find("http-password-limited-access")?,
        ))
    }
    pub fn credentials(&self, node: &str) -> Result<Value> {
        let (full, limited) = self.passwords(node)?;
        let seed = String::from_utf8(read_file(&self.nodes.join(node).join("seed.dat"), 8192)?)?;
        ensure!(!seed.trim().is_empty(), "credentials pending");
        Ok(json!({"seed":seed.trim(),"password":full,"restrictedPassword":limited}))
    }
    pub fn healthy(&self, node: &str) -> bool {
        self.processes
            .lock()
            .unwrap()
            .get_mut(node)
            .is_some_and(|p| p.child.try_wait().is_ok_and(|status| status.is_none()))
    }
    pub fn release_identity(&self, node: &str) -> Result<Value> {
        let mut processes = self.processes.lock().unwrap();
        let process = processes.get_mut(node).context("node not running")?;
        ensure!(process.child.try_wait()?.is_none(), "node not running");
        #[cfg(test)]
        if process.release.is_none() {
            return Ok(
                json!({"releaseSha256":"a".repeat(64),"version":"0.1.0","phoenixdVersion":"0.9.3","stateFormat":"phoenixd-0.9.3"}),
            );
        }
        let release = process
            .release
            .as_deref()
            .context("runtime bundle unavailable")?;
        let releases = self
            .releases
            .as_ref()
            .context("release store unavailable")?;
        let identity = releases.identity(release)?;
        // The launcher execs the bundled loader. Check the live process's loader
        // inode and Phoenixd argument, rather than attesting the desired target.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let root = releases.store.join(release);
            let expected = std::fs::metadata(root.join("lib/ld.so"))?;
            let actual = std::fs::metadata(format!("/proc/{}/exe", process.child.id()))?;
            ensure!(
                expected.dev() == actual.dev() && expected.ino() == actual.ino(),
                "runtime executable mismatch"
            );
            let command = std::fs::read(format!("/proc/{}/cmdline", process.child.id()))?;
            ensure!(
                command
                    .split(|v| *v == 0)
                    .any(|v| v == root.join("libexec/phoenixd").as_os_str().as_encoded_bytes()),
                "runtime payload mismatch"
            );
        }
        Ok(identity)
    }
    pub fn start(&self, job: &Job, slot: usize, previous: bool) -> Result<()> {
        self.startup
            .lock()
            .unwrap()
            .insert(job.node_id.clone(), "preparing");
        let result = self.start_inner(job, slot, previous);
        if result.is_err() {
            // Only fixed diagnostic labels leave the host. Child output and
            // errors can contain wallet material, passwords or request data.
            let stages = self.startup.lock().unwrap();
            let stage = stages.get(&job.node_id).copied().unwrap_or("preparing");
            let hint = self.startup_log_hint(&job.node_id);
            eprintln!(
                "NODANA_NODE_STARTUP_FAILED node={} stage={stage} hint={hint}",
                job.node_id
            );
        }
        result
    }
    fn startup_log_hint(&self, node: &str) -> &'static str {
        let tail = (|| -> Result<Vec<u8>> {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.nodes.join(node).join("console.log"))?;
            let size = file.metadata()?.len();
            file.seek(SeekFrom::Start(size.saturating_sub(65536)))?;
            let mut bytes = Vec::new();
            file.take(65536).read_to_end(&mut bytes)?;
            Ok(bytes)
        })()
        .unwrap_or_default();
        let text = String::from_utf8_lossy(&tail).to_ascii_lowercase();
        for (pattern, label) in [
            ("no space left on device", "disk_full"),
            ("permission denied", "permission_denied"),
            ("address already in use", "port_in_use"),
            ("outofmemoryerror", "runtime_out_of_memory"),
            ("unknownhostexception", "dns_failure"),
            ("connection refused", "connection_refused"),
            ("connection timed out", "connection_timeout"),
        ] {
            if text.contains(pattern) {
                return label;
            }
        }
        "unclassified"
    }
    fn start_inner(&self, job: &Job, slot: usize, previous: bool) -> Result<()> {
        let root = self.nodes.join(&job.node_id);
        if previous {
            ensure!(
                root.join("seed.dat").is_file()
                    && root.join("phoenix.conf").is_file()
                    && std::fs::read_dir(&root)?
                        .filter_map(Result::ok)
                        .any(|e| e.path().extension().is_some_and(|v| v == "db")),
                "existing node data missing"
            );
            self.credentials(&job.node_id)?;
        }
        std::fs::create_dir_all(&root)?;
        ensure!(
            !root.symlink_metadata()?.file_type().is_symlink(),
            "invalid node directory"
        );
        let uid = 20000 + slot as u32;
        std::os::unix::fs::chown(&root, Some(uid), Some(uid))?;
        if let Some(webhook) = &job.webhook {
            configure_webhook(&root, webhook, uid, uid)?;
        }
        let temporary = root.join("tmp");
        std::fs::create_dir_all(&temporary)?;
        ensure!(
            !temporary.symlink_metadata()?.file_type().is_symlink(),
            "invalid temporary directory"
        );
        std::os::unix::fs::chown(&temporary, Some(uid), Some(uid))?;
        let console = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("console.log"))?;
        let binary = match &self.releases {
            Some(releases) => releases.entrypoint(&job.release_sha256)?,
            None => {
                ensure!(cfg!(test), "native release store required");
                self.binary.clone()
            }
        };
        let mut command = Command::new(binary);
        command
            .args([
                "--chain=mainnet",
                "--http-bind-ip=127.0.0.1",
                &format!("--http-bind-port={}", 20000 + slot),
                &format!("--auto-liquidity={}", job.auto_liquidity),
                "--max-mining-fee=5000",
                "--agree-to-terms-of-service",
            ])
            .env_clear()
            .env("HOME", &root)
            .env("PHOENIX_DATADIR", &root)
            .env("TMPDIR", temporary)
            .env("TZ", "UTC")
            .env("PATH", "/run/current-system/sw/bin:/usr/bin:/bin")
            .stdin(Stdio::null())
            .stderr(console.try_clone()?)
            .stdout(console);
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0
                    || libc::setgroups(0, std::ptr::null()) < 0
                    || libc::setgid(uid) < 0
                    || libc::setuid(uid) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        self.processes.lock().unwrap().insert(
            job.node_id.clone(),
            Process {
                child,
                slot,
                release: Some(job.release_sha256.clone()),
            },
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if !self.healthy(&job.node_id) {
                self.startup
                    .lock()
                    .unwrap()
                    .insert(job.node_id.clone(), "process_exited");
                anyhow::bail!("node startup failed");
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let ready = self.startup_probe(&job.node_id, slot, remaining);
            let stage = ready.err().unwrap_or("ready");
            self.startup
                .lock()
                .unwrap()
                .insert(job.node_id.clone(), stage);
            if ready.is_ok() {
                if self.releases.is_some() {
                    self.release_identity(&job.node_id)?;
                }
                unsafe {
                    libc::sync();
                }
                return Ok(());
            }
            std::thread::sleep(
                Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        anyhow::bail!("node startup timeout")
    }
    fn startup_probe(
        &self,
        node: &str,
        slot: usize,
        remaining: Duration,
    ) -> std::result::Result<(), &'static str> {
        let password = self.passwords(node).map_err(|_| "credentials_pending")?.0;
        if remaining.is_zero() {
            return Err("http_timeout");
        }
        let response = self
            .client
            .get(format!("http://127.0.0.1:{}/getinfo", 20000 + slot))
            .basic_auth("", Some(password))
            .timeout(remaining.min(Duration::from_secs(10)))
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    "http_timeout"
                } else {
                    "http_unavailable"
                }
            })?;
        match response.status().as_u16() {
            200 => {}
            401 | 403 => return Err("http_unauthorized"),
            _ => return Err("http_error"),
        }
        let mut bytes = Vec::new();
        response
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| "http_read_failed")?;
        if bytes.len() > 65536 {
            return Err("invalid_response");
        }
        let info: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_response")?;
        if info["chain"] != "mainnet" {
            return Err("unexpected_chain");
        }
        self.credentials(node).map_err(|_| "seed_pending")?;
        Ok(())
    }
    pub fn proxy(
        &self,
        node: &str,
        method: &str,
        path: &str,
        authorization: Option<&reqwest::header::HeaderValue>,
        body: Option<Vec<u8>>,
        content_type: &str,
        maximum: usize,
    ) -> Result<(u16, reqwest::header::HeaderMap, Vec<u8>)> {
        let slot = {
            let mut processes = self.processes.lock().unwrap();
            let process = processes.get_mut(node).context("node not running")?;
            ensure!(process.child.try_wait()?.is_none(), "node stopped");
            process.slot
        };
        ensure!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains(['\r', '\n']),
            "invalid path"
        );
        let mut request = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_bytes())?,
                format!("http://127.0.0.1:{}{path}", 20000 + slot),
            )
            .header("Content-Type", content_type);
        if let Some(value) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, value.clone());
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send()?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        response
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= maximum, "response too large");
        Ok((status, headers, bytes))
    }
    fn read(&self, node: &str, path: &str, password: &str, maximum: usize) -> Result<Value> {
        let authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Basic {}",
            encode(format!(":{password}"))
        ))?;
        let (status, _, body) = self.proxy(
            node,
            "GET",
            path,
            Some(&authorization),
            None,
            "application/json",
            maximum,
        )?;
        ensure!(status == 200, "node read failed");
        Ok(serde_json::from_slice(&body)?)
    }
    pub fn create_invoice(&self, node: &str, request: &CreateInvoice) -> Result<Value> {
        request.validate()?;
        let password = self.passwords(node)?.1;
        let authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Basic {}",
            encode(format!(":{password}"))
        ))?;
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("amountSat", &request.amount_sat.to_string());
        form.append_pair("description", &request.description);
        if let Some(expiry) = request.expiry_seconds {
            form.append_pair("expirySeconds", &expiry.to_string());
        }
        if let Some(reference) = &request.external_id {
            form.append_pair("externalId", reference);
        }
        let (status, _, body) = self.proxy(
            node,
            "POST",
            "/createinvoice",
            Some(&authorization),
            Some(form.finish().into_bytes()),
            "application/x-www-form-urlencoded",
            32768,
        )?;
        ensure!(status == 200, "node invoice creation failed");
        let invoice: CreatedInvoice = serde_json::from_slice(&body)?;
        invoice.validate(request)?;
        Ok(serde_json::to_value(invoice)?)
    }

    pub fn create_offer(&self, node: &str, request: &CreateOffer) -> Result<Value> {
        request.validate()?;
        let password = self.passwords(node)?.0;
        let authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Basic {}",
            encode(format!(":{password}"))
        ))?;
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair(
            "description",
            request.description.as_deref().unwrap_or("Nodana offer"),
        );
        if let Some(amount) = request.amount_sat {
            form.append_pair("amountSat", &amount.to_string());
        }
        let (status, _, body) = self.proxy(
            node,
            "POST",
            "/createoffer",
            Some(&authorization),
            Some(form.finish().into_bytes()),
            "application/x-www-form-urlencoded",
            16384,
        )?;
        ensure!(status == 200, "node offer creation failed");
        let offer = std::str::from_utf8(&body)?.trim();
        ensure!(
            offer.starts_with("lno1")
                && offer
                    .bytes()
                    .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit()),
            "invalid offer response"
        );
        Ok(json!({"offer":offer}))
    }

    pub fn list_channels(&self, node: &str) -> Result<Value> {
        let password = self.passwords(node)?.0;
        let channels = self.read(node, "/listchannels", &password, 4 * 1024 * 1024)?;
        ensure!(
            channels
                .as_array()
                .is_some_and(|values| values.iter().all(Value::is_object)),
            "invalid channels response"
        );
        Ok(channels)
    }

    pub fn close_channel(&self, node: &str, request: &CloseChannel) -> Result<Value> {
        request.validate()?;
        let password = self.passwords(node)?.0;
        let authorization = reqwest::header::HeaderValue::from_str(&format!(
            "Basic {}",
            encode(format!(":{password}"))
        ))?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("channelId", &request.channel_id)
            .append_pair("address", &request.address)
            .append_pair("feerateSatByte", &request.feerate_sat_byte.to_string())
            .finish()
            .into_bytes();
        let (status, _, bytes) = self.proxy(
            node,
            "POST",
            "/closechannel",
            Some(&authorization),
            Some(body),
            "application/x-www-form-urlencoded",
            16384,
        )?;
        ensure!(status == 200, "node channel close failed");
        let tx_id = std::str::from_utf8(&bytes)?.trim();
        if tx_id.len() != 64 || !tx_id.bytes().all(|v| v.is_ascii_hexdigit()) {
            return Err(fail(409, "channel_close_failed"));
        }
        Ok(json!({"txId":tx_id}))
    }

    pub fn public_key(&self, node: &str) -> Result<String> {
        let password = self.passwords(node)?.0;
        self.read(node, "/getinfo", &password, 65536)?["nodeId"]
            .as_str()
            .map(str::to_owned)
            .context("missing node key")
    }
    pub fn dashboard(&self, job: &Job) -> Result<Value> {
        let password = self.passwords(&job.node_id)?.0;
        let balance = self.read(&job.node_id, "/getbalance", &password, 65536)?;
        let info = self.read(&job.node_id, "/getinfo", &password, 65536)?;
        let amount = match job.auto_liquidity.as_str() {
            "2m" => 2000000,
            "5m" => 5000000,
            _ => 10000000,
        };
        let estimate = self.read(
            &job.node_id,
            &format!("/estimateliquidityfees?amountSat={amount}"),
            &password,
            65536,
        )?;
        let channels: Vec<Value> = info["channels"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| {
                allow(
                    v,
                    &["state", "balanceSat", "inboundLiquiditySat", "capacitySat"],
                )
            })
            .collect();
        let mut info = allow(&info, &["nodeId", "chain", "version", "blockHeight"]);
        info["channels"] = json!(channels);
        Ok(
            json!({"balance":allow(&balance,&["balanceSat","feeCreditSat"]),"info":info,"liquidityFeeEstimate":allow(&estimate,&["miningFeeSat","serviceFeeSat"])}),
        )
    }
    pub fn incoming(&self, node: &str, offset: u64, to: u64) -> Result<Value> {
        let password = self.passwords(node)?.0;
        let data = self.read(
            node,
            &format!("/payments/incoming?all=true&limit=500&offset={offset}&to={to}"),
            &password,
            4 * 1024 * 1024,
        )?;
        let values = data.as_array().context("invalid node response")?;
        ensure!(values.len() <= 500, "invalid node response");
        Ok(json!(
            values
                .iter()
                .map(|v| allow(
                    v,
                    &[
                        "paymentHash",
                        "externalId",
                        "isPaid",
                        "requestedSat",
                        "receivedSat",
                        "fees",
                        "completedAt",
                        "createdAt"
                    ]
                ))
                .collect::<Vec<_>>()
        ))
    }
    pub fn stop(&self, node: &str) {
        let process = self.processes.lock().unwrap().remove(node);
        if let Some(mut process) = process {
            if process.child.try_wait().ok().flatten().is_none() {
                unsafe {
                    libc::kill(-(process.child.id() as i32), libc::SIGTERM);
                }
                let deadline = Instant::now() + Duration::from_secs(30);
                while Instant::now() < deadline {
                    if process.child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                if process.child.try_wait().ok().flatten().is_none() {
                    unsafe {
                        libc::kill(-(process.child.id() as i32), libc::SIGKILL);
                    }
                }
            }
            let _ = process.child.wait();
        }
    }
    pub fn stop_all(&self) {
        let nodes: Vec<String> = self.processes.lock().unwrap().keys().cloned().collect();
        for node in nodes {
            self.stop(&node);
        }
    }
    pub fn delete(&self, node: &str) -> Result<()> {
        id(node, "node", 8)?;
        self.stop(node);
        self.startup.lock().unwrap().remove(node);
        let root = self.nodes.join(node);
        if root.exists() {
            ensure!(
                !root.symlink_metadata()?.file_type().is_symlink(),
                "invalid node directory"
            );
            std::fs::remove_dir_all(root)?;
            std::fs::File::open(&self.nodes)?.sync_all()?;
        }
        Ok(())
    }
    pub fn resources(&self) -> Value {
        let available = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("MemAvailable:")
                        .and_then(|v| v.split_whitespace().next())
                        .and_then(|v| v.parse::<u64>().ok())
                })
            })
            .unwrap_or(0);
        let mut minimum = self.minimum.lock().unwrap();
        *minimum = (*minimum).min(available);
        let mut nodes = serde_json::Map::new();
        for (node, process) in self.processes.lock().unwrap().iter_mut() {
            if process.child.try_wait().ok().flatten().is_none() {
                let status =
                    std::fs::read_to_string(format!("/proc/{}/status", process.child.id()))
                        .unwrap_or_default();
                let field = |key: &str| {
                    status
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix(key)
                                .and_then(|v| v.split_whitespace().next())
                                .and_then(|v| v.parse::<u64>().ok())
                        })
                        .unwrap_or(0)
                };
                nodes.insert(
                    node.clone(),
                    json!({"rssKiB":field("VmRSS:"),"peakRssKiB":field("VmHWM:")}),
                );
            }
        }
        json!({"nodes":nodes,"memoryAvailableKiB":available,"minimumMemoryAvailableKiB":*minimum,"startupStages":*self.startup.lock().unwrap()})
    }
}
pub(crate) fn configure_webhook(
    root: &std::path::Path,
    webhook: &crate::protocol::Webhook,
    uid: u32,
    gid: u32,
) -> Result<()> {
    let path = root.join("phoenix.conf");
    let text = if path.exists() {
        String::from_utf8(read_file(&path, 8192)?)?
    } else {
        String::new()
    };
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| {
            !line.trim_start().starts_with("webhook=")
                && !line.trim_start().starts_with("webhook-secret=")
        })
        .map(str::to_owned)
        .collect();
    lines.extend([
        format!("webhook={}", webhook.url),
        format!("webhook-secret={}", webhook.secret),
    ]);
    atomic(&path, (lines.join("\n") + "\n").as_bytes())?;
    std::os::unix::fs::chown(&path, Some(uid), Some(gid))?;
    Ok(())
}
fn allow(value: &Value, keys: &[&str]) -> Value {
    Value::Object(
        keys.iter()
            .filter_map(|key| value.get(key).map(|v| ((*key).to_owned(), v.clone())))
            .collect(),
    )
}

#[cfg(test)]
mod startup_tests {
    use super::*;
    use std::{io::Write, net::TcpListener};

    #[test]
    fn supplied_credentials_are_written_before_launch_and_never_replaced() {
        let folder = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(folder.path(), std::env::current_exe().unwrap()).unwrap();
        let value = json!({"seed":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "password":"a".repeat(64), "restrictedPassword":"b".repeat(64)});
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        runtime
            .install_credentials_as("node-test", &value, uid, gid)
            .unwrap();
        assert_eq!(runtime.credentials("node-test").unwrap(), value);
        runtime
            .install_credentials_as("node-test", &value, uid, gid)
            .unwrap();
        let mut changed = value.clone();
        changed["seed"] =
            json!("legal winner thank year wave sausage worth useful legal winner thank yellow");
        assert!(
            runtime
                .install_credentials_as("node-test", &changed, uid, gid)
                .is_err()
        );
        assert_eq!(runtime.credentials("node-test").unwrap(), value);
        for name in ["seed.dat", "phoenix.conf"] {
            assert_eq!(
                std::fs::metadata(runtime.nodes.join("node-test").join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(runtime.processes.lock().unwrap().is_empty());
    }

    #[test]
    fn readiness_uses_full_password_and_bounds_a_stalled_http_request() {
        let folder = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(folder.path(), std::env::current_exe().unwrap()).unwrap();
        let root = runtime.nodes.join("node-test");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("phoenix.conf"),
            "http-password=full-secret\nhttp-password-limited-access=limited-secret\n",
        )
        .unwrap();
        std::fs::write(root.join("seed.dat"), "private wallet material").unwrap();
        for stalled in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let slot = listener.local_addr().unwrap().port() as usize - 20000;
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 8192];
                let count = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..count]).to_ascii_lowercase();
                assert!(request.contains(&format!(
                    "authorization: basic {}",
                    encode(":full-secret").to_ascii_lowercase()
                )));
                if stalled {
                    std::thread::sleep(Duration::from_millis(150));
                } else {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"chain\":\"mainnet\"}").unwrap();
                }
            });
            let started = Instant::now();
            let result = runtime.startup_probe("node-test", slot, Duration::from_millis(50));
            if stalled {
                assert_eq!(result, Err("http_timeout"));
                assert!(started.elapsed() < Duration::from_millis(140));
            } else {
                assert_eq!(result, Ok(()));
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn startup_log_hint_exports_only_fixed_labels() {
        let folder = tempfile::tempdir().unwrap();
        let runtime = Runtime::new(folder.path(), std::env::current_exe().unwrap()).unwrap();
        let root = runtime.nodes.join("node-test");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("console.log"),
            "password=private-value seed=private-wallet No space left on device",
        )
        .unwrap();
        assert_eq!(runtime.startup_log_hint("node-test"), "disk_full");
        std::fs::write(
            root.join("console.log"),
            "password=private-value seed=private-wallet arbitrary failure",
        )
        .unwrap();
        assert_eq!(runtime.startup_log_hint("node-test"), "unclassified");
        assert!(!runtime.resources().to_string().contains("private"));
    }
}
