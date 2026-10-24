use crate::{Args, protocol::*};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{Kem, Serializable};
use serde_json::{Value, json};
use std::{path::PathBuf, process::Command, sync::Mutex};
use x509_parser::{extensions::GeneralName, prelude::*};

fn hook_command(executable: &std::path::Path, action: &str, settings: &std::path::Path) -> String {
    fn quote(path: &std::path::Path) -> String {
        let text = path.to_string_lossy();
        // Certbot validates the first whitespace-delimited word literally.
        // Nix executable paths need no quoting. Quote arguments only when needed.
        if text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            text.into_owned()
        } else {
            format!("'{}'", text.replace('\'', "'\\''"))
        }
    }
    format!("{} dns {} {}", quote(executable), action, quote(settings))
}

fn certbot_failure(stderr: &[u8]) -> &'static str {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    for (needle, code) in [
        ("invalidcontact", "acme_contact_rejected"),
        ("error registering", "acme_registration_failed"),
        ("read-only file system", "certificate_storage_read_only"),
        ("permission denied", "certificate_permission_denied"),
        ("unrecognized arguments", "certbot_arguments_invalid"),
        ("no such file or directory", "certificate_helper_missing"),
        ("certificate verify failed", "certificate_ca_trust_failed"),
        ("dns_challenge_failed", "cloudflare_challenge_failed"),
        ("hook", "certificate_dns_hook_failed"),
        ("dns problem", "acme_dns_validation_failed"),
        ("connection", "acme_connection_failed"),
        ("ratelimited", "acme_rate_limited"),
    ] {
        if text.contains(needle) {
            return code;
        }
    }
    "certbot_failed"
}

fn run_certbot(command: &mut Command) -> Result<()> {
    use std::{
        io::Read,
        os::unix::process::CommandExt,
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("certificate_helper_unavailable")?;
    let mut stderr = child
        .stderr
        .take()
        .context("certificate_helper_unavailable")?;
    let reader = thread::spawn(move || {
        let mut retained = Vec::new();
        let mut buffer = [0u8; 4096];
        while let Ok(count) = stderr.read(&mut buffer) {
            if count == 0 {
                break;
            }
            // Drain output continuously, retaining only a bounded tail in RAM.
            retained.extend_from_slice(&buffer[..count]);
            if retained.len() > 16384 {
                retained.drain(..retained.len() - 16384);
            }
        }
        retained
    });
    let deadline = Instant::now() + Duration::from_secs(600);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            let _ = reader.join();
            anyhow::bail!("certificate_helper_timeout");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stderr = reader
        .join()
        .map_err(|_| anyhow::anyhow!("certificate_helper_unavailable"))?;
    if !status.success() {
        anyhow::bail!(certbot_failure(&stderr));
    }
    Ok(())
}

const RECIPIENT: &[u8] = b"nodana-wildcard-recipient-v1\0";
const TRANSFER: &[u8] = b"nodana-wildcard-transfer-v1\0";
struct Pending {
    nonce: String,
    key: <K as Kem>::PrivateKey,
    expires: u64,
}
pub struct Certificates {
    pub root: PathBuf,
    args: Args,
    gate: Mutex<()>,
    pending: Mutex<Option<Pending>>,
    #[cfg(test)]
    test_verifier: Mutex<Option<fn(&Value, &[u8], &[u8]) -> Result<()>>>,
}
impl Certificates {
    pub fn new(args: Args) -> Result<Self> {
        let root = args.data.join("certificates").join(DOMAIN);
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            args,
            gate: Mutex::new(()),
            pending: Mutex::new(None),
            #[cfg(test)]
            test_verifier: Mutex::new(None),
        })
    }
    /// Synthetic peer verification for local transfer-state tests only.
    /// Production builds always verify AWS evidence in-process.
    #[cfg(test)]
    pub fn test_peer_verifier(&self, verifier: fn(&Value, &[u8], &[u8]) -> Result<()>) {
        *self.test_verifier.lock().unwrap() = Some(verifier);
    }
    #[cfg(test)]
    pub fn test_expire_recipient(&self) {
        if let Some(pending) = self.pending.lock().unwrap().as_mut() {
            pending.expires = 0;
        }
    }
    fn read(&self, name: &str) -> Result<Option<Value>> {
        let path = self.root.join(name);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&read_file(&path, 196608)?)?))
    }
    pub fn current(&self) -> Result<Option<Value>> {
        let value = self.read("current.json")?;
        if let Some(v) = &value {
            let fingerprint = v["fingerprint"]
                .as_str()
                .context("invalid certificate state")?;
            ensure!(
                fingerprint.len() == 64
                    && fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid certificate state"
            );
        }
        Ok(value)
    }
    pub fn files(&self, current: &Value) -> (PathBuf, PathBuf) {
        let folder = self.root.join("versions").join(
            current["fingerprint"]
                .as_str()
                .expect("validated fingerprint"),
        );
        (folder.join("fullchain.pem"), folder.join("privkey.pem"))
    }
    fn attempt(&self, environment: &str) -> Result<Value> {
        Ok(self
            .read(&format!("attempt-{environment}.json"))?
            .unwrap_or(json!({"attempted":false,"nextAttemptAt":0,"error":null})))
    }
    pub fn status(&self) -> Result<Value> {
        let config = self.read("config.json")?;
        let current = self.current()?;
        let environment = config
            .as_ref()
            .map(|v| v["environment"].clone())
            .unwrap_or(Value::Null);
        let ready = config.is_some()
            && current.as_ref().is_some_and(|v| {
                v["expiresAt"].as_f64().unwrap_or(0.) > now() as f64
                    && v["environment"] == environment
            });
        let attempt = if config.as_ref().is_some_and(|v| v["role"] == "issuer") {
            self.attempt(environment.as_str().context("invalid certificate config")?)?
        } else {
            json!({})
        };
        Ok(
            json!({"domain":format!("*.{DOMAIN}"),"role":config.as_ref().map(|v|v["role"].clone()),"status":if ready {if environment=="production" {"ready"}else{"staging_ready"}}else if config.is_some(){"pending"}else{"unconfigured"},"fingerprint":current.as_ref().map(|v|v["fingerprint"].clone()),"expiresAt":current.as_ref().map(|v|v["expiresAt"].clone()),"environment":environment,"error":attempt["error"],"failureReason":attempt["failureReason"],"retryRequired":attempt["attempted"]==true&&attempt["nextAttemptAt"].is_null()&&!attempt["error"].is_null()}),
        )
    }
    pub fn ready(&self) -> bool {
        self.status()
            .is_ok_and(|v| v["status"] == "ready" || v["status"] == "staging_ready")
    }
    pub fn configure(&self, mut value: Value) -> Result<Value> {
        let _guard = self
            .gate
            .try_lock()
            .map_err(|_| anyhow::anyhow!("certificate busy"))?;
        let role = value["role"]
            .as_str()
            .context("invalid configuration")?
            .to_owned();
        if role == "issuer" {
            fields(
                &value,
                &[
                    "role",
                    "email",
                    "environment",
                    "cloudflareToken",
                    "cloudflareZoneId",
                ],
            )?;
            ensure!(
                regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")?
                    .is_match(value["email"].as_str().unwrap_or("")),
                "invalid email"
            );
            ensure!(
                regex::Regex::new(r"^[A-Za-z0-9_-]{20,256}$")?
                    .is_match(value["cloudflareToken"].as_str().unwrap_or(""))
                    && regex::Regex::new(r"^[a-f0-9]{32}$")?
                        .is_match(value["cloudflareZoneId"].as_str().unwrap_or("")),
                "invalid DNS configuration"
            );
        } else {
            ensure!(role == "replica", "invalid role");
            let keys = value.as_object().context("invalid configuration")?;
            ensure!(
                keys.len() == 1 || (keys.len() == 2 && keys.contains_key("environment")),
                "invalid configuration"
            );
            if value["environment"].is_null() {
                value["environment"] = json!("production");
            }
        }
        ensure!(
            matches!(
                value["environment"].as_str(),
                Some("staging" | "production")
            ),
            "invalid environment"
        );
        if let Some(old) = self.read("config.json")? {
            ensure!(old["role"] == role, "certificate role conflict");
        }
        if role == "issuer" {
            atomic(
                &self.root.join("cloudflare.json"),
                &canonical(
                    &json!({"token":value["cloudflareToken"],"zoneId":value["cloudflareZoneId"]}),
                ),
            )?;
            value.as_object_mut().unwrap().remove("cloudflareToken");
        }
        atomic(&self.root.join("config.json"), &canonical(&value))?;
        self.status()
    }
    pub fn retry(&self, value: Value) -> Result<Value> {
        fields(&value, &[])?;
        let _guard = self
            .gate
            .try_lock()
            .map_err(|_| anyhow::anyhow!("certificate busy"))?;
        let config = self.read("config.json")?.context("issuer required")?;
        ensure!(config["role"] == "issuer", "issuer required");
        atomic(
            &self.root.join(format!(
                "attempt-{}.json",
                config["environment"]
                    .as_str()
                    .context("invalid environment")?
            )),
            &canonical(&json!({"attempted":false,"nextAttemptAt":0,"error":null})),
        )?;
        self.status()
    }
    pub fn tick(&self) -> Result<()> {
        let Ok(_guard) = self.gate.try_lock() else {
            return Ok(());
        };
        let Some(config) = self.read("config.json")? else {
            return Ok(());
        };
        if config["role"] != "issuer" {
            return Ok(());
        }
        let environment = config["environment"]
            .as_str()
            .context("invalid environment")?;
        let attempt = self.attempt(environment)?;
        if attempt["attempted"] == true && attempt["nextAttemptAt"].is_null() {
            return Ok(());
        }
        if attempt["nextAttemptAt"].as_f64().unwrap_or(0.) > now() as f64 {
            return Ok(());
        }
        let renewal = self
            .current()?
            .is_some_and(|v| v["environment"] == "production" && environment == "production");
        let path = self.root.join(format!("attempt-{environment}.json"));
        let mut state = json!({"attempted":true,"nextAttemptAt":if renewal{Some(now()+3600)}else{None},"error":"certificate_attempt_interrupted"});
        atomic(&path, &canonical(&state))?;
        match self.issue(&config) {
            Ok(()) => {
                state["error"] = Value::Null;
                state["nextAttemptAt"] = if environment == "production" {
                    json!(now() + 43200)
                } else {
                    Value::Null
                };
            }
            Err(error) => {
                // Export static classifications only, never Certbot output,
                // tokens, contact addresses, paths or raw helper errors.
                let reason = error.to_string();
                let allowed = [
                    "acme_contact_rejected",
                    "acme_registration_failed",
                    "certificate_storage_read_only",
                    "certificate_permission_denied",
                    "certbot_arguments_invalid",
                    "certificate_helper_missing",
                    "certificate_ca_trust_failed",
                    "cloudflare_challenge_failed",
                    "certificate_dns_hook_failed",
                    "acme_dns_validation_failed",
                    "acme_connection_failed",
                    "acme_rate_limited",
                    "certbot_failed",
                    "certificate_helper_unavailable",
                    "certificate_helper_timeout",
                ];
                state["failureReason"] = json!(if allowed.contains(&reason.as_str()) {
                    reason.as_str()
                } else {
                    "certificate_installation_failed"
                });
                state["error"] = json!(if renewal {
                    "certificate_renewal_failed"
                } else {
                    "certificate_issuance_failed"
                });
            }
        }
        atomic(&path, &canonical(&state))?;
        Ok(())
    }
    fn issue(&self, config: &Value) -> Result<()> {
        let environment = config["environment"]
            .as_str()
            .context("invalid environment")?;
        let directory = match environment {
            "staging" => "https://acme-staging-v02.api.letsencrypt.org/directory",
            "production" => "https://acme-v02.api.letsencrypt.org/directory",
            _ => anyhow::bail!("invalid environment"),
        };
        let acme = self.root.join(format!("acme-{environment}"));
        let temporary = tempfile::tempdir_in(&self.args.runtime_dir)?;
        let executable = std::env::current_exe()?;
        let hook =
            |action: &str| hook_command(&executable, action, &self.root.join("cloudflare.json"));
        let mut command = Command::new(&self.args.certbot);
        command
            .args([
                "certonly",
                "--non-interactive",
                "--agree-tos",
                "--keep-until-expiring",
                "--manual",
                "--preferred-challenges",
                "dns",
                "--manual-auth-hook",
                &hook("auth"),
                "--manual-cleanup-hook",
                &hook("cleanup"),
                "--cert-name",
                "nodana-wildcard",
                "--domains",
                &format!("*.{DOMAIN}"),
                "--email",
                config["email"].as_str().context("invalid email")?,
                "--server",
                directory,
                "--config-dir",
            ])
            .arg(&acme)
            .arg("--work-dir")
            .arg(temporary.path())
            .arg("--logs-dir")
            .arg(temporary.path());
        run_certbot(&mut command)?;
        let live = acme.join("live/nodana-wildcard");
        let root = acme.canonicalize()?;
        let certificate = live.join("fullchain.pem").canonicalize()?;
        let key = live.join("privkey.pem").canonicalize()?;
        ensure!(
            certificate.starts_with(&root) && key.starts_with(&root),
            "invalid ACME files"
        );
        self.install(
            &read_file(&certificate, 32768)?,
            &read_file(&key, 16384)?,
            environment,
        )
    }
    pub fn install(&self, certificate: &[u8], key: &[u8], environment: &str) -> Result<()> {
        ensure!(
            ["staging", "production"].contains(&environment)
                && certificate.len() <= 32768
                && key.len() <= 16384,
            "invalid certificate"
        );
        let chain = rustls_pemfile::certs(&mut std::io::Cursor::new(certificate))
            .collect::<std::io::Result<Vec<_>>>()?;
        let leaf = chain.first().context("missing certificate")?;
        let (_, parsed) = parse_x509_certificate(leaf.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid certificate"))?;
        let names = parsed.subject_alternative_name()?.context("missing SAN")?;
        ensure!(
            names.value.general_names.len() == 1
                && names.value.general_names[0] == GeneralName::DNSName(&format!("*.{DOMAIN}")),
            "invalid certificate names"
        );
        let expires = parsed.validity().not_after.timestamp();
        ensure!(
            parsed.validity().is_valid() && expires > now() as i64 + 3600,
            "expired certificate"
        );
        let private =
            rustls_pemfile::private_key(&mut std::io::Cursor::new(key))?.context("missing key")?;
        let signer = rustls::crypto::ring::sign::any_supported_type(&private)?;
        rustls::sign::CertifiedKey::new(chain, signer).keys_match()?;
        if let Some(current) = self.current()? {
            ensure!(
                current["environment"] != environment
                    || current["expiresAt"].as_f64().unwrap_or(0.) <= expires as f64,
                "certificate rollback"
            );
        }
        let fingerprint = hex::encode(digest(certificate));
        let folder = self.root.join("versions").join(&fingerprint);
        atomic(&folder.join("fullchain.pem"), certificate)?;
        atomic(&folder.join("privkey.pem"), key)?;
        atomic(
            &self.root.join("current.json"),
            &canonical(
                &json!({"fingerprint":fingerprint,"expiresAt":expires,"environment":environment}),
            ),
        )?;
        Ok(())
    }
    pub fn recipient(&self, value: Value) -> Result<Value> {
        fields(&value, &[])?;
        ensure!(
            self.read("config.json")?
                .is_some_and(|v| v["role"] == "replica"),
            "replica required"
        );
        let (key, public) = K::gen_keypair(&mut rand::rngs::OsRng);
        let nonce = encode(rand::random::<[u8; 32]>());
        let public = encode(public.to_bytes());
        let context = json!({"domain":DOMAIN,"nonce":nonce,"publicKey":public,"version":1});
        let document = attest(
            &self.args,
            &decode(&nonce, 32)?,
            &binding(RECIPIENT, &context, None),
        )?;
        *self.pending.lock().unwrap() = Some(Pending {
            nonce: nonce.clone(),
            key,
            expires: now() + 300,
        });
        Ok(json!({"nonce":nonce,"publicKey":public,"attestationDocument":encode(document)}))
    }
    fn verify(&self, document: &Value, nonce: &[u8], binding: &[u8]) -> Result<()> {
        #[cfg(test)]
        if let Some(verifier) = *self.test_verifier.lock().unwrap() {
            return verifier(document, nonce, binding);
        }
        let own_nonce = rand::random::<[u8; 32]>();
        let own_binding = digest(b"nodana-wildcard-source-policy-v1");
        let own = attest(&self.args, &own_nonce, &own_binding)?;
        let input = json!({"ownDocument":encode(own),"ownNonce":encode(own_nonce),"ownBinding":encode(own_binding),"document":document,"nonce":encode(nonce),"binding":encode(binding)});
        crate::attestation::verify_peer(&serde_json::from_value(input)?, now() * 1000)?;
        Ok(())
    }
    pub fn export(&self, value: Value) -> Result<Value> {
        fields(&value, &["nonce", "publicKey", "attestationDocument"])?;
        let nonce = decode(value["nonce"].as_str().context("missing nonce")?, 32)?;
        let public = value["publicKey"].as_str().context("missing key")?;
        decode(public, 32)?;
        let context =
            json!({"domain":DOMAIN,"nonce":value["nonce"],"publicKey":public,"version":1});
        self.verify(
            &value["attestationDocument"],
            &nonce,
            &binding(RECIPIENT, &context, None),
        )?;
        let current = self.current()?.context("certificate not ready")?;
        ensure!(
            current["expiresAt"].as_f64().unwrap_or(0.) > now() as f64,
            "expired certificate"
        );
        let (cert, key) = self.files(&current);
        let bundle = json!({"certificate":String::from_utf8(read_file(&cert,32768)?)?,"privateKey":String::from_utf8(read_file(&key,16384)?)?,"environment":current["environment"]});
        let mut info = TRANSFER.to_vec();
        info.extend(canonical(&context));
        let encrypted = seal(public, &canonical(&bundle), &info)?;
        let evidence = attest(
            &self.args,
            &nonce,
            &binding(TRANSFER, &context, Some(&encrypted)),
        )?;
        Ok(
            json!({"nonce":value["nonce"],"encryptedBundle":encode(encrypted),"attestationDocument":encode(evidence)}),
        )
    }
    pub fn receive(&self, value: Value) -> Result<Value> {
        fields(&value, &["nonce", "encryptedBundle", "attestationDocument"])?;
        let mut pending = self.pending.lock().unwrap();
        let challenge = pending.as_ref().context("challenge expired")?;
        ensure!(
            value["nonce"] == challenge.nonce && challenge.expires >= now(),
            "challenge expired"
        );
        let public = K::sk_to_pk(&challenge.key);
        let context = json!({"domain":DOMAIN,"nonce":challenge.nonce,"publicKey":encode(public.to_bytes()),"version":1});
        let encrypted = STANDARD.decode(
            value["encryptedBundle"]
                .as_str()
                .context("missing ciphertext")?,
        )?;
        ensure!(encrypted.len() <= 65536, "ciphertext too large");
        self.verify(
            &value["attestationDocument"],
            &decode(&challenge.nonce, 32)?,
            &binding(TRANSFER, &context, Some(&encrypted)),
        )?;
        let mut info = TRANSFER.to_vec();
        info.extend(canonical(&context));
        let bundle: Value = serde_json::from_slice(&open(&challenge.key, &encrypted, &info)?)?;
        fields(&bundle, &["certificate", "privateKey", "environment"])?;
        self.install(
            bundle["certificate"]
                .as_str()
                .context("missing certificate")?
                .as_bytes(),
            bundle["privateKey"]
                .as_str()
                .context("missing key")?
                .as_bytes(),
            bundle["environment"]
                .as_str()
                .context("missing environment")?,
        )?;
        *pending = None;
        self.status()
    }
}
pub fn fields(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().context("object required")?;
    ensure!(
        object.len() == fields.len() && fields.iter().all(|key| object.contains_key(*key)),
        "invalid fields"
    );
    Ok(())
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn certificate_helper_errors_export_only_static_codes() {
        for (text, expected) in [
            (
                "requests: Read-only file system /private/token-path",
                "certificate_storage_read_only",
            ),
            (
                "dns_challenge_failed token=synthetic-private-value",
                "cloudflare_challenge_failed",
            ),
            (
                "urn:ietf:params:acme:error:invalidContact test@example.org",
                "acme_contact_rejected",
            ),
            ("unexpected private output", "certbot_failed"),
        ] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf '%s' \"$1\" >&2; exit 1", "test", text]);
            assert_eq!(run_certbot(&mut command).unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn packaged_certbot_accepts_the_dns_hook_before_contacting_acme() {
        let Ok(certbot) = std::env::var("NODANA_TEST_CERTBOT") else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let auth = hook_command(&executable, "auth", &root.path().join("settings.json"));
        let cleanup = hook_command(&executable, "cleanup", &root.path().join("settings.json"));
        let mut command = Command::new(certbot);
        command
            .args([
                "certonly",
                "--non-interactive",
                "--agree-tos",
                "--manual",
                "--preferred-challenges",
                "dns",
                "--manual-auth-hook",
                &auth,
                "--manual-cleanup-hook",
                &cleanup,
                "--email",
                "test@example.org",
                "--domains",
                &format!("*.{DOMAIN}"),
                "--server",
                "https://127.0.0.1:1/directory",
            ])
            .arg("--config-dir")
            .arg(root.path().join("config"))
            .arg("--work-dir")
            .arg(root.path().join("work"))
            .arg("--logs-dir")
            .arg(root.path().join("work"));
        assert_eq!(
            run_certbot(&mut command).unwrap_err().to_string(),
            "acme_connection_failed",
            "hook validation must pass before the intentionally refused local connection"
        );
    }
}
