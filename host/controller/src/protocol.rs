use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{Deserializable, Kem, Serializable};
use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub const DOMAIN: &str = include_str!(concat!(env!("OUT_DIR"), "/public-domain.txt"));
pub type K = X25519HkdfSha256;
pub fn canonical(value: &impl Serialize) -> Vec<u8> {
    // Value maps are sorted; identity and HPKE contexts contain ASCII fields.
    serde_json::to_vec(&serde_json::to_value(value).expect("serializable value")).expect("JSON")
}
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    struct Unique(Value);
    impl<'de> serde::Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON without duplicate fields")
                }
                fn visit_map<M: serde::de::MapAccess<'de>>(
                    self,
                    mut map: M,
                ) -> std::result::Result<Unique, M::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some((key, value)) = map.next_entry::<String, Unique>()? {
                        if out.insert(key, value.0).is_some() {
                            return Err(serde::de::Error::custom("duplicate field"));
                        }
                    }
                    Ok(Unique(Value::Object(out)))
                }
                fn visit_seq<S: serde::de::SeqAccess<'de>>(
                    self,
                    mut sequence: S,
                ) -> std::result::Result<Unique, S::Error> {
                    let mut values = Vec::new();
                    while let Some(value) = sequence.next_element::<Unique>()? {
                        values.push(value.0);
                    }
                    Ok(Unique(Value::Array(values)))
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Bool(v)))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::String(v.into())))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json_number(v.into())))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json_number(v.into())))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique(
                        serde_json::Number::from_f64(v)
                            .map(Value::Number)
                            .ok_or_else(|| E::custom("invalid number"))?,
                    ))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    fn json_number(v: serde_json::Number) -> Value {
        Value::Number(v)
    }
    Ok(serde_json::from_slice::<Unique>(bytes)?.0)
}
pub fn encode(value: impl AsRef<[u8]>) -> String {
    STANDARD.encode(value)
}
pub fn decode(value: &str, length: usize) -> Result<Vec<u8>> {
    ensure!(value.len() == length.div_ceil(3) * 4, "invalid encoding");
    let bytes = STANDARD.decode(value)?;
    ensure!(
        bytes.len() == length && encode(&bytes) == value,
        "invalid encoding"
    );
    Ok(bytes)
}
pub fn id(value: &str, prefix: &str, size: usize) -> Result<()> {
    let suffix = value
        .strip_prefix(&format!("{prefix}-"))
        .ok_or_else(|| anyhow::anyhow!("invalid identifier"))?;
    ensure!(
        (suffix.len() == size || (prefix == "node" && suffix.len() == 4))
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "invalid identifier"
    );
    Ok(())
}
pub fn hostname(value: &str) -> Option<String> {
    let stem = value.strip_suffix(&format!(".{DOMAIN}"))?;
    let (name, suffix) = stem.rsplit_once('-')?;
    if name.is_empty()
        || name.len() > 24
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let node = format!("node-{suffix}");
    id(&node, "node", 8).ok()?;
    Some(node)
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    pub release_sha256: String,
    pub deployment_id: String,
    pub account_id: String,
    pub node_id: String,
    pub auto_liquidity: String,
    pub owner_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub url: String,
    pub secret: String,
}
impl Job {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::releases::checksum(&self.release_sha256),
            "invalid release identity"
        );
        id(&self.deployment_id, "deployment", 24)?;
        id(&self.node_id, "node", 8)?;
        id(&self.account_id, "account", 8)?;
        ensure!(
            ["2m", "5m", "10m"].contains(&self.auto_liquidity.as_str()),
            "invalid liquidity"
        );
        let public = <K as Kem>::PublicKey::from_bytes(&decode(&self.owner_public_key, 32)?)?;
        // HPKE setup rejects non-contributory/low-order recipient keys.
        hpke::setup_sender::<AesGcm256, HkdfSha256, K, _>(
            &hpke::OpModeS::Base,
            &public,
            b"validation",
            &mut rand::rngs::OsRng,
        )?;
        if let Some(name) = &self.public_hostname {
            ensure!(
                hostname(name).as_deref() == Some(&self.node_id),
                "invalid hostname"
            );
        }
        if let Some(webhook) = &self.webhook {
            let url = url::Url::parse(&webhook.url)?;
            ensure!(
                webhook.url.len() <= 2048
                    && !webhook.url.chars().any(char::is_whitespace)
                    && url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "invalid webhook"
            );
            ensure!(
                regex::Regex::new(r"^/v1/webhooks/phoenixd/webhook-[a-f0-9]{32}$")?
                    .is_match(url.path())
                    && webhook.secret.len() == 64
                    && webhook
                        .secret
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid webhook"
            );
        }
        Ok(())
    }
}
pub fn seal(public: &str, plaintext: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    let key = <K as Kem>::PublicKey::from_bytes(&decode(public, 32)?)?;
    let (enc, mut sender) = hpke::setup_sender::<AesGcm256, HkdfSha256, K, _>(
        &hpke::OpModeS::Base,
        &key,
        info,
        &mut rand::rngs::OsRng,
    )?;
    let mut output = enc.to_bytes().to_vec();
    output.extend(sender.seal(plaintext, b"")?);
    Ok(output)
}
pub fn open(key: &<K as Kem>::PrivateKey, ciphertext: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        (48..=65536).contains(&ciphertext.len()),
        "invalid ciphertext"
    );
    let enc = <K as Kem>::EncappedKey::from_bytes(&ciphertext[..32])?;
    let mut recipient =
        hpke::setup_receiver::<AesGcm256, HkdfSha256, K>(&hpke::OpModeR::Base, key, &enc, info)?;
    Ok(recipient.open(&ciphertext[32..], b"")?)
}
pub fn digest(value: impl AsRef<[u8]>) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}
pub fn attest(args: &crate::Args, nonce: &[u8], binding: &[u8]) -> Result<Vec<u8>> {
    let folder = tempfile::tempdir_in(&args.runtime_dir)?;
    std::fs::write(folder.path().join("nonce"), nonce)?;
    std::fs::write(folder.path().join("binding"), binding)?;
    let output = run_command(
        Command::new(&args.attest_binary)
            .arg("--nonce")
            .arg(folder.path().join("nonce"))
            .arg("--user-data")
            .arg(folder.path().join("binding")),
        None,
        30,
        65536,
    )?;
    ensure!(!output.is_empty(), "attestation unavailable");
    Ok(output)
}
pub fn run_command(
    command: &mut Command,
    input: Option<&[u8]>,
    seconds: u64,
    maximum: usize,
) -> Result<Vec<u8>> {
    run_command_accepted(command, input, seconds, maximum, &[0])
}
pub fn run_command_accepted(
    command: &mut Command,
    input: Option<&[u8]>,
    seconds: u64,
    maximum: usize,
    accepted: &[i32],
) -> Result<Vec<u8>> {
    use std::os::unix::process::CommandExt;
    use std::{
        io::Read,
        thread,
        time::{Duration, Instant},
    };
    let mut child = command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(if maximum == 0 {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::null())
        .spawn()?;
    let stdin = child.stdin.take();
    let input = input.map(Vec::from);
    let writer = thread::spawn(move || {
        if let (Some(mut pipe), Some(input)) = (stdin, input) {
            let _ = pipe.write_all(&input);
        }
    });
    let stdout = child.stdout.take();
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stdout) = stdout {
            let _ = stdout
                .by_ref()
                .take((maximum + 1) as u64)
                .read_to_end(&mut bytes);
        }
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(anyhow::anyhow!("helper timeout"));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("helper failed"))?;
    ensure!(
        status.code().is_some_and(|code| accepted.contains(&code)) && bytes.len() <= maximum,
        "helper failed"
    );
    Ok(bytes)
}
pub fn read_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "invalid file");
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "file too large");
    Ok(bytes)
}
pub fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let folder = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid path"))?;
    std::fs::create_dir_all(folder)?;
    let mut file = tempfile::NamedTempFile::new_in(folder)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    std::fs::File::open(folder)?.sync_all()?;
    Ok(())
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn binding(prefix: &[u8], context: &Value, ciphertext: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    bytes.extend(canonical(context));
    if let Some(ciphertext) = ciphertext {
        bytes.extend(digest(ciphertext));
    }
    digest(bytes)
}
