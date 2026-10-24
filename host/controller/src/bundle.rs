//! Signed native bundles. Wallet paths and executable selection are never inputs.
use crate::protocol::{canonical, digest, parse_json};
use anyhow::{Context, Result, ensure};
use flate2::read::MultiGzDecoder;
use fs2::FileExt;
use openssl::{
    pkey::{Id, PKey, Public},
    sign::Verifier,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_PAYLOAD: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = MAX_PAYLOAD + 256 * 1024 + 10240;
const DOMAIN: &[u8] = b"nodana-native-release-v1\0";

fn expand(compressed: &[u8], maximum: u64) -> Result<Vec<u8>> {
    let mut expanded = Vec::new();
    MultiGzDecoder::new(compressed)
        .take(maximum + 1)
        .read_to_end(&mut expanded)?;
    ensure!(
        expanded.len() as u64 <= maximum,
        "expanded archive too large"
    );
    Ok(expanded)
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    version: String,
    release_sha256: String,
    state_format: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    path: String,
    sha256: String,
    size: u64,
    mode: u32,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    schema_version: u8,
    version: String,
    phoenixd_version: String,
    platform: String,
    state_format: String,
    upgrade_from: Vec<Source>,
    entrypoint: String,
    bundle_sha256: String,
    bundle_size: u64,
    files: Vec<Payload>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    manifest: Value,
    key_id: String,
    signature: String,
}

pub fn checksum(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(data: &[u8]) -> String {
    hex::encode(digest(data))
}
fn version(s: &str) -> Result<semver::Version> {
    ensure!(
        regex::Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")?.is_match(s),
        "invalid version"
    );
    Ok(semver::Version::parse(s)?)
}
fn state(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
}
fn elf(data: &[u8]) -> Result<()> {
    ensure!(
        data.len() >= 64 && &data[..6] == b"\x7fELF\x02\x01" && data[18..20] == [183, 0],
        "invalid ARM64 ELF"
    );
    Ok(())
}
fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum,
        "invalid file"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "oversized file");
    Ok(bytes)
}
fn mode(path: &Path, value: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(value))?;
    Ok(())
}
fn validate(value: &Value) -> Result<Manifest> {
    let m: Manifest = serde_json::from_value(value.clone())?;
    let target = version(&m.version)?;
    version(&m.phoenixd_version)?;
    ensure!(
        m.schema_version == 1
            && m.platform == "linux-arm64"
            && state(&m.state_format)
            && m.entrypoint == "bin/nodana-phoenixd",
        "invalid manifest"
    );
    ensure!(
        checksum(&m.bundle_sha256)
            && (1..=MAX_ARCHIVE).contains(&m.bundle_size)
            && m.upgrade_from.len() <= 128,
        "invalid bundle"
    );
    let mut sources = BTreeSet::new();
    for s in &m.upgrade_from {
        ensure!(
            version(&s.version)? < target
                && checksum(&s.release_sha256)
                && state(&s.state_format)
                && sources.insert(&s.release_sha256),
            "invalid update path"
        );
    }
    ensure!((3..=256).contains(&m.files.len()), "invalid payload count");
    let pattern = regex::Regex::new(r"^(bin|libexec|lib)/[a-zA-Z0-9_+.-]{1,128}$")?;
    let mut names = BTreeSet::new();
    let mut total = 0;
    for item in &m.files {
        ensure!(
            pattern.is_match(&item.path)
                && !matches!(item.path.split('/').nth(1), Some("." | ".."))
                && names.insert(item.path.as_str()),
            "invalid payload path"
        );
        ensure!(
            checksum(&item.sha256)
                && (1..=MAX_PAYLOAD).contains(&item.size)
                && matches!(item.mode, 0o444 | 0o555),
            "invalid payload"
        );
        total += item.size;
        ensure!(total <= MAX_PAYLOAD, "oversized payload");
    }
    for required in ["bin/nodana-phoenixd", "libexec/phoenixd", "lib/ld.so"] {
        ensure!(
            m.files
                .iter()
                .any(|f| f.path == required && f.mode == 0o555),
            "missing executable"
        );
    }
    Ok(m)
}
fn envelope(
    directory: &Path,
    key: &PKey<Public>,
    approval: &str,
) -> Result<(Manifest, Value, Vec<u8>)> {
    ensure!(checksum(approval), "explicit checksum required");
    let bytes = read(&directory.join("release.json"), 256 * 1024)?;
    let e: Envelope = serde_json::from_value(parse_json(&bytes)?)?;
    let manifest = validate(&e.manifest)?;
    let encoded = canonical(&e.manifest);
    ensure!(
        hash(&encoded) == approval
            && key.id() == Id::ED25519
            && hash(&key.raw_public_key()?) == e.key_id,
        "unapproved release or signing key"
    );
    ensure!(
        e.signature.len() == 128
            && e.signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid signature"
    );
    let mut message = DOMAIN.to_vec();
    message.extend(encoded);
    ensure!(
        Verifier::new_without_digest(key)?.verify_oneshot(&hex::decode(&e.signature)?, &message)?,
        "invalid release signature"
    );
    Ok((manifest, e.manifest, bytes))
}
fn archive(directory: &Path, m: &Manifest) -> Result<BTreeMap<String, Vec<u8>>> {
    let compressed = read(&directory.join("bundle.tar.gz"), MAX_ARCHIVE)?;
    ensure!(
        compressed.len() as u64 == m.bundle_size && hash(&compressed) == m.bundle_sha256,
        "archive checksum mismatch"
    );
    let expanded = expand(&compressed, MAX_EXPANDED)?;
    let mut tar = tar::Archive::new(expanded.as_slice());
    let mut content = BTreeMap::new();
    let mut end = 0;
    for entry in tar.entries()?.raw(true) {
        let mut entry = entry?;
        let name = String::from_utf8(entry.path_bytes().to_vec())?;
        let item = m
            .files
            .iter()
            .find(|f| f.path == name)
            .context("unexpected archive member")?;
        let header = entry.header();
        ensure!(
            !content.contains_key(&name)
                && header.entry_type().is_file()
                && header.mode()? == item.mode
                && header.size()? == item.size,
            "invalid archive member"
        );
        ensure!(
            header.uid()? == 0 && header.gid()? == 0 && header.mtime()? == 0,
            "noncanonical archive metadata"
        );
        end = entry.raw_file_position() + item.size.div_ceil(512) * 512;
        let mut data = Vec::new();
        entry.by_ref().take(item.size + 1).read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 == item.size && hash(&data) == item.sha256,
            "payload checksum mismatch"
        );
        elf(&data)?;
        content.insert(name, data);
    }
    ensure!(
        content.len() == m.files.len()
            && end <= expanded.len() as u64
            && expanded.len() as u64 - end <= 10240
            && expanded[end as usize..].iter().all(|b| *b == 0),
        "incomplete archive or trailing data"
    );
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use openssl::sign::Signer;
    struct Fixture {
        temporary: tempfile::TempDir,
        directory: PathBuf,
        store: Store,
        sha: String,
    }
    impl Fixture {
        fn new() -> Self {
            let value: Value =
                serde_json::from_str(include_str!("../fixtures/native-release.json")).unwrap();
            let temporary = tempfile::tempdir().unwrap();
            let directory = temporary.path().join("download");
            fs::create_dir(&directory).unwrap();
            fs::write(
                directory.join("release.json"),
                value["envelope"].as_str().unwrap(),
            )
            .unwrap();
            fs::write(
                directory.join("bundle.tar.gz"),
                STANDARD.decode(value["bundle"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            let key = temporary.path().join("key.pem");
            fs::write(&key, value["publicKey"].as_str().unwrap()).unwrap();
            let root = temporary.path().join("store");
            fs::create_dir(&root).unwrap();
            mode(&root, 0o711).unwrap();
            Self {
                temporary,
                directory,
                store: Store {
                    root,
                    key,
                    origin: "https://example.s3.us-east-1.amazonaws.com".into(),
                },
                sha: value["releaseSha256"].as_str().unwrap().into(),
            }
        }
        fn signed(&self, value: Value, archive: Vec<u8>) -> String {
            let key = PKey::generate_ed25519().unwrap();
            fs::write(&self.store.key, key.public_key_to_pem().unwrap()).unwrap();
            let mut value = value;
            value["bundleSha256"] = hash(&archive).into();
            value["bundleSize"] = (archive.len() as u64).into();
            let encoded = canonical(&value);
            let approval = hash(&encoded);
            let mut message = DOMAIN.to_vec();
            message.extend(encoded);
            let signature = Signer::new_without_digest(&key)
                .unwrap()
                .sign_oneshot_to_vec(&message)
                .unwrap();
            let envelope = json!({"manifest":value,"keyId":hash(&key.raw_public_key().unwrap()),"signature":hex::encode(signature)});
            fs::write(self.directory.join("release.json"), canonical(&envelope)).unwrap();
            fs::write(self.directory.join("bundle.tar.gz"), archive).unwrap();
            approval
        }
        fn manifest(&self) -> Value {
            parse_json(&fs::read(self.directory.join("release.json")).unwrap()).unwrap()["manifest"]
                .clone()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fn thaw(path: &Path) {
                if let Ok(m) = path.symlink_metadata() {
                    if m.is_dir() {
                        let _ = mode(path, 0o700);
                        for e in fs::read_dir(path).unwrap().flatten() {
                            thaw(&e.path());
                        }
                    }
                }
            }
            thaw(self.temporary.path());
        }
    }
    #[test]
    fn verifies_preexisting_signed_format_and_rechecks_installed_bytes() {
        let f = Fixture::new();
        f.store.verify_download(&f.directory, &f.sha).unwrap();
        f.store.install(&f.directory, &f.sha).unwrap();
        assert_eq!(
            f.store.identity(&f.sha).unwrap()["phoenixdVersion"],
            "0.9.3"
        );
        let binary = f.store.root.join(&f.sha).join("libexec/phoenixd");
        mode(&binary, 0o755).unwrap();
        fs::write(&binary, b"modified").unwrap();
        mode(&binary, 0o555).unwrap();
        assert!(f.store.identity(&f.sha).is_err());
    }
    #[test]
    fn signer_approval_and_archive_integrity_are_independent_requirements() {
        let f = Fixture::new();
        assert!(
            f.store
                .verify_download(&f.directory, &"0".repeat(64))
                .is_err()
        );
        fs::write(
            &f.store.key,
            PKey::generate_ed25519()
                .unwrap()
                .public_key_to_pem()
                .unwrap(),
        )
        .unwrap();
        assert!(f.store.verify_download(&f.directory, &f.sha).is_err());
        let f = Fixture::new();
        fs::write(f.directory.join("bundle.tar.gz"), b"corrupt").unwrap();
        assert!(f.store.install(&f.directory, &f.sha).is_err());
        assert!(!f.store.root.join(&f.sha).exists());
    }
    #[test]
    fn rejects_signed_links_duplicate_members_unknown_fields_and_trailing_data() {
        for kind in ["symlink", "duplicate", "trailing", "unknown"] {
            let f = Fixture::new();
            let mut value = f.manifest();
            let mut original = archive(&f.directory, &validate(&value).unwrap()).unwrap();
            let encoder = flate2::GzBuilder::new()
                .mtime(0)
                .write(Vec::new(), flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            for item in value["files"].as_array().unwrap() {
                let name = item["path"].as_str().unwrap();
                let data = original.remove(name).unwrap();
                let mut header = tar::Header::new_ustar();
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_mode(item["mode"].as_u64().unwrap() as u32);
                header.set_size(data.len() as u64);
                header.set_cksum();
                if kind == "symlink" {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_link_name("/etc/passwd").unwrap();
                    header.set_cksum();
                    builder
                        .append_data(&mut header, name, std::io::empty())
                        .unwrap();
                } else {
                    builder
                        .append_data(&mut header, name, data.as_slice())
                        .unwrap();
                    if kind == "duplicate" {
                        builder
                            .append_data(&mut header, name, data.as_slice())
                            .unwrap();
                    }
                }
            }
            let compressed = builder.into_inner().unwrap().finish().unwrap();
            let compressed = if kind == "trailing" {
                let mut bytes = expand(&compressed, MAX_EXPANDED).unwrap();
                bytes.extend(b"not tar padding");
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&bytes).unwrap();
                encoder.finish().unwrap()
            } else {
                compressed
            };
            if kind == "unknown" {
                value["downloadUrl"] = "https://other.example".into();
            }
            let approval = f.signed(value, compressed);
            assert!(f.store.install(&f.directory, &approval).is_err(), "{kind}");
            assert!(!f.store.root.join(approval).exists());
        }
    }
    #[test]
    fn decompression_is_bounded_before_tar_parsing_and_urls_are_exact() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0; 4096]).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(expand(&compressed, 128).is_err());
        let f = Fixture::new();
        let expected = format!("{}/releases/{}/release.json", f.store.origin, f.sha);
        assert!(
            f.store
                .url(
                    &f.sha,
                    "release.json",
                    &(expected.clone() + "?signature=test")
                )
                .is_ok()
        );
        for input in [
            expected.replace("https:", "http:"),
            expected.replace("/releases/", "/else/"),
            expected.clone() + "#fragment",
            expected.replace("release.json", "%72elease.json"),
        ] {
            assert!(f.store.url(&f.sha, "release.json", &input).is_err());
        }
    }
}
fn inspect_tree(
    directory: &Path,
    relative: &Path,
    expected: &BTreeMap<String, u32>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    let path = directory.join(relative);
    let metadata = path.symlink_metadata()?;
    ensure!(
        !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o222 == 0,
        "untrusted installed bytes"
    );
    if metadata.is_dir() {
        ensure!(
            relative.as_os_str().is_empty()
                || matches!(relative.to_str(), Some("bin" | "lib" | "libexec")),
            "unexpected directory"
        );
        for item in fs::read_dir(&path)? {
            inspect_tree(directory, &relative.join(item?.file_name()), expected, seen)?;
        }
    } else {
        let name = relative.to_str().context("invalid path")?.to_owned();
        ensure!(
            expected.get(&name) == Some(&(metadata.mode() & 0o7777)),
            "unexpected file or mode"
        );
        seen.insert(name);
    }
    Ok(())
}

pub struct Store {
    pub root: PathBuf,
    pub key: PathBuf,
    pub origin: String,
}
impl Store {
    pub fn verify_download(&self, directory: &Path, approval: &str) -> Result<Value> {
        let (manifest, _, _) = envelope(directory, &self.public_key()?, approval)?;
        archive(directory, &manifest)?;
        Ok(
            json!({"releaseSha256":approval,"version":manifest.version,"phoenixdVersion":manifest.phoenixd_version,"stateFormat":manifest.state_format}),
        )
    }
    fn public_key(&self) -> Result<PKey<Public>> {
        let key = PKey::public_key_from_pem(&read(&self.key, 16384)?)?;
        ensure!(key.id() == Id::ED25519, "Ed25519 key required");
        Ok(key)
    }
    fn installed(&self, sha: &str) -> Result<(Manifest, Value)> {
        ensure!(checksum(sha), "invalid release identity");
        let root = self.root.join(sha);
        let (m, value, _) = envelope(&root, &self.public_key()?, sha)?;
        ensure!(
            read(&root.join("manifest.json"), 256 * 1024)? == canonical(&value),
            "manifest differs"
        );
        let mut expected: BTreeMap<_, _> =
            m.files.iter().map(|f| (f.path.clone(), f.mode)).collect();
        expected.insert("manifest.json".into(), 0o444);
        expected.insert("release.json".into(), 0o444);
        let mut seen = BTreeSet::new();
        inspect_tree(&root, Path::new(""), &expected, &mut seen)?;
        ensure!(
            seen == expected.keys().cloned().collect(),
            "incomplete runtime"
        );
        for item in &m.files {
            let bytes = read(&root.join(&item.path), item.size)?;
            ensure!(
                bytes.len() as u64 == item.size && hash(&bytes) == item.sha256,
                "installed checksum mismatch"
            );
            elf(&bytes)?;
        }
        Ok((m, value))
    }
    pub fn identity(&self, sha: &str) -> Result<Value> {
        let (m, _) = self.installed(sha)?;
        Ok(
            json!({"releaseSha256":sha,"version":m.version,"phoenixdVersion":m.phoenixd_version,"stateFormat":m.state_format}),
        )
    }
    pub fn permits(&self, current: &str, target: &str) -> Result<()> {
        let (from, _) = self.installed(current)?;
        let (to, _) = self.installed(target)?;
        ensure!(
            to.upgrade_from.iter().any(|s| s.version == from.version
                && s.release_sha256 == current
                && s.state_format == from.state_format),
            "no approved update path"
        );
        Ok(())
    }
    fn install(&self, directory: &Path, approval: &str) -> Result<()> {
        let (m, value, envelope_bytes) = envelope(directory, &self.public_key()?, approval)?;
        let content = archive(directory, &m)?;
        let temporary = tempfile::tempdir_in(&self.root)?;
        let stage = temporary.path().join("release");
        fs::create_dir(&stage)?;
        for item in &m.files {
            let path = stage.join(&item.path);
            fs::create_dir_all(path.parent().context("missing parent")?)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            file.write_all(&content[&item.path])?;
            file.sync_all()?;
            mode(&path, item.mode)?;
        }
        for (name, bytes) in [
            ("manifest.json", canonical(&value)),
            ("release.json", envelope_bytes),
        ] {
            let path = stage.join(name);
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            mode(&path, 0o444)?;
        }
        // Sync before making directories immutable and publishing one atomic rename.
        for folder in ["bin", "lib", "libexec"] {
            File::open(stage.join(folder))?.sync_all()?;
        }
        File::open(&stage)?.sync_all()?;
        let destination = self.root.join(approval);
        ensure!(
            destination.symlink_metadata().is_err(),
            "release already exists"
        );
        let publish = (|| -> Result<()> {
            for folder in ["bin", "lib", "libexec"] {
                mode(&stage.join(folder), 0o555)?;
            }
            fs::rename(&stage, &destination)?;
            mode(&destination, 0o555)?;
            Ok(())
        })();
        if publish.is_err() && stage.exists() {
            for folder in ["", "bin", "lib", "libexec"] {
                let _ = mode(&stage.join(folder), 0o755);
            }
        }
        publish?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn url(&self, sha: &str, name: &str, input: &str) -> Result<reqwest::Url> {
        ensure!(checksum(sha), "invalid identity");
        let base = reqwest::Url::parse(&self.origin)?;
        let url = reqwest::Url::parse(input)?;
        ensure!(
            base.scheme() == "https"
                && base.host_str().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none()
                && base.path() == "/"
                && base.port_or_known_default() == Some(443),
            "invalid origin"
        );
        let prefix = format!(
            "{}/releases/{sha}/{name}",
            self.origin.trim_end_matches('/')
        );
        ensure!(
            input.len() <= 16384
                && (input == prefix || input.starts_with(&(prefix + "?")))
                && url.fragment().is_none()
                && url.origin() == base.origin(),
            "untrusted release URL"
        );
        Ok(url)
    }
    pub fn prepare(&self, request: Value) -> Result<Value> {
        let keys = request.as_object().context("invalid request")?;
        ensure!(
            keys.len() == 3
                && ["releaseSha256", "manifestUrl", "bundleUrl"]
                    .iter()
                    .all(|k| keys.contains_key(*k)),
            "invalid request fields"
        );
        let sha = request["releaseSha256"]
            .as_str()
            .context("missing identity")?;
        let urls = [
            (
                "release.json",
                self.url(
                    sha,
                    "release.json",
                    request["manifestUrl"].as_str().context("missing URL")?,
                )?,
                256 * 1024,
            ),
            (
                "bundle.tar.gz",
                self.url(
                    sha,
                    "bundle.tar.gz",
                    request["bundleUrl"].as_str().context("missing URL")?,
                )?,
                MAX_ARCHIVE,
            ),
        ];
        if !self.root.try_exists()? {
            fs::create_dir_all(&self.root)?;
            mode(&self.root, 0o711)?;
        }
        let metadata = self.root.symlink_metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0,
            "untrusted store"
        );
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.root.join(".install.lock"))?;
        lock.lock_exclusive()?;
        if self.root.join(sha).symlink_metadata().is_ok() {
            return self.identity(sha);
        }
        let temporary = tempfile::tempdir_in(&self.root)?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .build()?;
        for (name, url, maximum) in urls {
            let response = client.get(url).send()?;
            ensure!(
                response.status() == reqwest::StatusCode::OK,
                "download failed"
            );
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(temporary.path().join(name))?;
            let count = std::io::copy(&mut response.take(maximum + 1), &mut file)?;
            ensure!(count <= maximum, "download too large");
        }
        self.install(temporary.path(), sha)?;
        self.identity(sha)
    }
}
