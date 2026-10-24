//! TPM/LUKS startup. The on-disk format and derivation labels match existing hosts.
use crate::protocol::{atomic, encode, read_file, run_command};
use anyhow::{Context, Result, ensure};
use hkdf::Hkdf;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    pkey::{Id, PKey},
    symm::{Cipher, decrypt_aead, encrypt_aead},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, SubjectAlternativeName},
    },
};
use sha2::Sha256;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};
use zeroize::Zeroizing;

const RAM: &str = "/run/nodana-tpm";
const STATE: &str = "/var/lib/nodana-tpm";
const DATA: &str = "/var/lib/nodana-phoenix";
const DEVICE: &str = "/dev/disk/by-partlabel/nodana-phoenix-data";
const MAPPING: &str = "/dev/mapper/nodana-phoenix";
const PCRS: &str = "sha384:4,7,12";
fn derive<const N: usize>(material: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; N]>> {
    let mut key = Zeroizing::new([0; N]);
    Hkdf::<Sha256>::new(None, material)
        .expand(info, key.as_mut())
        .map_err(|_| anyhow::anyhow!("key derivation failed"))?;
    Ok(key)
}
fn tool(program: &str, args: &[&str], timeout: u64, maximum: usize) -> Result<Vec<u8>> {
    run_command(
        Command::new(program)
            .args(args)
            .current_dir(RAM)
            .env("TPM2TOOLS_TCTI", "device:/dev/tpmrm0"),
        None,
        timeout,
        maximum,
    )
}
struct SecretFile(PathBuf);
impl SecretFile {
    fn new(name: &str, bytes: &[u8]) -> Result<Self> {
        let path = Path::new(RAM).join(name);
        atomic(&path, bytes)?;
        Ok(Self(path))
    }
}
impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn material() -> Result<(Zeroizing<Vec<u8>>, bool)> {
    let paths = ["sealed.pub", "sealed.priv", "payload.bin"].map(|n| Path::new(STATE).join(n));
    let exists = paths.iter().filter(|p| p.exists()).count();
    ensure!(exists == 0 || exists == 3, "incomplete provisioning");
    tool(
        "tpm2_createprimary",
        &["-C", "o", "-G", "rsa", "-g", "sha256", "-c", "primary.ctx"],
        30,
        0,
    )?;
    if exists == 0 {
        let mut material = Zeroizing::new(vec![0; 32]);
        openssl::rand::rand_bytes(&mut material)?;
        let input = SecretFile::new("input.key", &material)?;
        tool(
            "tpm2_createpolicy",
            &["--policy-pcr", "-l", PCRS, "-L", "policy.digest"],
            30,
            0,
        )?;
        tool(
            "tpm2_create",
            &[
                "-C",
                "primary.ctx",
                "-i",
                "input.key",
                "-u",
                "sealed.pub",
                "-r",
                "sealed.priv",
                "-L",
                "policy.digest",
                "-a",
                "fixedtpm|fixedparent|adminwithpolicy|noda",
            ],
            30,
            0,
        )?;
        drop(input);
        let key = derive::<32>(&material, b"nodana-synthetic-data-v1")?;
        let mut nonce = [0; 12];
        openssl::rand::rand_bytes(&mut nonce)?;
        let mut tag = [0; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            key.as_ref(),
            Some(&nonce),
            b"nodana-trial-v1",
            b"nodana TPM synthetic recovery payload v1",
            &mut tag,
        )?;
        let mut payload = nonce.to_vec();
        payload.extend(ciphertext);
        payload.extend(tag);
        for path in &paths[..2] {
            atomic(
                path,
                &read_file(
                    &Path::new(RAM).join(path.file_name().context("missing file")?),
                    16384,
                )?,
            )?;
        }
        atomic(&paths[2], &payload)?;
    }
    tool(
        "tpm2_load",
        &[
            "-C",
            "primary.ctx",
            "-u",
            paths[0].to_str().context("invalid path")?,
            "-r",
            paths[1].to_str().context("invalid path")?,
            "-c",
            "sealed.ctx",
        ],
        30,
        0,
    )?;
    tool(
        "tpm2_startauthsession",
        &["--policy-session", "-S", "session.ctx"],
        30,
        0,
    )?;
    // Install the cleanup guard before unseal, so a failed read cannot leave plaintext.
    let unsealed = SecretFile(Path::new(RAM).join("unsealed.key"));
    let result = (|| -> Result<()> {
        tool("tpm2_policypcr", &["-S", "session.ctx", "-l", PCRS], 30, 0)?;
        tool(
            "tpm2_unseal",
            &[
                "-c",
                "sealed.ctx",
                "-p",
                "session:session.ctx",
                "-o",
                "unsealed.key",
            ],
            30,
            0,
        )?;
        Ok(())
    })();
    let flushed = tool("tpm2_flushcontext", &["session.ctx"], 30, 0);
    result?;
    flushed?;
    let material = Zeroizing::new(read_file(&unsealed.0, 32)?);
    ensure!(material.len() == 32, "invalid sealed key");
    drop(unsealed);
    let key = derive::<32>(&material, b"nodana-synthetic-data-v1")?;
    let payload = read_file(&paths[2], 4096)?;
    ensure!(payload.len() >= 28, "invalid recovery payload");
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        key.as_ref(),
        Some(&payload[..12]),
        b"nodana-trial-v1",
        &payload[12..payload.len() - 16],
        &payload[payload.len() - 16..],
    )?;
    ensure!(
        plaintext == b"nodana TPM synthetic recovery payload v1",
        "invalid recovery payload"
    );
    Ok((material, exists == 0))
}
fn open_storage(material: &[u8], new: bool) -> Result<()> {
    let key = derive::<64>(material, b"nodana-phoenix-luks-v1")?;
    let file = SecretFile::new("filesystem.key", key.as_ref())?;
    let marker = Path::new(STATE).join("phoenix-luks-uuid");
    let is_luks = Command::new("cryptsetup")
        .args(["isLuks", DEVICE])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?
        .success();
    if !is_luks {
        ensure!(new && !marker.exists(), "refuse reformatting existing node");
        tool(
            "cryptsetup",
            &[
                "luksFormat",
                DEVICE,
                "--type",
                "luks2",
                "--batch-mode",
                "--cipher",
                "aes-xts-plain64",
                "--key-size",
                "512",
                "--integrity",
                "hmac-sha256",
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                "--key-file",
                "/run/nodana-tpm/filesystem.key",
            ],
            180,
            0,
        )?;
    }
    let uuid = tool("cryptsetup", &["luksUUID", DEVICE], 180, 128)?;
    let uuid = std::str::from_utf8(&uuid)?.trim();
    ensure!(!uuid.is_empty(), "missing disk identity");
    if marker.exists() {
        ensure!(
            std::str::from_utf8(&read_file(&marker, 128)?)?.trim() == uuid,
            "disk identity mismatch"
        );
    } else {
        ensure!(!is_luks, "incomplete filesystem provisioning");
    }
    tool(
        "cryptsetup",
        &[
            "open",
            "--key-file",
            "/run/nodana-tpm/filesystem.key",
            DEVICE,
            "nodana-phoenix",
        ],
        180,
        0,
    )?;
    drop(file);
    if !is_luks {
        tool("mkfs.ext4", &["-F", MAPPING], 180, 0)?;
        atomic(&marker, format!("{uuid}\n").as_bytes())?;
    } else {
        crate::protocol::run_command_accepted(
            Command::new("e2fsck").args(["-p", MAPPING]),
            None,
            180,
            0,
            &[0, 1],
        )?;
    }
    tool(
        "mount",
        &["-t", "ext4", "-o", "nodev,nosuid,noexec", MAPPING, DATA],
        180,
        0,
    )?;
    Ok(())
}
fn certificate(material: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let seed = derive::<32>(material, b"nodana-protected-host-control-tls-v1")?;
    let key = PKey::private_key_from_raw_bytes(seed.as_ref(), Id::ED25519)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "protected-host.nodana.internal")?;
    let name = name.build();
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    let number = BigNum::from_u32(1)?;
    let serial = Asn1Integer::from_bn(&number)?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&name)?;
    cert.set_issuer_name(&name)?;
    cert.set_pubkey(&key)?;
    let start = Asn1Time::from_str_x509("20200101000000Z")?;
    let end = Asn1Time::from_str_x509("20400101000000Z")?;
    cert.set_not_before(&start)?;
    cert.set_not_after(&end)?;
    let san = SubjectAlternativeName::new()
        .dns("protected-host.nodana.internal")
        .build(&cert.x509v3_context(None, None))?;
    cert.append_extension(san)?;
    cert.append_extension(BasicConstraints::new().critical().build()?)?;
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    cert.sign(&key, MessageDigest::null())?;
    Ok((
        cert.build().to_pem()?,
        Zeroizing::new(key.private_key_to_pem_pkcs8()?),
    ))
}
pub fn boot(config: &Path) -> Result<()> {
    unsafe {
        libc::umask(0o077);
    }
    let secure = read_file(
        Path::new("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        8,
    )?;
    ensure!(secure.get(4..) == Some(&[1]), "secure boot required");
    for unit in [
        "serial-getty@.service",
        "getty@.service",
        "serial-getty@ttyS0.service",
        "getty@tty1.service",
    ] {
        ensure!(
            fs::canonicalize(Path::new("/etc/systemd/system").join(unit))?
                == Path::new("/dev/null"),
            "console login must be masked"
        );
    }
    let result = (|| -> Result<()> {
        let (material, new) = material()?;
        open_storage(&material, new)?;
        let releases = Path::new(DATA).join("releases");
        fs::create_dir_all(&releases)?;
        fs::set_permissions(&releases, fs::Permissions::from_mode(0o711))?;
        fs::create_dir_all("/run/nodana-releases")?;
        tool(
            "mount",
            &[
                "--bind",
                releases.to_str().context("invalid path")?,
                "/run/nodana-releases",
            ],
            30,
            0,
        )?;
        tool(
            "mount",
            &[
                "-o",
                "remount,bind,exec,nodev,nosuid",
                "/run/nodana-releases",
            ],
            30,
            0,
        )?;
        let (cert, key) = certificate(&material)?;
        drop(material);
        atomic(&Path::new(RAM).join("host.crt"), &cert)?;
        atomic(&Path::new(RAM).join("host.key"), &key)?;
        drop(key);
        println!(
            "NODANA_HOST_TLS_CERTIFICATE {}",
            serde_json::json!({"pem":encode(&cert)})
        );
        let mut command = Command::new(std::env::current_exe()?);
        command.args([
            "--data",
            DATA,
            "--runtime-dir",
            RAM,
            "--release-store",
            "/run/nodana-releases",
            "--tls-certificate",
            "/run/nodana-tpm/host.crt",
            "--tls-key",
            "/run/nodana-tpm/host.key",
        ]);
        for (flag, name) in [
            ("--release-public-key", "release-public-key.pem"),
            ("--client-ca", "control-client-ca.pem"),
            ("--client-certificate", "control-client.pem"),
            ("--admin-ca", "control-admin-ca.pem"),
            ("--admin-certificate", "control-admin.pem"),
        ] {
            command.arg(flag).arg(config.join(name));
        }
        let origin = read_file(&config.join("release-origin.txt"), 4096)?;
        command
            .arg("--release-origin")
            .arg(std::str::from_utf8(&origin)?.trim());
        command
            .arg("--attest-binary")
            .arg(std::env::var("ATTEST_BINARY")?)
            .arg("--certbot")
            .arg(std::env::var("CERTBOT_BINARY")?);
        println!("NODANA_PROTECTED_HOST_STARTING");
        Err(command.exec().into())
    })();
    // Exec only returns on failure. Preserve encrypted data and unwind mounts.
    for args in [vec!["/run/nodana-releases"], vec![DATA]] {
        let _ = run_command(Command::new("umount").args(args), None, 30, 0);
    }
    let _ = run_command(
        Command::new("cryptsetup").args(["close", "nodana-phoenix"]),
        None,
        30,
        0,
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_identity_is_stable_and_separate_from_disk_key() {
        let (first, key) = certificate(&[7; 32]).unwrap();
        let (second, _) = certificate(&[7; 32]).unwrap();
        assert_eq!(first, second);
        let cert = X509::from_pem(&first).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/bootstrap.json")).unwrap();
        assert_eq!(
            hex::encode(crate::protocol::digest(cert.to_der().unwrap())),
            fixture["certificateDerSha256"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(
                derive::<64>(&[7; 32], b"nodana-phoenix-luks-v1")
                    .unwrap()
                    .as_ref()
            ),
            fixture["luksKey"].as_str().unwrap()
        );
        let private = PKey::private_key_from_pem(&key).unwrap();
        assert!(cert.verify(&private).unwrap());
        assert_ne!(
            derive::<32>(&[7; 32], b"nodana-synthetic-data-v1")
                .unwrap()
                .as_ref(),
            derive::<32>(&[7; 32], b"nodana-protected-host-control-tls-v1")
                .unwrap()
                .as_ref()
        );
    }
}
