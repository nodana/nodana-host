//! Durable API client authorization; recovery identity is fixed in the image.
use crate::{Args, host::fail, protocol::*};
use anyhow::{Context, Result, ensure};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Cursor,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiCertificate {
    pub certificate: String,
    pub ca: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    revision: u64,
    api_certificates: Vec<ApiCertificate>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Role {
    Api,
    Administrator,
}

pub struct ControlIdentity {
    path: PathBuf,
    admin_ca: String,
    admin_fingerprint: String,
    policy: Mutex<Policy>,
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn certificate(pem: &str) -> Result<rustls::pki_types::CertificateDer<'static>> {
    ensure!(
        pem.len() <= 16384 && !pem.contains("PRIVATE KEY"),
        "public certificate required"
    );
    let values = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(values.len() == 1, "one certificate required");
    Ok(values.into_iter().next().unwrap())
}

fn validate(entry: &ApiCertificate) -> Result<String> {
    let leaf = certificate(&entry.certificate)?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate(&entry.ca)?)?;
    WebPkiClientVerifier::builder(Arc::new(roots))
        .build()?
        .verify_client_cert(&leaf, &[], rustls::pki_types::UnixTime::now())?;
    Ok(fingerprint(leaf.as_ref()))
}

impl ControlIdentity {
    pub fn open(args: &Args) -> Result<Self> {
        let admin_ca = String::from_utf8(read_file(&args.admin_ca, 16384)?)?;
        let admin = ApiCertificate {
            ca: admin_ca.clone(),
            certificate: String::from_utf8(read_file(&args.admin_certificate, 16384)?)?,
        };
        // These immutable public inputs are validated by the image builder.
        // TLS enforces expiry when the administrator connects; expiry must not
        // turn a reboot into a shutdown of otherwise usable node workloads.
        certificate(&admin.ca)?;
        let admin_fingerprint = fingerprint(certificate(&admin.certificate)?.as_ref());
        let path = args.data.join("control-identities.json");
        let policy: Policy = if path.try_exists()? {
            serde_json::from_slice(&read_file(&path, 131072)?)?
        } else {
            let initial = ApiCertificate {
                certificate: String::from_utf8(read_file(&args.client_certificate, 16384)?)?,
                ca: String::from_utf8(read_file(&args.client_ca, 16384)?)?,
            };
            ensure!(
                validate(&initial)? != admin_fingerprint,
                "separate admin identity required"
            );
            let policy = Policy {
                revision: 1,
                api_certificates: vec![initial],
            };
            atomic(&path, &canonical(&policy))?;
            policy
        };
        let value = Self {
            path,
            admin_ca,
            admin_fingerprint,
            policy: Mutex::new(policy),
        };
        // Expired API credentials must not prevent recovery through the admin.
        // Parse persisted certificates here; TLS checks validity at connection time.
        let policy = value.policy.lock().unwrap();
        ensure!(
            policy.revision > 0 && policy.api_certificates.len() <= 4,
            "invalid identity policy"
        );
        for entry in &policy.api_certificates {
            ensure!(
                fingerprint(certificate(&entry.certificate)?.as_ref()) != value.admin_fingerprint,
                "separate admin identity required"
            );
            certificate(&entry.ca)?;
        }
        drop(policy);
        Ok(value)
    }

    pub fn roots(&self) -> Result<Arc<RootCertStore>> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate(&self.admin_ca)?)?;
        for entry in &self.policy.lock().unwrap().api_certificates {
            roots.add(certificate(&entry.ca)?)?;
        }
        Ok(Arc::new(roots))
    }

    pub fn role(&self, client: &str) -> Option<Role> {
        if client == self.admin_fingerprint {
            return Some(Role::Administrator);
        }
        self.policy
            .lock()
            .unwrap()
            .api_certificates
            .iter()
            .any(|entry| {
                certificate(&entry.certificate)
                    .is_ok_and(|cert| fingerprint(cert.as_ref()) == client)
            })
            .then_some(Role::Api)
    }

    pub fn status(&self) -> Result<Value> {
        let policy = self.policy.lock().unwrap();
        Ok(
            json!({"revision":policy.revision,"apiFingerprints":policy.api_certificates.iter()
            .map(|entry| certificate(&entry.certificate).map(|cert| fingerprint(cert.as_ref())))
            .collect::<Result<Vec<_>>>()?}),
        )
    }

    pub fn replace(&self, request: Value) -> Result<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Update {
            expected_revision: u64,
            api_certificates: Vec<ApiCertificate>,
        }
        let update: Update =
            serde_json::from_value(request).map_err(|_| fail(400, "invalid_identity_policy"))?;
        ensure!(
            update.api_certificates.len() <= 4,
            fail(400, "invalid_identity_policy")
        );
        // An empty list is an emergency revocation of every API identity.
        let mut seen = std::collections::HashSet::new();
        for entry in &update.api_certificates {
            let fp = validate(entry).map_err(|_| fail(400, "invalid_client_certificate"))?;
            ensure!(
                fp != self.admin_fingerprint && seen.insert(fp),
                fail(400, "invalid_identity_policy")
            );
        }
        let mut policy = self.policy.lock().unwrap();
        ensure!(
            policy.revision == update.expected_revision,
            fail(409, "identity_revision_conflict")
        );
        let revision = policy
            .revision
            .checked_add(1)
            .context("identity revision exhausted")?;
        let next = Policy {
            revision,
            api_certificates: update.api_certificates,
        };
        let encoded = canonical(&next);
        ensure!(
            encoded.len() <= 131072,
            fail(400, "invalid_identity_policy")
        );
        atomic(&self.path, &encoded)?;
        *policy = next;
        drop(policy);
        self.status()
    }
}
