//! Disposable TLS identities for local tests. Never included in the runtime.
use crate::protocol::DOMAIN;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use std::path::Path;

fn cert(
    key: &PKey<Private>,
    label: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    dns: Option<&str>,
    server: bool,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", label).unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    let serial = serial.to_asn1_integer().unwrap();
    cert.set_serial_number(&serial).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(issuer.map(|(cert, _)| cert.subject_name()).unwrap_or(&name))
        .unwrap();
    cert.set_pubkey(key).unwrap();
    let start = Asn1Time::days_from_now(0).unwrap();
    let end = Asn1Time::days_from_now(365).unwrap();
    cert.set_not_before(&start).unwrap();
    cert.set_not_after(&end).unwrap();
    if issuer.is_none() {
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    } else {
        cert.append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        let mut usage = ExtendedKeyUsage::new();
        if server {
            usage.server_auth();
        } else {
            usage.client_auth();
        }
        cert.append_extension(usage.build().unwrap()).unwrap();
        if let Some(dns) = dns {
            let extension = SubjectAlternativeName::new()
                .dns(dns)
                .build(&cert.x509v3_context(issuer.map(|(cert, _)| cert.as_ref()), None))
                .unwrap();
            cert.append_extension(extension).unwrap();
        }
    }
    cert.sign(
        issuer.map(|(_, key)| key).unwrap_or(key),
        MessageDigest::null(),
    )
    .unwrap();
    cert.build()
}
pub fn generate(root: &Path) {
    let key = PKey::generate_ed25519().unwrap();
    let ca = cert(&key, "Disposable test CA", None, None, false);
    let next_key = PKey::generate_ed25519().unwrap();
    let next_ca = cert(&next_key, "Replacement test CA", None, None, false);
    std::fs::write(root.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
    std::fs::write(root.join("next-ca.pem"), next_ca.to_pem().unwrap()).unwrap();
    let wildcard = format!("*.{DOMAIN}");
    for (label, dns, server) in [
        ("control", Some("protected-host.nodana.internal"), true),
        ("client", None, false),
        ("client-next", None, false),
        ("admin", None, false),
        ("unauthorized", None, false),
        ("wildcard", Some(wildcard.as_str()), true),
        ("rotated", Some(wildcard.as_str()), true),
        ("wrong", Some("*.other.example"), true),
    ] {
        let leaf_key = PKey::generate_ed25519().unwrap();
        let issuer = if label == "client-next" {
            (&next_ca, &next_key)
        } else {
            (&ca, &key)
        };
        let leaf = cert(&leaf_key, label, Some(issuer), dns, server);
        std::fs::write(root.join(format!("{label}.pem")), leaf.to_pem().unwrap()).unwrap();
        std::fs::write(
            root.join(format!("{label}.key")),
            leaf_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
    }
}
