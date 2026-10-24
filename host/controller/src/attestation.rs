//! AWS NitroTPM verification for certificate replication, entirely in-process.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ciborium::value::Value;
use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    sha::sha256,
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder},
};
use serde::Deserialize;
use std::collections::BTreeSet;

const AWS_ROOT: &str = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

struct ApprovedImage {
    image_id: String,
    pcr4: String,
    pcr7: String,
    pcr12: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerEvidence {
    own_document: String,
    own_nonce: String,
    own_binding: String,
    document: String,
    nonce: String,
    binding: String,
}

fn base64(text: &str, limit: usize) -> Result<Vec<u8>> {
    ensure!(text.len() <= limit.div_ceil(3) * 4, "oversized evidence");
    let bytes = STANDARD.decode(text)?;
    ensure!(
        bytes.len() <= limit && STANDARD.encode(&bytes) == text,
        "invalid encoding"
    );
    Ok(bytes)
}

pub fn verify_peer(input: &PeerEvidence, now: u64) -> Result<()> {
    let own = base64(&input.own_document, 65536)?;
    let mut cose = decode(&own)?;
    if let Value::Tag(tag, inner) = cose {
        ensure!(tag == 18, "invalid tag");
        cose = *inner;
    }
    let array = cose.as_array().context("invalid quote")?;
    ensure!(array.len() == 4, "invalid quote");
    let payload = decode(bytes(&array[2], 1, 65536)?)?;
    let pcrs = field(&payload, "nitrotpm_pcrs")?
        .as_map()
        .context("missing PCRs")?;
    let pcr = |index: i128| -> Result<String> {
        let value = pcrs
            .iter()
            .find_map(|(k, v)| (integer(k).ok() == Some(index)).then_some(v))
            .context("missing PCR")?;
        Ok(hex::encode(bytes(value, 48, 48)?))
    };
    let image = ApprovedImage {
        image_id: "same-protected-boot-policy".into(),
        pcr4: pcr(4)?,
        pcr7: pcr(7)?,
        pcr12: pcr(12)?,
    };
    ensure!(
        image.pcr4 != "00".repeat(48)
            && image.pcr7 != "00".repeat(48)
            && image.pcr12 == "00".repeat(48),
        "invalid boot policy"
    );
    let images = [image];
    verify_document(
        &own,
        &base64(&input.own_nonce, 32)?,
        &base64(&input.own_binding, 32)?,
        now,
        &images,
    )?;
    verify_document(
        &base64(&input.document, 65536)?,
        &base64(&input.nonce, 32)?,
        &base64(&input.binding, 32)?,
        now,
        &images,
    )?;
    Ok(())
}

fn decode(bytes: &[u8]) -> Result<Value> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor).context("Invalid attestation CBOR")?;
    ensure!(
        cursor.position() == bytes.len() as u64,
        "Trailing attestation data"
    );
    validate_maps(&value, 0)?;
    Ok(value)
}

fn validate_maps(value: &Value, depth: usize) -> Result<()> {
    ensure!(depth < 32, "Attestation nesting is too deep");
    match value {
        Value::Map(entries) => {
            let mut seen = BTreeSet::new();
            for (key, value) in entries {
                let mut encoded = Vec::new();
                ciborium::into_writer(key, &mut encoded)?;
                ensure!(seen.insert(encoded), "Duplicate attestation map key");
                validate_maps(key, depth + 1)?;
                validate_maps(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_maps(value, depth + 1)?;
            }
        }
        Value::Tag(_, value) => validate_maps(value, depth + 1)?,
        _ => {}
    }
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find_map(|(key, value)| (key.as_text() == Some(name)).then_some(value))
        })
        .with_context(|| format!("Missing attestation field {name}"))
}
fn bytes(value: &Value, min: usize, max: usize) -> Result<&[u8]> {
    let value = value.as_bytes().context("Invalid attestation bytes")?;
    ensure!(
        (min..=max).contains(&value.len()),
        "Invalid attestation byte length"
    );
    Ok(value)
}
fn integer(value: &Value) -> Result<i128> {
    Ok(value
        .as_integer()
        .context("Invalid attestation integer")?
        .into())
}

fn verify_document(
    document: &[u8],
    nonce: &[u8],
    binding: &[u8],
    now: u64,
    images: &[ApprovedImage],
) -> Result<(String, String)> {
    ensure!(
        document.len() <= 65536 && nonce.len() == 32 && binding.len() == 32 && !images.is_empty(),
        "Host verification is not configured"
    );
    let mut cose = decode(document)?;
    if let Value::Tag(tag, inner) = cose {
        ensure!(tag == 18, "Invalid COSE tag");
        cose = *inner;
    }
    let cose = cose.as_array().context("Invalid COSE document")?;
    ensure!(cose.len() == 4, "Invalid COSE document");
    let protected = bytes(&cose[0], 1, 128)?;
    let header = decode(protected)?;
    let header = header.as_map().context("Invalid COSE header")?;
    ensure!(
        header.len() == 1
            && integer(&header[0].0)? == 1
            && integer(&header[0].1)? == -35
            && cose[1].as_map().is_some_and(|v| v.is_empty()),
        "Unsupported attestation signature"
    );
    let payload_bytes = bytes(&cose[2], 1, 65536)?;
    let payload = decode(payload_bytes)?;
    let signature = bytes(&cose[3], 96, 96)?;
    let module = field(&payload, "module_id")?
        .as_text()
        .context("Invalid host identity")?;
    let timestamp = integer(field(&payload, "timestamp")?)?;
    ensure!(
        !module.is_empty()
            && module.len() <= 256
            && field(&payload, "digest")?.as_text() == Some("SHA384")
            && timestamp >= i128::from(now) - 300_000
            && timestamp <= i128::from(now) + 30_000,
        "Host attestation has expired or is invalid"
    );
    ensure!(
        bytes(field(&payload, "nonce")?, 32, 32)? == nonce
            && bytes(field(&payload, "user_data")?, 32, 32)? == binding,
        "Host response does not match this request"
    );
    let pcrs = field(&payload, "nitrotpm_pcrs")?
        .as_map()
        .context("Invalid boot measurements")?;
    let pcr = |index: i128| -> Result<String> {
        let value = pcrs
            .iter()
            .find_map(|(key, value)| (integer(key).ok() == Some(index)).then_some(value))
            .context("Missing boot measurement")?;
        Ok(hex::encode(bytes(value, 48, 48)?))
    };
    let (pcr4, pcr7, pcr12) = (pcr(4)?, pcr(7)?, pcr(12)?);
    let image = images
        .iter()
        .find(|image| image.pcr4 == pcr4 && image.pcr7 == pcr7 && image.pcr12 == pcr12)
        .context("This host image has not been approved. Check the node URL and update the CLI")?;
    let bundle = field(&payload, "cabundle")?
        .as_array()
        .context("Invalid attestation chain")?;
    ensure!((1..=8).contains(&bundle.len()), "Invalid attestation chain");
    let root_der = bytes(&bundle[0], 1, 2048)?;
    ensure!(
        hex::encode(sha256(root_der)) == AWS_ROOT,
        "Untrusted attestation authority"
    );
    let root = X509::from_der(root_der)?;
    let leaf = X509::from_der(bytes(field(&payload, "certificate")?, 1, 2048)?)?;
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(root)?;
    let mut params = openssl::x509::verify::X509VerifyParam::new()?;
    params.set_time((now / 1000).try_into()?);
    store.set_param(&params)?;
    let mut chain = Stack::new()?;
    for item in &bundle[1..] {
        chain.push(X509::from_der(bytes(item, 1, 2048)?)?)?;
    }
    let mut context = X509StoreContext::new()?;
    ensure!(
        context.init(&store.build(), &leaf, &chain, |ctx| ctx.verify_cert())?,
        "Invalid attestation certificate chain"
    );
    let key = leaf.public_key()?;
    ensure!(
        key.ec_key()?.group().curve_name() == Some(openssl::nid::Nid::SECP384R1),
        "Unsupported attestation signing key"
    );
    let der_signature = EcdsaSig::from_private_components(
        BigNum::from_slice(&signature[..48])?,
        BigNum::from_slice(&signature[48..])?,
    )?
    .to_der()?;
    let signed = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.into()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload_bytes.into()),
    ]);
    let mut signed_bytes = Vec::new();
    ciborium::into_writer(&signed, &mut signed_bytes)?;
    let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha384(), &key)?;
    verifier.update(&signed_bytes)?;
    if !verifier.verify(&der_signature)? {
        bail!("Invalid host attestation signature");
    }
    Ok((module.into(), image.image_id.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_evidence_rejects_changed_nonce_binding_policy_and_signature() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/nitrotpm.json")).unwrap();
        let value = serde_json::json!({
            "ownDocument":fixture["document"],"ownNonce":fixture["nonce"],"ownBinding":fixture["binding"],
            "document":fixture["document"],"nonce":fixture["nonce"],"binding":fixture["binding"]
        });
        let verify = |value: serde_json::Value| {
            verify_peer(
                &serde_json::from_value(value).unwrap(),
                fixture["now"].as_u64().unwrap(),
            )
        };
        verify(value.clone()).unwrap();
        for field in ["nonce", "ownNonce", "binding", "ownBinding"] {
            let mut changed = value.clone();
            changed[field] = STANDARD.encode([0; 32]).into();
            assert!(verify(changed).is_err());
        }
        for field in ["document", "ownDocument"] {
            let mut changed = value.clone();
            let mut data = STANDARD.decode(changed[field].as_str().unwrap()).unwrap();
            *data.last_mut().unwrap() ^= 1;
            changed[field] = STANDARD.encode(data).into();
            assert!(verify(changed).is_err());
        }
        let input: PeerEvidence = serde_json::from_value(value).unwrap();
        assert!(verify_peer(&input, fixture["now"].as_u64().unwrap() + 400_000).is_err());
    }
}
