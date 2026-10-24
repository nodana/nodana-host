//! Scoped DNS-01 hooks. Only this image's wildcard challenge record is writable.
use crate::protocol::{DOMAIN, parse_json};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{io::Read, path::Path, time::Duration};

trait Api {
    fn request(&self, method: &str, suffix: &str, body: Option<Value>) -> Result<Value>;
}
struct Cloudflare {
    client: reqwest::blocking::Client,
    base: String,
    token: String,
}
impl Api for Cloudflare {
    fn request(&self, method: &str, suffix: &str, body: Option<Value>) -> Result<Value> {
        let mut request = self
            .client
            .request(method.parse()?, format!("{}{suffix}", self.base))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send()?.error_for_status()?;
        let mut bytes = Vec::new();
        response.take(131073).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 131072, "oversized DNS response");
        let value = parse_json(&bytes)?;
        ensure!(value["success"] == true, "DNS challenge failed");
        Ok(value["result"].clone())
    }
}
fn valid(domain: &str, validation: &str) -> Result<()> {
    ensure!(
        (domain == DOMAIN || domain == format!("*.{DOMAIN}"))
            && regex::Regex::new(r"^[A-Za-z0-9_-]{43}$")?.is_match(validation),
        "invalid challenge"
    );
    Ok(())
}
fn identifier(value: &Value) -> Result<&str> {
    let id = value.as_str().context("missing DNS ID")?;
    ensure!(
        regex::Regex::new(r"^[a-f0-9]{32}$")?.is_match(id),
        "invalid DNS ID"
    );
    Ok(id)
}
fn auth(api: &impl Api, domain: &str, validation: &str) -> Result<Value> {
    valid(domain, validation)?;
    let name = format!("_acme-challenge.{DOMAIN}");
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("type", "TXT")
        .append_pair("name", &name)
        .append_pair("per_page", "100")
        .finish();
    let rows = api.request("GET", &format!("?{query}"), None)?;
    for row in rows.as_array().context("invalid DNS response")? {
        if row["type"] == "TXT" && row["name"] == name && row["content"] == validation {
            return Ok(json!({"recordId":identifier(&row["id"])? ,"created":false}));
        }
    }
    let row = api.request(
        "POST",
        "",
        Some(json!({"type":"TXT","name":name,"content":validation,"ttl":60})),
    )?;
    Ok(json!({"recordId":identifier(&row["id"])? ,"created":true}))
}
fn cleanup(api: &impl Api, domain: &str, validation: &str, output: &Value) -> Result<()> {
    valid(domain, validation)?;
    let keys = output.as_object().context("invalid cleanup")?;
    ensure!(
        keys.len() == 2 && keys.contains_key("recordId") && keys.contains_key("created"),
        "invalid cleanup fields"
    );
    let id = identifier(&output["recordId"])?;
    let created = output["created"].as_bool().context("invalid cleanup")?;
    if !created {
        return Ok(());
    }
    let row = api.request("GET", &format!("/{id}"), None)?;
    ensure!(
        row["type"] == "TXT"
            && row["name"] == format!("_acme-challenge.{DOMAIN}")
            && row["content"] == validation,
        "DNS challenge changed"
    );
    api.request("DELETE", &format!("/{id}"), None)?;
    Ok(())
}
pub fn run(action: &str, credentials: &Path) -> Result<()> {
    let value = parse_json(&crate::protocol::read_file(credentials, 16384)?)?;
    let zone = identifier(&value["zoneId"])?;
    let token = value["token"].as_str().context("missing token")?;
    ensure!(
        regex::Regex::new(r"^[A-Za-z0-9_-]{20,256}$")?.is_match(token),
        "invalid token"
    );
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let api = Cloudflare {
        client,
        base: format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records"),
        token: token.into(),
    };
    let domain = std::env::var("CERTBOT_DOMAIN")?;
    let validation = std::env::var("CERTBOT_VALIDATION")?;
    match action {
        "auth" => {
            let output = auth(&api, &domain, &validation)?;
            std::thread::sleep(Duration::from_secs(60));
            println!("{output}");
        }
        "cleanup" => cleanup(
            &api,
            &domain,
            &validation,
            &parse_json(std::env::var("CERTBOT_AUTH_OUTPUT")?.as_bytes())?,
        )?,
        _ => anyhow::bail!("invalid DNS action"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Fixture {
        rows: RefCell<Vec<Value>>,
        deleted: RefCell<Vec<String>>,
    }
    impl Api for Fixture {
        fn request(&self, method: &str, suffix: &str, body: Option<Value>) -> Result<Value> {
            match method {
                "GET" if suffix.starts_with('?') => Ok(json!(*self.rows.borrow())),
                "GET" => Ok(self.rows.borrow()[0].clone()),
                "POST" => {
                    let mut row = body.unwrap();
                    row["id"] = "a".repeat(32).into();
                    self.rows.borrow_mut().push(row.clone());
                    Ok(row)
                }
                "DELETE" => {
                    self.deleted.borrow_mut().push(suffix.into());
                    Ok(Value::Null)
                }
                _ => unreachable!(),
            }
        }
    }
    #[test]
    fn retry_reuses_txt_and_cleanup_preserves_changed_or_reused_records() {
        let api = Fixture {
            rows: RefCell::new(vec![]),
            deleted: RefCell::new(vec![]),
        };
        let validation = "A".repeat(43);
        let created = auth(&api, DOMAIN, &validation).unwrap();
        assert_eq!(created["created"], true);
        let reused = auth(&api, DOMAIN, &validation).unwrap();
        assert_eq!(reused["created"], false);
        cleanup(&api, DOMAIN, &validation, &reused).unwrap();
        assert!(api.deleted.borrow().is_empty());
        api.rows.borrow_mut()[0]["content"] = "B".repeat(43).into();
        assert!(cleanup(&api, DOMAIN, &validation, &created).is_err());
        assert!(api.deleted.borrow().is_empty());
        assert!(auth(&api, "other.example", &validation).is_err());
    }
}
