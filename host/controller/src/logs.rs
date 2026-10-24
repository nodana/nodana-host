use crate::protocol::now;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
const CAPACITY: usize = 500;
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub id: String,
    pub node_id: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub duration_ms: u64,
    pub created_at: u64,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Query {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
    pub query: Option<String>,
    pub method: Option<String>,
    pub cursor: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub logs: Vec<Entry>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    pub next_cursor: Option<String>,
    pub epoch: String,
}
pub struct Logs {
    epoch: String,
    sequence: u64,
    nodes: BTreeMap<String, VecDeque<Entry>>,
}
impl Logs {
    pub fn new() -> Self {
        Self {
            epoch: hex::encode(rand::random::<[u8; 16]>()),
            sequence: 0,
            nodes: BTreeMap::new(),
        }
    }
    pub fn record(&mut self, node: &str, method: &str, path: &str, status: u16, millis: u64) {
        // Never retain arbitrary paths: identifiers, invoices or secrets may be
        // embedded in them. Keep only recognised route templates.
        let path = safe_path(path);
        if path == "/[unrecognised]" {
            return;
        }
        self.sequence += 1;
        let entries = self.nodes.entry(node.into()).or_default();
        if entries.len() == CAPACITY {
            entries.pop_front();
        }
        entries.push_back(Entry {
            id: format!("{}:{}", self.epoch, self.sequence),
            node_id: node.into(),
            method: match method {
                "GET" | "POST" | "DELETE" | "PATCH" | "PUT" | "HEAD" | "OPTIONS" => method,
                _ => "OTHER",
            }
            .into(),
            path,
            status_code: status,
            duration_ms: millis.min(600_000),
            created_at: now(),
        });
    }
    pub fn remove(&mut self, node: &str) {
        self.nodes.remove(node);
    }
    pub fn page(&self, node: &str, query: Query) -> anyhow::Result<Page> {
        let page = query.page.unwrap_or(1);
        let size = query.page_size.unwrap_or(25);
        anyhow::ensure!(
            (1..=100).contains(&size)
                && page >= 1
                && page <= 500
                && query.query.as_ref().is_none_or(|s| s.len() <= 256)
                && query.method.as_ref().is_none_or(|s| s.len() <= 16),
            "invalid log query"
        );
        let before = if let Some(cursor) = query.cursor {
            let (epoch, sequence) = cursor
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid cursor"))?;
            anyhow::ensure!(page == 1, "invalid cursor page");
            let sequence = sequence.parse::<u64>()?;
            if epoch != self.epoch {
                None
            } else {
                Some(sequence)
            }
        } else {
            None
        };
        let search = query.query.unwrap_or_default().trim().to_ascii_lowercase();
        let method = query.method.map(|s| s.to_ascii_uppercase());
        let matches: Vec<_> = self
            .nodes
            .get(node)
            .into_iter()
            .flatten()
            .rev()
            .filter(|e| {
                method
                    .as_ref()
                    .is_none_or(|m| m.is_empty() || m == &e.method)
                    && format!("{} {} {}", e.method, e.path, e.status_code)
                        .to_ascii_lowercase()
                        .contains(&search)
            })
            .collect();
        let total = matches.len();
        let mut entries: Vec<_> = matches
            .into_iter()
            .filter(|e| {
                before.is_none_or(|n| {
                    e.id.rsplit(':')
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .is_some_and(|id| id < n)
                })
            })
            .skip((page - 1) * size)
            .take(size + 1)
            .cloned()
            .collect();
        let more = entries.len() > size;
        entries.truncate(size);
        let next_cursor = if more {
            entries.last().map(|e| e.id.clone())
        } else {
            None
        };
        Ok(Page {
            logs: entries,
            total,
            page,
            page_size: size,
            total_pages: total.div_ceil(size),
            next_cursor,
            epoch: self.epoch.clone(),
        })
    }
}
fn safe_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    const ROUTES: &[&str] = &[
        "/getinfo",
        "/getbalance",
        "/createinvoice",
        "/payinvoice",
        "/payoffer",
        "/paylnaddress",
        "/lnurlpay",
        "/lnurlwithdraw",
        "/lnurlauth",
        "/createoffer",
        "/getoffer",
        "/getlnurl",
        "/getbolt12invoice",
        "/estimateliquidityfees",
        "/payments/incoming",
        "/payments/outgoing",
        "/attestation",
    ];
    if ROUTES.contains(&path) {
        path.into()
    } else if path.starts_with("/payments/incoming/") {
        "/payments/incoming/:paymentHash".into()
    } else if path.starts_with("/payments/outgoing/") {
        "/payments/outgoing/:paymentId".into()
    } else {
        "/[unrecognised]".into()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_private_and_node_scoped() {
        let mut logs = Logs::new();
        for _ in 0..510 {
            logs.record("node-a1b2", "GET", "/getinfo?password=secret", 200, 2);
        }
        logs.record("node-c3d4", "POST", "/SECRET/invoice", 401, 1);
        let page = logs.page("node-a1b2", Query::default()).unwrap();
        assert_eq!(page.total, 500);
        assert!(page.logs.iter().all(|e| e.path == "/getinfo"));
        let next = logs
            .page(
                "node-a1b2",
                Query {
                    cursor: page.next_cursor,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            next.logs
                .iter()
                .all(|e| !page.logs.iter().any(|a| a.id == e.id))
        );
        assert_eq!(logs.page("node-c3d4", Query::default()).unwrap().total, 0);
        logs.remove("node-a1b2");
        assert_eq!(logs.page("node-a1b2", Query::default()).unwrap().total, 0);
    }
}
