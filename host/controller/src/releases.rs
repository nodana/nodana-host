use crate::{Args, bundle::Store};
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Releases {
    key: PathBuf,
    origin: String,
    pub store: PathBuf,
    #[cfg(test)]
    mock: bool,
}

pub use crate::bundle::checksum;

impl Releases {
    pub fn new(args: &Args) -> Self {
        Self {
            key: args.release_public_key.clone(),
            origin: args.release_origin.clone(),
            store: args.release_store.clone(),
            #[cfg(test)]
            mock: args.mock_releases,
        }
    }
    fn runtime(&self) -> Store {
        Store {
            root: self.store.clone(),
            key: self.key.clone(),
            origin: self.origin.clone(),
        }
    }
    pub fn prepare(&self, request: Value) -> Result<Value> {
        self.runtime()
            .prepare(request)
            .map_err(|_| anyhow::anyhow!("native_release_verification_failed"))
    }
    pub fn identity(&self, release: &str) -> Result<Value> {
        ensure!(checksum(release), "invalid release");
        #[cfg(test)]
        if self.mock {
            return Ok(
                serde_json::json!({"releaseSha256":release,"version":if release=="b".repeat(64){"0.2.0"}else{"0.1.0"},"phoenixdVersion":"0.9.3","stateFormat":"phoenixd-0.9.3"}),
            );
        }
        self.runtime()
            .identity(release)
            .map_err(|_| anyhow::anyhow!("native_release_verification_failed"))
    }
    pub fn permits(&self, current: &str, target: &str) -> Result<()> {
        ensure!(checksum(current) && checksum(target), "invalid release");
        #[cfg(test)]
        if self.mock {
            ensure!(
                current == "a".repeat(64) && target == "b".repeat(64),
                "unsupported test update"
            );
            return Ok(());
        }
        self.runtime()
            .permits(current, target)
            .map_err(|_| anyhow::anyhow!("native_release_verification_failed"))
    }
    pub fn entrypoint(&self, release: &str) -> Result<PathBuf> {
        self.identity(release)?;
        Ok(self.store.join(release).join("bin/nodana-phoenixd"))
    }
}
