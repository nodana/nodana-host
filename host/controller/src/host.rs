use crate::{Args, certificates::Certificates, logs::Logs, protocol::*, runtime::Runtime};
use anyhow::{Context, Result};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    fs::File,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub struct Host {
    pub args: Args,
    pub runtime: Runtime,
    pub certificates: Certificates,
    pub control_identity: crate::control_identity::ControlIdentity,
    pub logs: Mutex<Logs>,
    db: Mutex<Connection>,
    operation: Mutex<()>,
    _lock: File,
    pub stopping: AtomicBool,
}
impl Host {
    #[cfg(test)]
    pub fn test_job(&self, job: &Job, slot: usize) {
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO deployments VALUES(?,?,?,?,'ready',1)",
                params![job.deployment_id, job.node_id, canonical(job), slot],
            )
            .unwrap();
    }
    pub fn open(args: Args) -> Result<Self> {
        let root = args.data.join("control");
        std::fs::create_dir_all(&root)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("host.lock"))?;
        lock.try_lock_exclusive()?;
        let db = Connection::open(root.join("control.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS deployments(deployment_id TEXT PRIMARY KEY,node_id TEXT NOT NULL UNIQUE,request BLOB NOT NULL,slot INTEGER NOT NULL UNIQUE,status TEXT NOT NULL,ever_ready INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS deletions(deployment_id TEXT PRIMARY KEY,node_id TEXT NOT NULL UNIQUE,account_id TEXT NOT NULL,status TEXT NOT NULL);UPDATE deployments SET status='queued' WHERE status IN ('ready','starting');")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS lifecycle_operations(operation_id TEXT PRIMARY KEY,deployment_id TEXT NOT NULL,node_id TEXT NOT NULL,account_id TEXT NOT NULL,action TEXT NOT NULL,applied INTEGER NOT NULL);UPDATE deployments SET status='stopped' WHERE status='stopping';")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS native_updates(operation_id TEXT PRIMARY KEY,deployment_id TEXT NOT NULL,source_sha256 TEXT NOT NULL,target_sha256 TEXT NOT NULL,applied INTEGER NOT NULL DEFAULT 0);")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS host_settings(key TEXT PRIMARY KEY,value INTEGER NOT NULL);INSERT OR IGNORE INTO host_settings VALUES('capacity',0);")?;
        db.execute_batch("UPDATE deployments SET status='queued' WHERE status='stopped' AND EXISTS(SELECT 1 FROM native_updates u WHERE u.deployment_id=deployments.deployment_id AND u.applied=0 AND u.target_sha256=json_extract(CAST(deployments.request AS TEXT),'$.releaseSha256'));UPDATE native_updates SET applied=1 WHERE applied=0 AND EXISTS(SELECT 1 FROM deployments d WHERE d.deployment_id=native_updates.deployment_id AND d.status='queued' AND native_updates.target_sha256=json_extract(CAST(d.request AS TEXT),'$.releaseSha256'));")?;
        let mut runtime = Runtime::new(&args.data, std::env::current_exe()?)?;
        runtime.releases = Some(crate::releases::Releases::new(&args));
        Ok(Self {
            runtime,
            certificates: Certificates::new(args.clone())?,
            control_identity: crate::control_identity::ControlIdentity::open(&args)?,
            args,
            logs: Mutex::new(Logs::new()),
            db: Mutex::new(db),
            operation: Mutex::new(()),
            _lock: lock,
            stopping: AtomicBool::new(false),
        })
    }
    pub fn provision(&self, mut value: Value) -> Result<Value> {
        let credentials = value
            .as_object_mut()
            .context("invalid creation request")?
            .remove("credentials");
        let job: Job = serde_json::from_value(value)?;
        job.validate()?;
        self.runtime
            .releases
            .as_ref()
            .context("release store unavailable")?
            .identity(&job.release_sha256)?;
        if !self.certificates.ready() {
            return Err(fail(503, "public_tls_not_ready"));
        }
        let mut db = self.db.lock().unwrap();
        let transaction = db.transaction()?;
        let deleted: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM deletions WHERE deployment_id=? OR node_id=?)",
            params![job.deployment_id, job.node_id],
            |r| r.get(0),
        )?;
        if deleted {
            return Err(fail(409, "node_deleted"));
        }
        let existing:Option<(String,String,Vec<u8>,String)>=transaction.query_row("SELECT deployment_id,node_id,request,status FROM deployments WHERE deployment_id=? OR node_id=?",params![job.deployment_id,job.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((deployment, node, request, mut status)) = existing {
            if request != canonical(&job) {
                return Err(fail(409, "deployment_conflict"));
            }
            if status == "ready" && !self.runtime.healthy(&node) {
                status = "failed".into();
                transaction.execute(
                    "UPDATE deployments SET status='failed' WHERE deployment_id=?",
                    [&deployment],
                )?;
            }
            transaction.commit()?;
            return Ok(json!({"deploymentId":deployment,"nodeId":node,"status":status}));
        }
        let used = transaction
            .prepare("SELECT slot FROM deployments")?
            .query_map([], |r| r.get::<_, usize>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let capacity: usize = transaction.query_row(
            "SELECT value FROM host_settings WHERE key='capacity'",
            [],
            |row| row.get(0),
        )?;
        if used.len() >= capacity {
            return Err(fail(503, "host_capacity_exhausted"));
        }
        // Slots retain their UID and port when the operating limit is reduced.
        let slot = (0..=usize::from(u16::MAX) - 20000)
            .find(|slot| !used.contains(slot))
            .ok_or_else(|| fail(503, "host_capacity_exhausted"))?;
        if let Some(credentials) = &credentials {
            self.runtime
                .install_credentials(&job.node_id, slot, credentials)
                .map_err(|_| fail(400, "invalid_creation_credentials"))?;
        }
        transaction.execute(
            "INSERT INTO deployments VALUES (?,?,?,?,'queued',0)",
            params![job.deployment_id, job.node_id, canonical(&job), slot],
        )?;
        transaction.commit()?;
        Ok(json!({"deploymentId":job.deployment_id,"nodeId":job.node_id,"status":"queued"}))
    }
    pub fn job(&self, deployment: &str) -> Result<(Job, String)> {
        id(deployment, "deployment", 24)?;
        let db = self.db.lock().unwrap();
        let (request, mut status): (Vec<u8>, String) = db
            .query_row(
                "SELECT request,status FROM deployments WHERE deployment_id=?",
                [deployment],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| fail(404, "deployment_not_found"))?;
        let job: Job = serde_json::from_slice(&request)?;
        if status == "ready" && !self.runtime.healthy(&job.node_id) {
            status = "failed".into();
            db.execute(
                "UPDATE deployments SET status='failed' WHERE deployment_id=?",
                [deployment],
            )?;
        }
        Ok((job, status))
    }
    pub fn ready_job(&self, deployment: &str) -> Result<Job> {
        let (job, status) = self.job(deployment)?;
        if status != "ready" {
            return Err(fail(409, "node_not_ready"));
        }
        Ok(job)
    }
    pub fn deployment(&self, deployment: &str) -> Result<Value> {
        let (job, status) = self.job(deployment)?;
        Ok(json!({"deploymentId":job.deployment_id,"nodeId":job.node_id,"status":status}))
    }
    pub fn public_job(&self, node: &str, hostname: Option<&str>) -> Result<Job> {
        id(node, "node", 8)?;
        let deployment: String = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT deployment_id FROM deployments WHERE node_id=? AND status='ready'",
                [node],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| fail(404, "node_not_ready"))?;
        let job = self
            .ready_job(&deployment)
            .map_err(|_| fail(404, "node_not_ready"))?;
        if let Some(hostname) = hostname {
            if job.public_hostname.as_deref() != Some(hostname) {
                return Err(fail(404, "node_not_ready"));
            }
        }
        Ok(job)
    }
    pub fn release_attestation(&self, deployment: &str, value: Value) -> Result<Value> {
        crate::certificates::fields(&value, &["nonce"])?;
        let nonce = decode(value["nonce"].as_str().context("invalid nonce")?, 32)?;
        let _guard = self.operation.lock().unwrap();
        let job = self.ready_job(deployment)?;
        let release = self.runtime.release_identity(&job.node_id)?;
        let identity = json!({"nodeId":job.node_id,"release":release});
        let document = attest(
            &self.args,
            &nonce,
            &binding(b"nodana-node-release-v1\0", &identity, None),
        )?;
        Ok(json!({"identity":identity,"attestationDocument":encode(document)}))
    }
    pub fn list_channels(&self, deployment: &str) -> Result<Value> {
        let _guard = self.operation.lock().unwrap();
        let job = self.ready_job(deployment)?;
        self.runtime.list_channels(&job.node_id)
    }

    pub fn close_channel(
        &self,
        deployment: &str,
        request: &crate::runtime::CloseChannel,
    ) -> Result<Value> {
        // Keep the deployment's process/slot stable through the funds operation.
        let _guard = self.operation.lock().unwrap();
        let job = self.ready_job(deployment)?;
        self.runtime.close_channel(&job.node_id, request)
    }

    pub fn lifecycle(&self, deployment: &str, value: Value) -> Result<Value> {
        crate::certificates::fields(&value, &["operationId", "nodeId", "accountId", "action"])?;
        let operation = value["operationId"].as_str().context("invalid operation")?;
        id(operation, "operation", 32).map_err(|_| fail(400, "invalid_operation"))?;
        let action = value["action"].as_str().context("invalid action")?;
        if !["start", "stop"].contains(&action) {
            return Err(fail(400, "invalid_action"));
        }
        let _guard = self.operation.lock().unwrap();
        let (job, status) = self.job(deployment)?;
        if value["nodeId"] != job.node_id || value["accountId"] != job.account_id {
            return Err(fail(409, "deployment_conflict"));
        }
        if status == "deleting" {
            return Err(fail(409, "node_deleted"));
        }
        {
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction()?;
            let previous:Option<(String,String,String,String,bool)>=tx.query_row("SELECT deployment_id,node_id,account_id,action,applied FROM lifecycle_operations WHERE operation_id=?",[operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            if let Some((d, n, a, original, applied)) = previous {
                if d != deployment || n != job.node_id || a != job.account_id || original != action
                {
                    return Err(fail(409, "operation_conflict"));
                }
                if applied {
                    return Ok(
                        json!({"deploymentId":deployment,"nodeId":job.node_id,"status":status}),
                    );
                }
            } else {
                tx.execute(
                    "INSERT INTO lifecycle_operations VALUES(?,?,?,?,?,0)",
                    params![operation, deployment, job.node_id, job.account_id, action],
                )?;
            }
            if action == "start" {
                if !self.certificates.ready() {
                    return Err(fail(503, "public_tls_not_ready"));
                }
                if status != "ready" {
                    tx.execute(
                        "UPDATE deployments SET status='queued' WHERE deployment_id=?",
                        [deployment],
                    )?;
                }
                tx.execute(
                    "UPDATE lifecycle_operations SET applied=1 WHERE operation_id=?",
                    [operation],
                )?;
                tx.commit()?;
                return Ok(
                    json!({"deploymentId":deployment,"nodeId":job.node_id,"status":if status=="ready"{"ready"}else{"starting"}}),
                );
            }
            tx.execute(
                "UPDATE deployments SET status='stopping' WHERE deployment_id=?",
                [deployment],
            )?;
            tx.commit()?;
        }
        self.runtime.stop(&job.node_id);
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE deployments SET status='stopped' WHERE deployment_id=?",
            [deployment],
        )?;
        tx.execute(
            "UPDATE lifecycle_operations SET applied=1 WHERE operation_id=?",
            [operation],
        )?;
        tx.commit()?;
        Ok(json!({"deploymentId":deployment,"nodeId":job.node_id,"status":"stopped"}))
    }
    pub fn update(&self, deployment: &str, value: Value) -> Result<Value> {
        crate::certificates::fields(
            &value,
            &["operationId", "nodeId", "accountId", "releaseSha256"],
        )?;
        let operation = value["operationId"].as_str().context("invalid operation")?;
        id(operation, "operation", 32)?;
        let target = value["releaseSha256"].as_str().context("invalid release")?;
        let _guard = self.operation.lock().unwrap();
        let (mut job, status) = self.job(deployment)?;
        if value["nodeId"] != job.node_id || value["accountId"] != job.account_id {
            return Err(fail(409, "deployment_conflict"));
        }
        let releases = self
            .runtime
            .releases
            .as_ref()
            .context("release store unavailable")?;
        let mut db = self.db.lock().unwrap();
        let previous: Option<(String, String, String, bool)> = db.query_row(
            "SELECT deployment_id,source_sha256,target_sha256,applied FROM native_updates WHERE operation_id=?",
            [operation], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        if let Some((original, _, selected, applied)) = &previous {
            if original != deployment || selected != target {
                return Err(fail(409, "operation_conflict"));
            }
            if *applied {
                return Ok(
                    json!({"deploymentId":deployment,"nodeId":job.node_id,"status":status,"releaseSha256":job.release_sha256}),
                );
            }
        } else {
            if status != "ready" {
                return Err(fail(409, "node_not_ready"));
            }
            let actual = self.runtime.release_identity(&job.node_id)?;
            if actual["releaseSha256"] != job.release_sha256 {
                return Err(fail(409, "runtime_release_mismatch"));
            }
            // Verify compatibility before stopping or changing any wallet files.
            releases.permits(&job.release_sha256, target)?;
            db.execute("INSERT INTO native_updates(operation_id,deployment_id,source_sha256,target_sha256) VALUES(?,?,?,?)", params![operation,deployment,job.release_sha256,target])?;
        }
        releases.identity(target)?;
        // Commit the selection before stopping. A crash resumes the target;
        // it must never reopen a potentially migrated wallet with the old binary.
        job.release_sha256 = target.into();
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE deployments SET request=?,status='stopping' WHERE deployment_id=?",
            params![canonical(&job), deployment],
        )?;
        tx.commit()?;
        self.runtime.stop(&job.node_id);
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE deployments SET status='queued' WHERE deployment_id=?",
            [deployment],
        )?;
        tx.execute(
            "UPDATE native_updates SET applied=1 WHERE operation_id=?",
            [operation],
        )?;
        tx.commit()?;
        Ok(
            json!({"deploymentId":deployment,"nodeId":job.node_id,"status":"starting","releaseSha256":target}),
        )
    }

    pub fn delete(&self, value: Value) -> Result<Value> {
        crate::certificates::fields(&value, &["deploymentId", "nodeId", "accountId"])?;
        let deployment = value["deploymentId"]
            .as_str()
            .context("invalid deployment")?;
        let node = value["nodeId"].as_str().context("invalid node")?;
        let account = value["accountId"].as_str().context("invalid account")?;
        id(deployment, "deployment", 24)?;
        id(node, "node", 8)?;
        id(account, "account", 8)?;
        let _guard = self.operation.lock().unwrap();
        self.delete_locked(deployment, node, account)
    }
    fn delete_locked(&self, deployment: &str, node: &str, account: &str) -> Result<Value> {
        {
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction()?;
            let request: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT request FROM deployments WHERE deployment_id=? OR node_id=?",
                    params![deployment, node],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(request) = request {
                let job: Job = serde_json::from_slice(&request)?;
                if job.deployment_id != deployment
                    || job.node_id != node
                    || job.account_id != account
                {
                    return Err(fail(409, "deployment_conflict"));
                }
            }
            let tombstone:Option<(String,String,String,String)>=tx.query_row("SELECT deployment_id,node_id,account_id,status FROM deletions WHERE deployment_id=? OR node_id=?",params![deployment,node],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            if let Some((d, n, a, status)) = tombstone {
                if d != deployment || n != node || a != account {
                    return Err(fail(409, "deployment_conflict"));
                }
                if status == "deleted" {
                    return Ok(json!({"deploymentId":deployment,"nodeId":node,"status":"deleted"}));
                }
            }
            tx.execute(
                "INSERT OR IGNORE INTO deletions VALUES(?,?,?,'deleting')",
                params![deployment, node, account],
            )?;
            tx.execute(
                "UPDATE deployments SET status='deleting' WHERE deployment_id=?",
                [deployment],
            )?;
            tx.commit()?;
        }
        self.runtime.delete(node)?;
        self.logs.lock().unwrap().remove(node);
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "DELETE FROM deployments WHERE deployment_id=?",
            [deployment],
        )?;
        tx.execute(
            "UPDATE deletions SET status='deleted' WHERE deployment_id=?",
            [deployment],
        )?;
        tx.commit()?;
        Ok(json!({"deploymentId":deployment,"nodeId":node,"status":"deleted"}))
    }
    pub fn run_next(&self) -> Result<bool> {
        let _guard = self.operation.lock().unwrap();
        let deletion:Option<(String,String,String)>=self.db.lock().unwrap().query_row("SELECT deployment_id,node_id,account_id FROM deletions WHERE status='deleting' LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((deployment, node, account)) = deletion {
            self.delete_locked(&deployment, &node, &account)?;
            return Ok(true);
        }
        let row: Option<(Vec<u8>, usize, bool)> = {
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction()?;
            let row:Option<(Vec<u8>,usize,bool)>=tx.query_row("SELECT request,slot,ever_ready FROM deployments WHERE status='queued' ORDER BY slot LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((ref request, _, _)) = row {
                let job: Job = serde_json::from_slice(request)?;
                tx.execute(
                    "UPDATE deployments SET status='starting' WHERE deployment_id=?",
                    [job.deployment_id],
                )?;
            }
            tx.commit()?;
            row
        };
        let Some((request, slot, previous)) = row else {
            return Ok(false);
        };
        let job: Job = serde_json::from_slice(&request)?;
        if self.runtime.start(&job, slot, previous).is_ok() {
            self.db.lock().unwrap().execute(
                "UPDATE deployments SET status='ready',ever_ready=1 WHERE deployment_id=?",
                [job.deployment_id],
            )?;
        } else {
            self.runtime.stop(&job.node_id);
            self.db.lock().unwrap().execute(
                "UPDATE deployments SET status='failed' WHERE deployment_id=?",
                [job.deployment_id],
            )?;
        }
        Ok(true)
    }
    pub fn configure_capacity(&self, value: Value) -> Result<Value> {
        crate::certificates::fields(&value, &["capacity"])?;
        let capacity = value["capacity"]
            .as_u64()
            .filter(|value| (1..=u64::from(u16::MAX) - 20000 + 1).contains(value))
            .ok_or_else(|| fail(400, "invalid_capacity"))?;
        self.db.lock().unwrap().execute(
            "UPDATE host_settings SET value=? WHERE key='capacity'",
            [capacity],
        )?;
        Ok(json!({"capacity":capacity}))
    }
    pub fn capacity(&self) -> Result<usize> {
        Ok(self.db.lock().unwrap().query_row(
            "SELECT value FROM host_settings WHERE key='capacity'",
            [],
            |row| row.get(0),
        )?)
    }
    pub fn resources(&self) -> Result<Value> {
        let mut value = self.runtime.resources();
        let capacity = self.capacity()?;
        value["capacity"] = json!(capacity);
        value["ready"] = json!(capacity > 0 && self.certificates.ready());
        value["bootId"] = json!(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim());
        let mut tls = self.certificates.status()?;
        tls["listening"] = json!(self.certificates.ready());
        value["publicTls"] = tls;
        Ok(value)
    }
    pub fn work(&self) {
        while !self.stopping.load(Ordering::Relaxed) {
            match self.run_next() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => eprintln!("NODANA_HOST_WORKER_FAILURE"),
            };
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    pub fn certificate_work(&self) {
        while !self.stopping.load(Ordering::Relaxed) {
            if self.certificates.tick().is_err() {
                eprintln!("NODANA_CERTIFICATE_SERVICE_FAILURE");
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

#[derive(Debug)]
pub struct Fault {
    pub status: u16,
    pub code: &'static str,
}
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Fault {}
pub fn fail(status: u16, code: &'static str) -> anyhow::Error {
    anyhow::Error::new(Fault { status, code })
}
