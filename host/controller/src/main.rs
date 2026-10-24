mod attestation;
mod bootstrap;
mod bundle;
mod certificates;
mod control_identity;
mod dns;
mod helpers;
mod host;
mod logs;
mod protocol;
mod releases;
mod runtime;
mod server;
#[cfg(test)]
mod test_material;
#[cfg(test)]
mod tests;

use anyhow::{Result, ensure};
use clap::Parser;
use std::{path::PathBuf, sync::Arc};

#[derive(Parser, Clone)]
struct Args {
    #[arg(long)]
    data: PathBuf,
    #[arg(long)]
    runtime_dir: PathBuf,
    #[arg(long)]
    release_public_key: PathBuf,
    #[arg(long)]
    release_origin: String,
    #[arg(long)]
    release_store: PathBuf,
    #[arg(long)]
    attest_binary: PathBuf,
    #[arg(long)]
    tls_certificate: PathBuf,
    #[arg(long)]
    tls_key: PathBuf,
    #[arg(long)]
    client_ca: PathBuf,
    #[arg(long)]
    client_certificate: PathBuf,
    #[arg(long)]
    admin_ca: PathBuf,
    #[arg(long)]
    admin_certificate: PathBuf,
    #[arg(long, default_value_t = 8443)]
    port: u16,
    #[arg(long)]
    certbot: PathBuf,
    #[cfg(test)]
    #[arg(skip)]
    mock_releases: bool,
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("NODANA_HOST_PANIC")));
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Some(result) = helpers::dispatch() {
        if result.is_err() {
            let code = match std::env::args().nth(1).as_deref() {
                Some("dns") => "dns_challenge_failed",
                Some("boot") => "NODANA_PROTECTED_HOST_BOOT_FAILED",
                _ => "native_release_verification_failed",
            };
            eprintln!("{code}");
            std::process::exit(1);
        }
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build();
    let result = runtime
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(run()));
    if result.is_err() {
        eprintln!("NODANA_HOST_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    unsafe {
        libc::umask(0o077);
    }
    validate_storage(&args.data)?;
    let host_args = args.clone();
    let host = Arc::new(tokio::task::spawn_blocking(move || host::Host::open(host_args)).await??);
    let worker = host.clone();
    let worker_thread = std::thread::spawn(move || worker.work());
    let certificate_host = host.clone();
    let certificate_thread = std::thread::spawn(move || certificate_host.certificate_work());
    let servers = server::serve(host.clone());
    tokio::pin!(servers);
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = &mut servers => { if result.is_err() { eprintln!("NODANA_LISTENER_FAILED"); } },
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
    host.stopping
        .store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::task::spawn_blocking(move || {
        let _ = worker_thread.join();
        let _ = certificate_thread.join();
        host.runtime.stop_all();
        let _ = std::process::Command::new("umount")
            .arg(&args.release_store)
            .output();
        let _ = std::process::Command::new("umount")
            .arg(&args.data)
            .output();
        let _ = std::process::Command::new("cryptsetup")
            .args(["close", "nodana-phoenix"])
            .output();
    })
    .await?;
    Ok(())
}

fn validate_storage(data: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let boot =
        std::fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")?;
    ensure!(boot.get(4..) == Some(&[1]), "secure boot required");
    let device = std::fs::metadata(data)?.dev();
    let parent_device = std::fs::metadata(
        data.parent()
            .ok_or_else(|| anyhow::anyhow!("invalid data directory"))?,
    )?
    .dev();
    ensure!(
        device != parent_device,
        "mounted encrypted storage required"
    );
    #[cfg(target_os = "linux")]
    {
        let uuid = std::fs::read_to_string(format!(
            "/sys/dev/block/{}:{}/dm/uuid",
            libc::major(device),
            libc::minor(device)
        ))?;
        ensure!(
            uuid.starts_with("CRYPT-LUKS2-"),
            "encrypted storage required"
        );
    }
    Ok(())
}
