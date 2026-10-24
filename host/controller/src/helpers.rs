use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
struct Helpers {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Unlock the protected data disk and exec the controller.
    Boot {
        #[arg(long)]
        config: PathBuf,
    },
    /// Certbot DNS hook. Tokens and provider errors never reach stdout.
    Dns {
        action: String,
        credentials: PathBuf,
    },
    /// Independently verify a downloaded bundle before publication.
    VerifyBundle {
        #[arg(long)]
        release: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        approve_sha256: String,
    },
}
pub fn dispatch() -> Option<Result<()>> {
    let first = std::env::args_os().nth(1)?;
    if !["boot", "dns", "verify-bundle"]
        .iter()
        .any(|name| first == *name)
    {
        return None;
    }
    Some(match Helpers::parse().command {
        Action::Boot { config } => crate::bootstrap::boot(&config),
        Action::Dns {
            action,
            credentials,
        } => crate::dns::run(&action, &credentials)
            .map_err(|_| anyhow::anyhow!("dns_challenge_failed")),
        Action::VerifyBundle {
            release,
            public_key,
            approve_sha256,
        } => {
            let store = crate::bundle::Store {
                root: PathBuf::new(),
                key: public_key,
                origin: String::new(),
            };
            store
                .verify_download(&release, &approve_sha256)
                .map(|identity| println!("{identity}"))
        }
    })
}
