use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use openfortivpn_manager_headless::install::{self, INSTALLED_ENGINE};
use openfortivpn_manager_headless::storage::Storage;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "openfortivpn-manager-headless",
    version,
    about = "Headless openfortivpn manager"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = "/etc/openfortivpn-manager-headless"
    )]
    config_dir: PathBuf,
    #[arg(
        long,
        global = true,
        default_value = "/var/lib/openfortivpn-manager-headless"
    )]
    state_dir: PathBuf,
    #[arg(
        long,
        global = true,
        default_value = "/run/openfortivpn-manager-headless"
    )]
    runtime_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install this binary, the VPN engine and the systemd service.
    Install {
        /// Path to the already-built openfortivpn binary; auto-detected when omitted.
        #[arg(long)]
        engine: Option<PathBuf>,
        /// Install files without enabling or starting the systemd service.
        #[arg(long)]
        no_start: bool,
        /// Suppress all successful installation output (for package managers and CI).
        #[arg(long, conflicts_with = "show_token")]
        quiet: bool,
        /// Explicitly print the sensitive Bearer token after installation.
        #[arg(long, conflicts_with = "quiet")]
        show_token: bool,
    },
    /// Disable and remove the installed service and binaries.
    Uninstall {
        /// Also permanently remove profiles, secrets, token and TLS identity.
        #[arg(long)]
        purge: bool,
    },
    /// Show or rotate the remote access token.
    Token {
        #[arg(long)]
        rotate: bool,
    },
    /// Show service and profile status.
    Status,
    /// Run the HTTPS manager in the foreground.
    Serve {
        #[arg(long, default_value = INSTALLED_ENGINE)]
        engine: PathBuf,
        /// Override server.json for this process only.
        #[arg(long)]
        bind_address: Option<String>,
        /// Override server.json for this process only.
        #[arg(long)]
        port: Option<u16>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = Storage::new(cli.config_dir, cli.state_dir, cli.runtime_dir);
    match cli.command {
        Command::Install {
            engine,
            no_start,
            quiet,
            show_token,
        } => {
            if storage.config_dir != Storage::default().config_dir
                || storage.state_dir != Storage::default().state_dir
                || storage.runtime_dir != Storage::default().runtime_dir
            {
                bail!("install uses fixed system paths; remove directory override flags");
            }
            let installed = install::install(engine, !no_start, quiet)?;
            let token = if show_token {
                Some(storage.load_or_create_token()?)
            } else {
                None
            };
            print!(
                "{}",
                format_install_output(&installed, quiet, show_token, token.as_deref())?
            );
        }
        Command::Uninstall { purge } => {
            install::uninstall(purge)?;
            println!(
                "openfortivpn-manager-headless removed{}",
                if purge { " (data purged)" } else { "" }
            );
        }
        Command::Token { rotate } => {
            storage.ensure_layout()?;
            let token = if rotate {
                storage.rotate_token()?
            } else {
                storage.load_or_create_token()?
            };
            println!("{token}");
            if rotate {
                eprintln!("token rotated; restart the service to activate it: sudo systemctl restart openfortivpn-manager-headless");
            }
        }
        Command::Status => {
            println!("{}", install::service_status(&storage)?);
        }
        Command::Serve {
            engine,
            bind_address,
            port,
        } => {
            if !engine.is_file() {
                bail!("openfortivpn engine not found: {}", engine.display());
            }
            openfortivpn_manager_headless::serve(storage, engine, bind_address, port)
                .await
                .context("headless service failed")?;
        }
    }
    Ok(())
}

fn format_install_output(
    installed: &install::InstallResult,
    quiet: bool,
    show_token: bool,
    token: Option<&str>,
) -> Result<String> {
    if quiet {
        return Ok(String::new());
    }
    let mut output = format!(
        "installed manager: {}\ninstalled engine: {}\ninstalled systemd unit: {}\n",
        installed.binary.display(),
        installed.engine.display(),
        installed.unit.display(),
    );
    if show_token {
        let token = token.ok_or_else(|| anyhow::anyhow!("access token was not loaded"))?;
        output.push_str(&format!(
            "access token (sensitive; store securely): {token}\n"
        ));
    } else {
        output.push_str(
            "access token: hidden; view it with `sudo openfortivpn-manager-headless token`\n",
        );
    }
    output.push_str("HTTPS endpoint: https://SERVER:18443/\n");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn installed() -> install::InstallResult {
        install::InstallResult {
            binary: "/manager".into(),
            engine: "/engine".into(),
            unit: "/manager.service".into(),
        }
    }

    #[test]
    fn default_install_output_never_contains_the_token() {
        let secret = "TOP-SECRET-BEARER-TOKEN";
        let output = format_install_output(&installed(), false, false, None).unwrap();
        assert!(!output.contains(secret));
        assert!(output.contains("openfortivpn-manager-headless token"));
    }

    #[test]
    fn quiet_install_has_no_success_output() {
        let output = format_install_output(&installed(), true, false, None).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn show_token_is_explicit_and_cannot_be_combined_with_quiet() {
        let secret = "TOP-SECRET-BEARER-TOKEN";
        let output = format_install_output(&installed(), false, true, Some(secret)).unwrap();
        assert!(output.contains(secret));
        assert!(Cli::try_parse_from(["manager", "install", "--quiet", "--show-token"]).is_err());
    }

    #[test]
    fn debian_postinst_uses_quiet_install_without_token_opt_in() {
        let postinst = include_str!("../packaging/debian/postinst");
        assert!(postinst.contains("--quiet"));
        assert!(!postinst.contains("--show-token"));
    }
}
