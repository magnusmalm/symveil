use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;

use symveil::audit::AuditLog;
use symveil::build_engine;
#[cfg(feature = "identifiers")]
use symveil::category::Category;
use symveil::config::{resolve_path, Config};
use symveil::proxy::{self, AppState};
use symveil::vault::Vault;

#[cfg(feature = "identifiers")]
use symveil::{index_repo, IndexOptions, IndexReport};

#[derive(Parser)]
#[command(
    name = "symveil",
    version,
    about = "Reversible local redaction between coding agents and cloud LLMs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Index a C/C++ repository and write the local vault.
    #[cfg(feature = "identifiers")]
    Index(IndexArgs),
    /// Proxy OpenAI and Anthropic APIs, redacting requests and restoring responses.
    Proxy(ProxyArgs),
    /// Redact stdin to stdout using the vault and policy.
    Redact(TextArgs),
    /// Restore placeholders on stdin back to the original text.
    Restore(TextArgs),
}

#[cfg(feature = "identifiers")]
#[derive(clap::Args)]
struct IndexArgs {
    /// Repository root.
    #[arg(default_value = ".")]
    repo: PathBuf,
    /// Path to .symveil.toml. Defaults to the nearest file at or above the repo.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Replace the vault instead of merging into it.
    #[arg(long)]
    reset: bool,
    /// Print each learned term. Secrets are shown by rule and length only.
    #[arg(long)]
    verbose: bool,
}

#[derive(clap::Args)]
struct ProxyArgs {
    /// Listen port. Overrides .symveil.toml.
    #[arg(long)]
    port: Option<u16>,
    /// Repository root used to find the vault and config.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    /// OpenAI origin, without a trailing /v1.
    #[arg(long)]
    openai_base: Option<String>,
    /// Anthropic origin, without a trailing /v1.
    #[arg(long)]
    anthropic_base: Option<String>,
}

#[derive(clap::Args)]
struct TextArgs {
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("symveil: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    match Cli::parse().cmd {
        #[cfg(feature = "identifiers")]
        Command::Index(args) => cmd_index(args),
        Command::Proxy(args) => cmd_proxy(args).await,
        Command::Redact(args) => cmd_text(args, true),
        Command::Restore(args) => cmd_text(args, false),
    }
}

fn load_context(repo: &Path, config: Option<&Path>) -> Result<(PathBuf, Config)> {
    let root = repo
        .canonicalize()
        .with_context(|| format!("open {}", repo.display()))?;
    if !root.is_dir() {
        anyhow::bail!("{} is not a directory", root.display());
    }
    let cfg = Config::load_for(&root, config)?;
    Ok((root, cfg))
}

fn open_vault(root: &Path, cfg: &Config) -> Result<Vault> {
    let vault_path = resolve_path(root, &cfg.proxy.vault);
    if vault_path.exists() {
        return Vault::load(&vault_path);
    }
    #[cfg(feature = "identifiers")]
    {
        eprintln!(
            "no vault at {}, indexing {}",
            vault_path.display(),
            root.display()
        );
        let report = index_repo(
            root,
            cfg,
            &IndexOptions {
                vault_path: Some(vault_path),
                reset: false,
            },
        )?;
        for warning in &report.warnings {
            eprintln!("warning: {warning}");
        }
        Ok(report.vault)
    }
    #[cfg(not(feature = "identifiers"))]
    {
        eprintln!("no vault at {}; masking secrets only", vault_path.display());
        Ok(Vault::create(vault_path))
    }
}

#[cfg(feature = "identifiers")]
fn cmd_index(args: IndexArgs) -> Result<()> {
    let (root, cfg) = load_context(&args.repo, args.config.as_deref())?;
    let vault_path = resolve_path(&root, &cfg.proxy.vault);
    let report = index_repo(
        &root,
        &cfg,
        &IndexOptions {
            vault_path: Some(vault_path),
            reset: args.reset,
        },
    )?;
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    print_report(&report, args.verbose);
    Ok(())
}

#[cfg(feature = "identifiers")]
fn print_report(report: &IndexReport, verbose: bool) {
    println!("scanned {} files", report.files);
    let counts = report.vault.counts();
    if counts.is_empty() {
        println!("vault is empty");
    }
    for (category, count) in &counts {
        println!("  {category:<12} {count}");
    }
    if verbose {
        for entry in report.vault.iter() {
            match entry.category {
                Category::Secret => {
                    let rule = entry.rule.as_deref().unwrap_or("secret");
                    println!(
                        "  secret {rule} len={} {}",
                        entry.original.len(),
                        entry.placeholder
                    );
                }
                Category::Function
                | Category::Type
                | Category::Macro
                | Category::Register
                | Category::Field
                | Category::Enumerator
                | Category::Codename
                | Category::Hostname
                | Category::Ip
                | Category::Identifier => {
                    println!(
                        "  {} {} {}",
                        entry.category, entry.original, entry.placeholder
                    );
                }
            }
        }
    }
    if let Some(path) = report.vault.path() {
        println!("vault {}", path.display());
    }
    println!("restart `symveil proxy` if it is already running");
}

async fn cmd_proxy(args: ProxyArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "symveil=info".into()),
        )
        .with_target(false)
        .init();

    let (root, mut cfg) = load_context(&args.repo, args.config.as_deref())?;
    if let Some(port) = args.port {
        cfg.proxy.port = port;
    }
    if let Some(base) = args.openai_base {
        cfg.proxy.openai_base = base;
    }
    if let Some(base) = args.anthropic_base {
        cfg.proxy.anthropic_base = base;
    }

    let vault_path = resolve_path(&root, &cfg.proxy.vault);
    let vault = open_vault(&root, &cfg)?;
    let entries = vault.len();
    let mut engine = build_engine(vault, &cfg.redact)?;
    engine.save_if_dirty()?;

    let audit_path = resolve_path(&root, &cfg.proxy.audit_log);
    let audit = AuditLog::open(&audit_path)?;
    let state = AppState::new(
        engine,
        cfg.proxy.openai_base.clone(),
        cfg.proxy.anthropic_base.clone(),
        audit,
        cfg.proxy.timeout_secs,
    )?;

    let addr: SocketAddr = format!("{}:{}", cfg.proxy.listen, cfg.proxy.port)
        .parse()
        .with_context(|| format!("listen address {}:{}", cfg.proxy.listen, cfg.proxy.port))?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let bound = listener.local_addr().context("local address")?;
    eprintln!("symveil listening on http://{bound}");
    eprintln!("  openai      {}", cfg.proxy.openai_base);
    eprintln!("  anthropic   {}", cfg.proxy.anthropic_base);
    #[cfg(feature = "identifiers")]
    eprintln!("  masking     secrets and identifiers");
    #[cfg(not(feature = "identifiers"))]
    eprintln!("  masking     secrets");
    eprintln!("  vault       {entries} entries ({})", vault_path.display());
    eprintln!("  audit       {}", audit_path.display());
    proxy::serve(listener, state).await
}

fn cmd_text(args: TextArgs, redact: bool) -> Result<()> {
    if io::stdin().is_terminal() {
        anyhow::bail!("pipe text on stdin");
    }
    let (root, cfg) = load_context(&args.repo, args.config.as_deref())?;
    let vault = open_vault(&root, &cfg)?;
    let mut engine = build_engine(vault, &cfg.redact)?;
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    if raw.len() > 32 * 1024 * 1024 {
        anyhow::bail!("stdin exceeds 32MiB");
    }
    let json = serde_json::from_str::<serde_json::Value>(&raw).is_ok();
    if redact {
        let (bytes, hits) = if json {
            engine.redact_bytes(raw.as_bytes())?
        } else {
            let (text, hits) = engine.redact_str(&raw)?;
            (text.into_bytes(), hits)
        };
        engine.save_if_dirty()?;
        io::stdout().write_all(&bytes)?;
        eprintln!("redactions: {}", hits.len());
    } else {
        let (bytes, restored) = engine.restore_bytes(raw.as_bytes(), json);
        io::stdout().write_all(&bytes)?;
        eprintln!("restored: {restored}");
    }
    Ok(())
}
