use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;

use symveil_learn::Options as LearnOptions;

use symveil::audit::AuditLog;
use symveil::build_engine;
#[cfg(feature = "identifiers")]
use symveil::category::Category;
use symveil::config::{resolve_path, Action, Config};
use symveil::proxy::{self, AppState};
use symveil::redact::{self as policy, Hit};
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
    /// Scan a local tree and record names, secrets, and symbols to redact.
    ///
    /// Offline and read-only. No model and no network connection. The result
    /// is a list the proxy can merge. It does not guarantee nothing leaks,
    /// and it does not sandbox the tree.
    Learn(LearnArgs),
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
struct LearnArgs {
    /// Local directory to scan. A URL is refused.
    path: PathBuf,
    /// Where to write learned.toml. Default: the user config directory.
    /// The path must not be inside the scanned tree.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Print a masked candidate summary and do not prompt or write.
    #[arg(long)]
    report: bool,
    /// Print full secret values. Off by default.
    #[arg(long)]
    reveal: bool,
    /// Skip files larger than this many bytes.
    #[arg(long, default_value_t = symveil_learn::DEFAULT_MAX_BYTES)]
    max_bytes: u64,
    /// Do not apply .gitignore rules. .git and build directories are still skipped.
    #[arg(long)]
    no_gitignore: bool,
    /// Follow symlinks that resolve inside the scan root. Links that leave the root are never opened.
    #[arg(long)]
    follow_symlinks: bool,
    /// Also scan build directories other than `.git`, and text inside files
    /// skipped by extension (pdf, png, zip, and the rest).
    #[arg(long)]
    include_skipped: bool,
}

#[derive(clap::Args)]
struct TextArgs {
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Command::Learn(args) => symveil_learn::run(learn_options(args)),
        other => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(run_network(other))
        }
    };
    if let Err(err) = result {
        eprintln!("symveil: {err:#}");
        std::process::exit(1);
    }
}

fn learn_options(args: LearnArgs) -> LearnOptions {
    LearnOptions {
        root: args.path,
        out: args.out,
        report: args.report,
        reveal: args.reveal,
        max_bytes: args.max_bytes,
        gitignore: !args.no_gitignore,
        follow_symlinks: args.follow_symlinks,
        include_skipped: args.include_skipped,
    }
}

async fn run_network(cmd: Command) -> Result<()> {
    match cmd {
        #[cfg(feature = "identifiers")]
        Command::Index(args) => cmd_index(args),
        Command::Proxy(args) => cmd_proxy(args).await,
        Command::Redact(args) => cmd_text(args, true),
        Command::Restore(args) => cmd_text(args, false),
        Command::Learn(_) => anyhow::bail!("learn is not a networked command"),
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
                Category::Secret | Category::Pii => {
                    let rule = entry.rule.as_deref().unwrap_or(entry.category.as_str());
                    println!(
                        "  {} {rule} len={} {}",
                        entry.category,
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
    let key_line = vault.key_location_line();
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
    if cfg.redact.pii.enabled() {
        eprintln!("  masking     secrets, identifiers, and personal data");
    } else {
        eprintln!("  masking     secrets and identifiers");
    }
    #[cfg(not(feature = "identifiers"))]
    if cfg.redact.pii.enabled() {
        eprintln!("  masking     secrets and personal data");
    } else {
        eprintln!("  masking     secrets");
    }
    eprintln!("  mode        {}", cfg.redact.mode);
    eprintln!(
        "  vault       {entries} entries ({}, encrypted at rest)",
        vault_path.display()
    );
    eprintln!("  vault key   {key_line}");
    eprintln!("  audit       {}", audit_path.display());
    let _ = io::stderr().flush();
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
        if policy::contains_block(&hits) {
            anyhow::bail!("{}", policy::block_message(&hits));
        }
        engine.save_if_dirty()?;
        io::stdout().write_all(&bytes)?;
        eprintln!("redactions: {}", policy::redact_count(&hits));
        warn_forwarded(&hits);
    } else {
        let (bytes, restored) = engine.restore_bytes(raw.as_bytes(), json);
        io::stdout().write_all(&bytes)?;
        eprintln!("restored: {restored}");
    }
    Ok(())
}

fn warn_forwarded(hits: &[Hit]) {
    for hit in hits.iter().filter(|hit| hit.action == Action::Warn) {
        eprintln!("warning: {} forwarded unchanged", policy::match_label(hit));
    }
}
