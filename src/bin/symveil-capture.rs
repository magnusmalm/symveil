//! Testing-only loopback forwarder.
//!
//! Records the request bodies a SymVeil proxy sends onward and forwards them.
//! Nothing records those bodies unless this program is run. It does not
//! sandbox the client.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "symveil-capture",
    about = "Testing only. Record request bodies on loopback and forward them. The proxy does not do this unless you run this program. This does not sandbox a client."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Listen, append each request body, and forward to the upstream.
    Forward(ForwardArgs),
    /// Compare a dotenv fixture with captured bodies.
    ///
    /// Prints `captured_requests=N` and `value N: masked` or `value N: LEAKED`.
    /// Does not print the values.
    Scan(ScanArgs),
}

#[derive(clap::Args)]
struct ForwardArgs {
    /// `127.0.0.1:PORT`. Port 0 picks a free port.
    #[arg(long)]
    listen: String,
    /// `https` origin, or `http` on a loopback host. No userinfo.
    #[arg(long)]
    upstream: String,
    /// File that receives the raw request bodies. Created mode 0600.
    #[arg(long)]
    bodies: PathBuf,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Dotenv fixture whose assignment values are searched for.
    #[arg(long)]
    fixture: PathBuf,
    /// File written by `forward`.
    #[arg(long)]
    bodies: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("symveil-capture: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Scan(args) => scan(args),
        Cmd::Forward(args) => forward(args),
    }
}

fn scan(args: ScanArgs) -> Result<()> {
    let fixture = std::fs::read_to_string(&args.fixture)
        .with_context(|| format!("read {}", args.fixture.display()))?;
    let bodies =
        std::fs::read(&args.bodies).with_context(|| format!("read {}", args.bodies.display()))?;
    let report = symveil_core::capture::report(&fixture, &bodies)?;
    print!("{report}");
    io::stdout().flush()?;
    Ok(())
}

fn forward(args: ForwardArgs) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("capture runtime")?;
    runtime.block_on(async move {
        let (listener, url) = symveil_core::capture::bind(&args.listen).await?;
        println!("listening {url}");
        io::stdout().flush()?;
        symveil_core::capture::serve(listener, &args.upstream, &args.bodies).await
    })
}
