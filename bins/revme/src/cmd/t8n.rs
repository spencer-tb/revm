//! `t8n` subcommand — state transition tool.
//!
//! Implements the geth-compatible t8n CLI contract used by
//! execution-spec-tests and other test frameworks to fill fixtures.
//!
//! Inputs (alloc / env / txs) and outputs (result / alloc / body) may be
//! routed via stdin/stdout (sentinel value `stdin` or `stdout`) or files.

pub mod execute;
pub mod fork;
pub mod input;
pub mod output;

use clap::Parser;
use std::path::PathBuf;

/// `t8n` subcommand: state-transition tool.
///
/// Accepts a pre-state (alloc), a block environment (env), and a list of
/// transactions (txs), executes the block with revm, and emits the
/// post-state (alloc), execution result (result), and RLP-encoded
/// transaction body (body).
#[derive(Parser, Debug)]
pub struct Cmd {
    /// Path to alloc JSON, or `stdin` to read from standard input.
    #[arg(long = "input.alloc", default_value = "alloc.json")]
    pub input_alloc: String,

    /// Path to env JSON, or `stdin` to read from standard input.
    #[arg(long = "input.env", default_value = "env.json")]
    pub input_env: String,

    /// Path to txs JSON, or `stdin` to read from standard input.
    #[arg(long = "input.txs", default_value = "txs.json")]
    pub input_txs: String,

    /// Optional blob parameters file (fork-dependent).
    #[arg(long = "input.blobParams")]
    pub input_blob_params: Option<PathBuf>,

    /// Path to result JSON output, or `stdout` to write to standard output.
    #[arg(long = "output.result", default_value = "result.json")]
    pub output_result: String,

    /// Path to post-state alloc JSON output, or `stdout` to write to
    /// standard output.
    #[arg(long = "output.alloc", default_value = "alloc.json")]
    pub output_alloc: String,

    /// Path to RLP-encoded transaction body output, or `stdout`.
    #[arg(long = "output.body", default_value = "txs.rlp")]
    pub output_body: String,

    /// Base directory under which to write output files. Defaults to the
    /// current working directory.
    #[arg(long = "output.basedir", default_value = ".")]
    pub output_basedir: PathBuf,

    /// Fork name (e.g. `Cancun`, `Prague`, `Osaka`, `PragueToOsakaAtTime15k`).
    #[arg(long = "state.fork", required = true)]
    pub state_fork: String,

    /// Chain ID.
    #[arg(long = "state.chainid", default_value_t = 1)]
    pub state_chainid: u64,

    /// Block reward in wei. Use `-1` for the genesis block (no reward).
    #[arg(long = "state.reward", default_value_t = 0, allow_hyphen_values = true)]
    pub state_reward: i64,

    /// Enable EVM trace output (EIP-3155 style). Not yet implemented.
    #[arg(long)]
    pub trace: bool,
}

impl Cmd {
    /// Runs the `t8n` command.
    ///
    /// Currently parses inputs and exits with a not-yet-implemented error
    /// after summarising what was received. Execution and output wiring
    /// land in subsequent commits.
    pub fn run(&self) -> Result<(), super::Error> {
        let blob_params_source = self.input_blob_params.as_deref().and_then(
            |p| p.to_str(),
        );
        let parsed = input::load(
            &self.input_alloc,
            &self.input_env,
            &self.input_txs,
            blob_params_source,
            &self.output_basedir,
        )
        .map_err(|e| {
            super::Error::Custom(Box::leak(
                format!("t8n input parse error: {e}").into_boxed_str(),
            ))
        })?;

        let withdrawals = parsed.env.withdrawals.clone();
        let exec_output = execute::execute(
            parsed,
            &self.state_fork,
            self.state_chainid,
        )
        .map_err(|e| {
            super::Error::Custom(Box::leak(
                format!("t8n execution error: {e}").into_boxed_str(),
            ))
        })?;

        // Diagnostic: dump rejected-tx details to /tmp so we can inspect
        // what error strings revme is actually emitting. Cheap and only
        // writes when there's something to look at. Drop this once
        // exception mapping is fully tuned.
        if !exec_output.rejected.is_empty() {
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/revme-rejects.log")
            {
                use std::io::Write;
                for r in &exec_output.rejected {
                    let _ = writeln!(
                        f,
                        "fork={} idx={} err={}",
                        self.state_fork, r.index, r.error
                    );
                }
            }
        }

        output::emit(
            &exec_output,
            &self.output_result,
            &self.output_alloc,
            &self.output_body,
            &self.output_basedir,
            &withdrawals,
        )
        .map_err(|e| {
            super::Error::Custom(Box::leak(
                format!("t8n output error: {e}").into_boxed_str(),
            ))
        })?;

        Ok(())
    }
}
