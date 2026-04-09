mod agent_runtime;
mod audit;
mod cli;
mod config;
mod container;
mod discovery;
mod ebpf;
mod monitor;

use anyhow::Result;

fn main() -> Result<()> {
    cli::run()
}
