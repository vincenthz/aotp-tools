use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// A fictional versioning CLI
#[derive(Debug, Parser)]
#[clap(name = "git")]
#[clap(about = "A fictional versioning CLI", long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    QrDump {
        // QR file to dump
        #[clap(parse(from_os_str))]
        path: PathBuf,
    },
}

pub fn args() -> Args {
    Args::parse()
}