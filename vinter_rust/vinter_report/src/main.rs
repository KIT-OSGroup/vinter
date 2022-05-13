use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use vinter_common::trace::{self, TraceEntry};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read a binary trace file and print a textual representation.
    ReadTrace {
        /// trace file to process (from vinter_trace)
        #[clap(parse(from_os_str))]
        trace: PathBuf,

        /// vmlinux file to resolve kernel symbols
        #[clap(long, parse(from_os_str))]
        vmlinux: Option<PathBuf>,

        /// how many entries to skip
        #[clap(long)]
        skip: Option<usize>,
    },
}

fn init_addr2line(vmlinux: &Path) -> Result<addr2line::ObjectContext> {
    let mut f = File::open(vmlinux).context("could not open vmlinux file")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let parsed = addr2line::object::read::File::parse(&*buf)?;
    Ok(addr2line::Context::new(&parsed)?)
}

fn print_frame(a2l: &addr2line::ObjectContext, addr: u64) {
    print!("0x{:x} ", addr);
    match a2l.find_frames(addr) {
        Ok(mut iter) => match iter.next() {
            Ok(Some(frame)) => {
                if let Some(function) = frame.function {
                    print!("{}", function.demangle().unwrap());
                } else {
                    print!("??");
                }
            }
            Ok(None) => {
                print!("??");
            }
            Err(err) => {
                print!("<frame error: {}>", err);
            }
        },
        Err(err) => {
            print!("<frame error: {}>", err);
        }
    }
    print!(" at ");
    match a2l.find_location(addr) {
        Ok(Some(loc)) => {
            println!(
                "{file}:{line}:{column}",
                file = loc.file.unwrap_or("?"),
                line = loc.line.unwrap_or(0),
                column = loc.column.unwrap_or(0)
            );
        }
        Ok(None) => {
            println!("?");
        }
        Err(err) => {
            println!("<location error: {}>", err);
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ReadTrace {
            trace,
            vmlinux,
            skip,
        } => {
            let a2l = if let Some(vmlinux) = vmlinux {
                Some(init_addr2line(&vmlinux)?)
            } else {
                None
            };
            let mut file = BufReader::new(File::open(&trace).context("could not open trace file")?);
            for entry in trace::parse_trace_file_bin(&mut file).skip(skip.unwrap_or(0)) {
                let entry = entry?;
                println!("{:?}", entry);

                if let Some(a2l) = &a2l {
                    match entry {
                        TraceEntry::Write { metadata, .. }
                        | TraceEntry::Fence { metadata, .. }
                        | TraceEntry::Flush { metadata, .. } => {
                            if metadata.in_kernel {
                                print!("\tpc: ");
                                print_frame(a2l, metadata.pc);
                                if !metadata.kernel_stacktrace.is_empty() {
                                    println!("\tstack trace:");
                                    for (i, addr) in metadata.kernel_stacktrace.iter().enumerate() {
                                        print!("\t#{}: ", i + 1);
                                        print_frame(a2l, *addr);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}
