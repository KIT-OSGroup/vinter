use serde::Deserialize;
use std::collections::HashMap;

/// Format of the VM definition.
#[derive(Debug, PartialEq, Deserialize)]
pub struct VM {
    /// Start of PMEM area in physical memory.
    pub pmem_start: u64,
    /// Length of PMEM area in physical memory.
    pub pmem_len: u64,
    /// qemu -m argument
    pub mem: String,
    /// shell prompt for panda automation
    pub prompt: String,
    /// additional free-form qemu arguments
    pub qemu_args: Vec<String>,
    /// path to Linux kernel System.map file
    pub system_map: String,
}

/// Format of the VM configuration file.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    pub commands: HashMap<String, String>,
    pub vm: VM,
}

/// Format of a test configuration file.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Test {
    pub trace_cmd_suffix: String,
    pub checkpoint_range: Option<(isize, isize)>,
    pub dump_cmd_suffix: String,
}
