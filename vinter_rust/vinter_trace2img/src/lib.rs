use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Result};
use itertools::Itertools;
use serde::{Serialize, Serializer};

use vinter_common::trace::{self, TraceEntry};

mod image;
mod set;
pub use image::{MemoryImage, MemoryImageMmap, MemoryImageVec};

mod pmem;
pub use pmem::{LineGranularity, X86PersistentMemory};

pub mod config;

pub struct MemoryReplayer {
    pub mem: Rc<RefCell<X86PersistentMemory>>,
}

impl MemoryReplayer {
    pub fn new(mem: X86PersistentMemory) -> MemoryReplayer {
        MemoryReplayer {
            mem: Rc::new(RefCell::new(mem)),
        }
    }

    pub fn process_trace<'a>(
        &'a mut self,
        file: impl BufRead + 'a,
    ) -> impl Iterator<Item = Result<trace::TraceEntry>> + 'a {
        let mut deferred_fence = false;
        trace::parse_trace_file_bin(file).map(move |entry| {
            if deferred_fence {
                self.mem.borrow_mut().fence();
                deferred_fence = false;
            }
            match &entry {
                Ok(TraceEntry::Write {
                    id: _,
                    address,
                    size: _,
                    content,
                    non_temporal,
                    metadata,
                }) => {
                    self.mem
                        .borrow_mut()
                        .write(*address, content, *non_temporal, metadata);
                }
                Ok(TraceEntry::Fence { .. }) => {
                    // A fence persists all flushed cachelines. For crash image
                    // generation, we still need to see these flushed lines, so
                    // defer the flush until the next iteration.
                    deferred_fence = true;
                }
                Ok(TraceEntry::Flush {
                    id: _,
                    mnemonic,
                    address,
                    ..
                }) => {
                    let mut mem = self.mem.borrow_mut();
                    match mnemonic.as_ref() {
                        "clwb" => {
                            mem.clwb(*address, None);
                        }
                        "clflush" => {
                            mem.clwb(*address, None);
                            // Note that this fence is not completely correct (in that we may lose
                            // bugs), as clflushes are only ordered among themselves (and some other
                            // things), but *not* among CLFLUSHOPT and CLWB.  However applications
                            // usually don't mix those anyway.
                            mem.fence();
                        }
                        m => {
                            bail!("unknown flush mnemonic {}", m);
                        }
                    }
                }
                _ => {}
            };
            entry
        })
    }
}

#[derive(Debug, Serialize)]
pub enum CrashPersistenceType {
    /// We always create an image at a checkpoint, even if there are no writes.
    NoWrites,
    /// Image with no pending writes persisted.
    NothingPersisted,
    /// Image with all pending writes persisted.
    FullyPersisted { dirty_lines: Vec<usize> },
    /// Image with a subset of all writes persisted.
    StrictSubsetPersisted {
        strict_subset_lines: Vec<usize>,
        partial_write_indices: Vec<usize>,
        dirty_lines: Vec<usize>,
    },
}

#[derive(Debug, Serialize)]
pub struct CrashMetadata {
    pub fence_id: usize,
    /// -1 is before the first checkpoint
    pub checkpoint_id: isize,
    pub persistence_type: CrashPersistenceType,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SemanticStateHash(blake3::Hash);
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct CrashImageHash(blake3::Hash);

macro_rules! impl_serialize_hash {
    ($t: ty) => {
        impl Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0.to_hex())
            }
        }
    };
}
impl_serialize_hash!(SemanticStateHash);
impl_serialize_hash!(CrashImageHash);

#[derive(Debug, Serialize)]
pub struct SemanticState {
    pub hash: SemanticStateHash,
    pub successful: bool,
    pub originating_images: Vec<CrashImageHash>,
}

/// Did we use a crash image for a heuristic?
#[derive(Debug, Serialize)]
pub enum HeuristicState {
    /// No, the crash image was not considered (only fully-persisted crash images are used for the heuristic).
    NotConsidered,
    /// Yes, we applied the heuristic and traced the post-recovery code.
    HeuristicApplied {
        heuristic_images: Vec<CrashImageHash>,
        modified_lines: usize,
        read_lines: usize,
    },
    /// Heuristic was disabled, we used a subset of all modified lines.
    AllConsidered { modified_lines: usize },
}

/// Describes a crash image and all CrashMetadata that have been discovered to lead to this crash image.
#[derive(Debug, Serialize)]
pub struct CrashImage {
    pub hash: CrashImageHash,
    pub heuristic: HeuristicState,
    pub originating_crashes: Vec<CrashMetadata>,
}

impl CrashImage {
    pub fn new(hash: CrashImageHash) -> CrashImage {
        CrashImage {
            hash,
            heuristic: HeuristicState::NotConsidered,
            originating_crashes: Vec::new(),
        }
    }
}

/// Tries to find a file with the given name adjacent to our executable.
fn adjacent_file(name: &OsStr) -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let dir = current_exe.parent()?;
    let file = dir.join(name);
    if file.exists() {
        Some(file)
    } else {
        None
    }
}

fn trace_command() -> Result<Command> {
    Ok(Command::new(match std::env::var_os("VINTER_TRACE_CMD") {
        Some(path) => PathBuf::from(path),
        None => {
            if let Some(path) = adjacent_file(OsStr::new("vinter_trace.py")) {
                path
            } else {
                bail!("VINTER_TRACE_CMD is not set");
            }
        }
    }))
}

/// Concatenates two OsStr.
fn concat_osstr<A: Into<OsString>, B: AsRef<OsStr> + ?Sized>(a: A, b: &B) -> OsString {
    let mut str = a.into();
    str.push(b);
    return str;
}

// TODO: Make these command-line parameters.

/// How many random subsets of all unflushed lines to consider when generating crash images.
const MAX_UNPERSISTED_SUBSETS: usize = 20;
/// log2(MAX_UNPERSISTED_SUBSETS)
const MAX_UNPERSISTED_SUBSETS_LOG2: usize = 4;
/// For each random subset, how many (in-order) partial flushes to consider in case of multiple
/// writes to the same line. Note that the maximum number of generated crash images at one fence is
/// thus `MAX_UNPERSISTED_SUBSETS * MAX_PARTIAL_FLUSHES_COUNT`.
const MAX_PARTIAL_FLUSHES_COUNT: usize = 20;
/// Use heuristic based on read lines or consider all stores?
const USE_HEURISTIC: bool = true;

pub struct HeuristicCrashImageGenerator {
    vm_config_path: PathBuf,
    vm_config: config::Config,
    test_config: config::Test,
    output_dir: PathBuf,
    log: File,
    rng: fastrand::Rng,
    /// Generated crash images, indexed by their hash.
    pub crash_images: HashMap<CrashImageHash, CrashImage>,
    /// Semantic states extracted the crash images, indexed by their hash.
    pub semantic_states: HashMap<SemanticStateHash, SemanticState>,
}

impl HeuristicCrashImageGenerator {
    pub fn new(
        vm_config_path: PathBuf,
        test_config_path: PathBuf,
        mut output_dir: PathBuf,
    ) -> Result<Self> {
        let vm_config: config::Config = {
            let f = File::open(&vm_config_path).context("could not open VM config file")?;
            serde_yaml::from_reader(f).context("could not parse VM config file")?
        };
        let test_config = {
            let f = File::open(&test_config_path).context("could not open test config file")?;
            serde_yaml::from_reader(f).context("could not parse test config file")?
        };
        // Build full output path: <output_dir>/vm_foo/test_bar/
        let vm_name = vm_config_path
            .file_stem()
            .ok_or_else(|| anyhow!("invalid VM config file name"))?;
        output_dir.push(vm_name);
        let test_name = test_config_path
            .file_stem()
            .ok_or_else(|| anyhow!("invalid test config file name"))?;
        output_dir.push(test_name);
        if output_dir.exists() {
            bail!("output directory {} already exists", output_dir.display());
        }
        std::fs::create_dir_all(&output_dir).context("could not create output directory")?;
        std::fs::copy(
            &vm_config_path,
            output_dir.join(concat_osstr(vm_name, ".yaml")),
        )
        .context("could not copy VM config file")?;
        std::fs::copy(
            &test_config_path,
            output_dir.join(concat_osstr(test_name, ".yaml")),
        )
        .context("could not copy test config file")?;
        std::fs::create_dir(output_dir.join("crash_images"))
            .context("could not create crash_images directory")?;
        std::fs::create_dir(output_dir.join("crash_image_states"))
            .context("could not create crash_image_states directory")?;
        std::fs::create_dir(output_dir.join("recovery_traces"))
            .context("could not create recovery_traces directory")?;
        std::fs::create_dir(output_dir.join("semantic_states"))
            .context("could not create semantic_states directory")?;
        let log = File::create(output_dir.join("trace2img.log"))
            .context("could not create trace2img.log")?;
        // create a base image for snapshots
        let status = Command::new("qemu-img")
            .args(["create", "-f", "qcow2"])
            .arg(output_dir.join("img.qcow2").as_os_str())
            .arg("1G")
            .stdout(log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("qemu-img failed with status {}", status);
        }

        Ok(HeuristicCrashImageGenerator {
            vm_config_path,
            vm_config,
            test_config,
            output_dir,
            log,
            rng: fastrand::Rng::with_seed(1633634632),
            crash_images: HashMap::new(),
            semantic_states: HashMap::new(),
        })
    }

    /// Start a VM and trace test execution.
    pub fn trace_pre_failure(&self) -> Result<()> {
        let cmd = format!("cat /proc/uptime; cat /proc/uptime; cat /proc/uptime; {prefix} && {suffix} && hypercall success; cat /proc/uptime",
            prefix = self.vm_config.commands.get("trace_cmd_prefix").ok_or_else(|| anyhow!("missing trace_cmd_prefix in VM configuration"))?,
            suffix = self.test_config.trace_cmd_suffix);
        let status = trace_command()?
            .arg("--qcow")
            .arg(self.output_dir.join("img.qcow2"))
            .arg("--trace")
            .arg(self.trace_path())
            .args(["--trace-what", "write,fence,flush,hypercall"])
            .arg("--run")
            .arg(cmd)
            .arg("--save-pmem")
            .arg(self.output_dir.join("final.img"))
            .arg(&self.vm_config_path)
            .stderr(self.log.try_clone()?)
            .stdout(self.log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("pre-failure tracing failed with status {}", status);
        }
        Ok(())
    }

    /// Trace recovery of a crash image, for use in the cross-failure heuristic.
    pub fn trace_recovery(&self, crash_img_hash: &CrashImageHash) -> Result<PathBuf> {
        let cmd = self
            .vm_config
            .commands
            .get("recovery_cmd")
            .ok_or_else(|| anyhow!("missing recovery_cmd in VM configuration"))?;
        let path = self.recovery_trace_path(crash_img_hash);
        let status = trace_command()?
            .arg("--qcow")
            .arg(self.output_dir.join("img.qcow2"))
            .args(["--load-snapshot", "boot"])
            .arg("--load-pmem")
            .arg(self.crash_image_path(crash_img_hash))
            .arg("--trace")
            .arg(&path)
            .args(["--trace-what", "read,hypercall"])
            .arg("--run")
            .arg(cmd)
            .arg(&self.vm_config_path)
            .stdout(self.log.try_clone()?)
            .stderr(self.log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("pre-failure tracing failed with status {}", status);
        }
        Ok(path)
    }

    /// Returns the path to the pre-failure trace file.
    fn trace_path(&self) -> PathBuf {
        self.output_dir.join("trace.bin")
    }

    /// Returns the output path to a crash image with the given hash.
    fn crash_image_path(&self, hash: &CrashImageHash) -> PathBuf {
        self.output_dir
            .join("crash_images")
            .join(format!("{}.img", hash.0.to_hex()))
    }

    /// Returns the output path to a post-failure recovery trace.
    fn recovery_trace_path(&self, hash: &CrashImageHash) -> PathBuf {
        self.output_dir
            .join("recovery_traces")
            .join(format!("{}.bin", hash.0.to_hex()))
    }

    /// Returns the output path to a semantic state for the given crash image.
    fn crash_image_state_path(&self, hash: &CrashImageHash, ext: &str) -> PathBuf {
        // TODO: enum instead of str for ext?
        self.output_dir
            .join("crash_image_states")
            .join(format!("{}.{}", hash.0.to_hex(), ext))
    }

    /// Returns the output path to a semantic state, indexed by its own hash.
    fn semantic_state_path(&self, hash: &SemanticStateHash) -> PathBuf {
        self.output_dir
            .join("semantic_states")
            .join(format!("{}.txt", hash.0.to_hex()))
    }

    fn run_state_extractor(&self, crash_img: &CrashImage) -> Result<SemanticState> {
        let cmd = format!(
            "{prefix} && {suffix} && hypercall success",
            prefix = self
                .vm_config
                .commands
                .get("dump_cmd_prefix")
                .ok_or_else(|| anyhow!("missing dump_cmd_prefix in VM configuration"))?,
            suffix = self.test_config.dump_cmd_suffix
        );
        let cmd_output_path = self.crash_image_state_path(&crash_img.hash, "state.txt");
        let trace_path = self.crash_image_state_path(&crash_img.hash, "trace.bin");
        let status = trace_command()?
            .arg("--qcow")
            .arg(self.output_dir.join("img.qcow2"))
            .args(["--load-snapshot", "boot"])
            .arg("--load-pmem")
            .arg(self.crash_image_path(&crash_img.hash))
            .arg("--trace")
            .arg(&trace_path)
            .args(["--trace-what", "hypercall"])
            .arg("--run")
            .arg(cmd)
            .arg("--cmd-output")
            .arg(&cmd_output_path)
            .arg(&self.vm_config_path)
            .stdout(self.log.try_clone()?)
            .stderr(self.log.try_clone()?)
            .status()?;
        if !status.success() {
            bail!("semantic state extraction failed with status {}", status);
        }
        let mut hasher = blake3::Hasher::new();
        std::io::copy(&mut File::open(&cmd_output_path)?, &mut hasher)
            .context("could not read semantic state output file")?;
        let mut successful = false;
        for entry in trace::parse_trace_file_bin(BufReader::new(
            File::open(&trace_path).context("could not open trace output file")?,
        )) {
            match entry? {
                TraceEntry::Hypercall { action, .. } if action == "success" => {
                    successful = true;
                }
                _ => {}
            }
        }
        Ok(SemanticState {
            hash: SemanticStateHash(hasher.finalize()),
            successful,
            // note: creating an empty Vec does not allocate
            originating_images: Vec::new(),
        })
    }

    fn insert_crash_image(
        &mut self,
        fence_id: usize,
        mem: &X86PersistentMemory,
        checkpoint_id: isize,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;
        macro_rules! image_entry {
            ($mem:expr) => {{
                let hash = CrashImageHash($mem.blake3());
                let path = self.crash_image_path(&hash);
                match self.crash_images.entry(hash) {
                    Entry::Vacant(e) => {
                        $mem.image.persist(&mut File::create(path)?)?;
                        e.insert(CrashImage::new(hash.clone()))
                    }
                    // the closure will never be called, it just makes the borrow checker happy
                    e => e.or_insert_with(|| CrashImage::new(hash.clone())),
                }
            }};
        }

        let no_writes = mem.unpersisted_content.is_empty();

        // At each relevant fence, create crash images:
        // 1. with no pending writes persisted
        image_entry!(mem).originating_crashes.push(CrashMetadata {
            fence_id,
            persistence_type: if no_writes {
                CrashPersistenceType::NoWrites
            } else {
                CrashPersistenceType::NothingPersisted
            },
            checkpoint_id,
        });

        // At a checkpoint, we create images even if there are no pending writes.
        // Skip computing the other images and running the heuristic in this case.
        if no_writes {
            return Ok(());
        }

        // 2. with all pending writes persisted
        let mut fully_persisted_mem = mem.try_clone()?;
        fully_persisted_mem.persist_unpersisted();
        let fully_persisted_img = image_entry!(&fully_persisted_mem);
        fully_persisted_img.originating_crashes.push(CrashMetadata {
            fence_id,
            persistence_type: CrashPersistenceType::FullyPersisted {
                dirty_lines: mem.unpersisted_content.keys().copied().collect(),
            },
            checkpoint_id,
        });
        let fully_persisted_img_hash = fully_persisted_img.hash;

        // 3. with subsets chosen randomly or by heuristic
        if let HeuristicState::NotConsidered = fully_persisted_img.heuristic {
            let line_granularity: usize = mem.line_granularity().into();

            let unpersisted_reads_lines: Vec<usize> = if USE_HEURISTIC {
                let hash = fully_persisted_img.hash;
                let mut success = false;
                // trace2img.py tracks these only for statistic purposes
                // let mut unpersisted_reads: HashSet<(usize, usize)> = HashSet::new();
                let mut unpersisted_reads_lines: HashSet<usize> = HashSet::new();
                let trace_path = self
                    .trace_recovery(&hash)
                    .context("recovery trace failed")?;
                let trace_file =
                    File::open(trace_path).context("could not open recovery trace file")?;
                for entry in trace::parse_trace_file_bin(BufReader::new(trace_file)) {
                    match entry? {
                        TraceEntry::Hypercall { action, .. } if action == "success" => {
                            success = true;
                        }
                        TraceEntry::Read { address, size, .. } => {
                            let min_line_number = address / line_granularity;
                            let max_line_number = (address + size - 1) / line_granularity;
                            for line_number in min_line_number..=max_line_number {
                                if let Some(line) = mem.unpersisted_content.get(&line_number) {
                                    if line.overlaps_access(address, size) {
                                        // unpersisted_reads.insert((address, size));
                                        unpersisted_reads_lines.insert(line_number);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if !success {
                    // Ignore errors here, state extraction will most likely also fail later on.
                    println!("Recovery for crash image {:?} failed", hash);
                }
                // unwrap: will never panic since we inserted the image above.
                self.crash_images
                    .get_mut(&fully_persisted_img_hash)
                    .unwrap()
                    .heuristic = HeuristicState::HeuristicApplied {
                    heuristic_images: Vec::new(),
                    modified_lines: mem.unpersisted_content.len(),
                    read_lines: unpersisted_reads_lines.len(),
                };

                unpersisted_reads_lines.drain().collect()
            } else {
                // Without heuristic, consider all modified lines.
                fully_persisted_img.heuristic = HeuristicState::AllConsidered {
                    modified_lines: mem.unpersisted_content.len(),
                };
                mem.unpersisted_content.keys().copied().collect()
            };
            // Do we have any unpersisted reads?
            if !unpersisted_reads_lines.is_empty() {
                let mut heuristic_images = Vec::new();
                let random_subsets: Vec<Vec<usize>> =
                    if unpersisted_reads_lines.len() <= MAX_UNPERSISTED_SUBSETS_LOG2 {
                        // Skip the empty set in the powerset.
                        unpersisted_reads_lines
                            .iter()
                            .copied()
                            .powerset()
                            .skip(1)
                            .collect()
                    } else {
                        set::random_subsets(&mut self.rng, &unpersisted_reads_lines)
                            .filter(|vec| !vec.is_empty())
                            .take(MAX_UNPERSISTED_SUBSETS)
                            .collect()
                    };
                for random_lines in random_subsets {
                    let partial_flushes_count = random_lines
                        .iter()
                        .map(|line_number| mem.unpersisted_content[line_number].all_writes().len())
                        .fold(0, |acc, x| acc * x);
                    let line_partial_writes: Vec<Vec<usize>> = random_lines
                        .iter()
                        .map(|line_number| {
                            let writes_count =
                                mem.unpersisted_content[line_number].all_writes().len();
                            if partial_flushes_count > MAX_PARTIAL_FLUSHES_COUNT {
                                if writes_count <= 1 {
                                    vec![writes_count]
                                } else {
                                    vec![writes_count, self.rng.usize(1..writes_count)]
                                }
                            } else {
                                (1..=writes_count).collect()
                            }
                        })
                        .collect();
                    for partial_write_indices in
                        line_partial_writes.iter().multi_cartesian_product()
                    {
                        let mut subset_persisted_mem = mem.try_clone()?;
                        for (line_number, flush_writes_limit) in random_lines
                            .iter()
                            .copied()
                            .zip(partial_write_indices.iter().copied())
                        {
                            subset_persisted_mem
                                .clwb(line_number * line_granularity, Some(*flush_writes_limit));
                            subset_persisted_mem.fence_line(line_number);
                        }
                        let entry = image_entry!(&subset_persisted_mem);
                        entry.originating_crashes.push(CrashMetadata {
                            fence_id,
                            persistence_type: CrashPersistenceType::StrictSubsetPersisted {
                                strict_subset_lines: random_lines.clone(),
                                partial_write_indices: partial_write_indices
                                    .iter()
                                    .map(|&x| *x)
                                    .collect(),
                                // Dirty lines are all lines that are not (fully) persisted in this image.
                                // First, all lines that are not in random_lines at all.
                                dirty_lines: mem
                                    .unpersisted_content
                                    .keys()
                                    .copied()
                                    .collect::<HashSet<_>>()
                                    .difference(&random_lines.iter().copied().collect())
                                    .copied()
                                    .collect::<HashSet<_>>()
                                    // Then, all lines that are partially included (i.e., not with all writes).
                                    .union(
                                        &random_lines
                                            .iter()
                                            .zip(partial_write_indices.iter().copied())
                                            .filter_map(|(line, &writes_limit)| {
                                                if mem.unpersisted_content[line].all_writes().len()
                                                    > writes_limit
                                                {
                                                    Some(*line)
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect(),
                                    )
                                    .copied()
                                    .collect(),
                            },
                            checkpoint_id,
                        });
                        heuristic_images.push(entry.hash);
                    }
                }
                if let HeuristicState::HeuristicApplied {
                    heuristic_images: imgs,
                    ..
                } = &mut self
                    .crash_images
                    .get_mut(&fully_persisted_img_hash)
                    .unwrap()
                    .heuristic
                {
                    std::mem::swap(&mut heuristic_images, imgs);
                }
            }
        }
        Ok(())
    }

    /// Replay the generated trace and generate crash images.
    pub fn replay(&mut self) -> Result<usize> {
        use std::collections::hash_map::Entry;

        let mut current_writes = false;
        let mut fences_with_writes: usize = 0;
        let mut last_hypercall_checkpoint: isize = -1;
        let mut pre_failure_success = false;
        let mut checkpoint_ids: HashMap<isize, usize> = HashMap::new();

        let checkpoint_range = self
            .test_config
            .checkpoint_range
            .map(|(start, end)| start..end);
        let within_checkpoint_range = |checkpoint_id| {
            checkpoint_range.is_none()
                || checkpoint_range.as_ref().unwrap().contains(&checkpoint_id)
        };

        // unwrap: PMEM size will always fit in u64/usize
        let image = MemoryImageMmap::new_in(
            &self.output_dir,
            self.vm_config.vm.pmem_len.try_into().unwrap(),
        )?;
        let mem = X86PersistentMemory::new(image, LineGranularity::Word)?;
        let mut replayer = MemoryReplayer::new(mem);

        // grab a reference to the memory so that we can access it while processing the trace
        let replayer_mem = replayer.mem.clone();
        let trace_file = File::open(self.trace_path()).context("could not open trace file")?;
        for entry in replayer.process_trace(BufReader::new(trace_file)) {
            match entry? {
                TraceEntry::Fence { id, .. } => {
                    if current_writes && within_checkpoint_range(last_hypercall_checkpoint) {
                        self.insert_crash_image(
                            id,
                            &replayer_mem.borrow(),
                            last_hypercall_checkpoint,
                        )?;
                        current_writes = false;
                        fences_with_writes += 1;
                    }
                }
                TraceEntry::Write { .. } => {
                    current_writes = true;
                }
                TraceEntry::Hypercall {
                    id, action, value, ..
                } => match action.as_ref() {
                    "checkpoint" => {
                        last_hypercall_checkpoint =
                            value.parse().context("invalid checkpoint value")?;
                        match checkpoint_ids.entry(last_hypercall_checkpoint) {
                            Entry::Vacant(e) => {
                                e.insert(id);
                            }
                            _ => {
                                bail!("duplicate checkpoint id {}", last_hypercall_checkpoint);
                            }
                        }
                        // Create a single crash image after the checkpoint range to allow checking for SFS.
                        if within_checkpoint_range(last_hypercall_checkpoint)
                            || self.test_config.checkpoint_range.map(|(_start, end)| end)
                                == Some(last_hypercall_checkpoint)
                        {
                            self.insert_crash_image(
                                id,
                                &replayer_mem.borrow(),
                                last_hypercall_checkpoint,
                            )?;
                        }
                    }
                    "success" => {
                        if pre_failure_success {
                            bail!("multiple success hypercalls");
                        }
                        pre_failure_success = true;
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        let index_file = File::create(self.output_dir.join("crash_images").join("index.yaml"))?;
        serde_yaml::to_writer(&index_file, &self.crash_images)
            .context("failed writing crash_images/index.yaml")?;

        Ok(fences_with_writes)
    }

    /// Extract the semantic state of each crash image.
    pub fn extract_semantic_states(&mut self) -> Result<()> {
        let mut states = HashMap::new();
        for (image_hash, image) in &self.crash_images {
            let state = self.run_state_extractor(image)?;
            states
                .entry(state.hash)
                .or_insert(state)
                .originating_images
                .push(*image_hash);
        }

        // copy unique semantic states
        for (state_hash, state) in &states {
            std::fs::copy(
                self.crash_image_state_path(&state.originating_images[0], "state.txt"),
                self.semantic_state_path(state_hash),
            )?;
        }
        let index_file = File::create(self.output_dir.join("semantic_states").join("index.yaml"))?;
        serde_yaml::to_writer(&index_file, &states)
            .context("failed writing semantic_states/index.yaml")?;

        self.semantic_states = states;
        Ok(())
    }
}
