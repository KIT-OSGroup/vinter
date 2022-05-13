use serde::Serialize;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::fs::File;
use std::io::Read;
use walkdir::WalkDir;

#[derive(Serialize)]
struct FileAttrs {
    typeflag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u64,
    st_uid: u32,
    st_gid: u32,
    st_size: u64,
    st_blocks: u64,
    st_atim_sec: i64,
    st_atim_nsec: i64,
    st_mtim_sec: i64,
    st_mtim_nsec: i64,
    st_ctim_sec: i64,
    st_ctim_nsec: i64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (path, dump_contents) = match args.len() {
        2 => (&args[1], false),
        3 if args[1] == "--contents" => (&args[2], true),
        _ => {
            println!("usage: {} [--contents] <path>", args[0]);
            std::process::exit(1);
        }
    };
    let mut result = BTreeMap::new();
    for entry in WalkDir::new(path) {
        let entry = entry.expect("could not read dir entry");
        let metadata = entry.metadata().expect("could not retrieve file metadata");
        result.insert(
            entry.path().to_string_lossy().into_owned(),
            FileAttrs {
                typeflag: match entry.file_type() {
                    t if t.is_file() => "F",
                    t if t.is_dir() => "D",
                    t if t.is_symlink() => "SL",
                    _ => panic!("unexpected file type at {}", entry.path().display())
                }.to_string(),
                content: if dump_contents && entry.file_type().is_file() {
                    let mut file = File::open(entry.path()).expect("could not open file");
                    let mut contents = String::new();
                    file.read_to_string(&mut contents).expect("could not read file contents");
                    Some(contents)
                } else {
                    None
                },
                target: if dump_contents && entry.file_type().is_symlink() {
                    Some(std::fs::read_link(entry.path()).expect("could not read symlink").to_string_lossy().into_owned())
                } else {
                    None}
                    ,
                st_ino: metadata.ino(),
                st_mode: metadata.mode(),
                st_nlink: metadata.nlink(),
                st_uid: metadata.uid(),
                st_gid: metadata.gid(),
                st_size: metadata.size(),
                st_blocks: metadata.blocks(),
                st_atim_sec: metadata.atime(),
                st_atim_nsec: metadata.atime_nsec(),
                st_mtim_sec: metadata.mtime(),
                st_mtim_nsec: metadata.mtime_nsec(),
                st_ctim_sec: metadata.ctime(),
                st_ctim_nsec: metadata.ctime_nsec(),
            },
        );
    }
    serde_json::to_writer_pretty(std::io::stdout(), &result).expect("could not serialize JSON");
}
