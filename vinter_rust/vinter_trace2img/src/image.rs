use std::fs::File;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::Once;

use anyhow::{Context, Result};
use memmap2::{MmapMut, MmapOptions};
use tempfile::NamedTempFile;

pub trait MemoryImage: Deref<Target = [u8]> + DerefMut + std::marker::Sized {
    /// Create a new image with the given size.
    fn new(len: usize) -> Result<Self>;
    /// Try to clone the image.
    fn try_clone(&self) -> Result<Self>;
    /// Persist the image to the given file.
    fn persist(&self, file: &mut File) -> Result<()>;
}

pub type MemoryImageVec = Vec<u8>;

impl MemoryImage for MemoryImageVec {
    fn new(len: usize) -> Result<Self> {
        Ok(vec![0; len])
    }

    fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    fn persist(&self, file: &mut File) -> Result<()> {
        file.write_all(self)?;
        Ok(())
    }
}

pub struct MemoryImageMmap {
    tmpfile: NamedTempFile,
    mapping: MmapMut,
}

impl MemoryImageMmap {
    /// Create a new image in the given directory. The directory should be in a file system that
    /// supports reflinks. Later calls to `persist()` should be in the same file system.
    pub fn new_in<P: AsRef<Path>>(dir: P, len: usize) -> Result<Self> {
        let mut tmpfile =
            NamedTempFile::new_in(dir).context("creating temporary file for PMEM image failed")?;
        // unwrap: usize should always fit into u64
        tmpfile.as_file_mut().set_len(len.try_into().unwrap())?;
        // safety: we create a shared mapping to a temporay file, so we will always hold the only
        // reference.
        let mapping = unsafe { MmapOptions::new().populate().map_mut(&tmpfile)? };

        Ok(MemoryImageMmap { tmpfile, mapping })
    }
}

impl MemoryImage for MemoryImageMmap {
    fn new(len: usize) -> Result<Self> {
        MemoryImageMmap::new_in(std::env::current_dir()?, len)
    }

    fn try_clone(&self) -> Result<Self> {
        // unwrap: tmpfile will always have a parent directory.
        let mut tmpfile = NamedTempFile::new_in(self.tmpfile.path().parent().unwrap())
            .context("creating temporary file for PMEM image failed")?;
        reflink_or_copy(self.tmpfile.as_file(), tmpfile.as_file_mut())?;
        // safety: same as in new_in()
        let mapping = unsafe { MmapOptions::new().populate().map_mut(&tmpfile)? };

        Ok(MemoryImageMmap { tmpfile, mapping })
    }

    /// Persist a snapshot of the memory image to a file.
    fn persist(&self, file: &mut File) -> Result<()> {
        reflink_or_copy(self.tmpfile.as_file(), file)
    }
}

impl Deref for MemoryImageMmap {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.mapping.deref()
    }
}

impl DerefMut for MemoryImageMmap {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.mapping.deref_mut()
    }
}

static REFLINK_WARNING: Once = Once::new();

/// Try to reflink source to target, fall back to a normal copy if not supported.
fn reflink_or_copy(source: &File, target: &mut File) -> Result<()> {
    use linux_raw_sys::ioctl;
    use std::io::Seek;
    use std::os::unix::io::AsRawFd;

    let ret = unsafe {
        // see ioctl_ficlonerange(2)
        libc::ioctl(
            target.as_raw_fd(),
            ioctl::FICLONE.into(),
            source.as_raw_fd(),
        )
    };
    if ret == -1 {
        // reflink failed - fall back to normal copy
        // TODO: fall back to copy_file_range
        REFLINK_WARNING.call_once(|| {
            eprintln!(
                "WARNING: reflink failed, errno = {} (run on XFS or btrfs for more efficiency)",
                std::io::Error::last_os_error()
            );
        });
        // Hack to avoid mutable source. Note that the clone shares the file position.
        let mut source_clone = source.try_clone()?;
        let tell = source_clone.seek(std::io::SeekFrom::Current(0))?;
        source_clone.seek(std::io::SeekFrom::Start(0))?;
        std::io::copy(&mut source_clone, target)?;
        source_clone.seek(std::io::SeekFrom::Start(tell))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    fn test_memory_image<T>() -> Result<()>
    where
        T: MemoryImage,
    {
        let len = 1 << 23;
        let mut img = T::new(len)?;
        img[0] = 42;
        let clone = img.try_clone()?;
        assert_eq!(img[0], 42);
        assert_eq!(clone[0], 42);
        Ok(())
    }

    #[test]
    fn test_memory_image_vec() -> Result<()> {
        test_memory_image::<MemoryImageVec>()
    }

    #[test]
    fn test_memory_image_mmap() -> Result<()> {
        test_memory_image::<MemoryImageMmap>()
    }
}
