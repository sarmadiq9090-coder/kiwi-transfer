//! Platform layer. Windows is the real target; the Unix implementation exists
//! so the engine's logic can be tested on Linux CI and is documented as
//! weaker wherever it is.

use std::fs::File;
use std::io::{self, Read};
use std::ops::ControlFlow;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(not(any(windows, unix)))]
compile_error!("kiwi-store supports Windows (the real target) and Unix (for tests) only");

/// Size of the buffer used for verification reads.
pub(crate) const VERIFY_BUF_SIZE: usize = 1 << 20;

/// Alignment of that buffer. Unbuffered I/O needs the buffer address and the
/// read length to be multiples of the volume's sector size; 64 KiB covers
/// every sector size in use (512, 4096, and the rare larger ones).
pub(crate) const VERIFY_BUF_ALIGN: usize = 64 * 1024;

/// A heap buffer whose start address is a multiple of `align`.
pub(crate) struct AlignedBuf {
    backing: Vec<u8>,
    offset: usize,
    len: usize,
}

impl AlignedBuf {
    pub(crate) fn new(len: usize, align: usize) -> Self {
        assert!(align.is_power_of_two() && len % align == 0);
        let backing = vec![0u8; len + align];
        let offset = backing.as_ptr().align_offset(align);
        assert!(
            offset < align,
            "allocator returned an address that cannot be aligned"
        );
        Self {
            backing,
            offset,
            len,
        }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.backing[self.offset..self.offset + self.len]
    }
}

/// Streams a whole file opened by [`open_for_verify`] through `sink`.
///
/// Returns the number of bytes delivered and whether the sink let the read
/// run to the end of the file.
pub(crate) fn read_to_end_aligned(
    file: &mut File,
    sink: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
) -> io::Result<(u64, bool)> {
    let mut buf = AlignedBuf::new(VERIFY_BUF_SIZE, VERIFY_BUF_ALIGN);
    let slice = buf.as_mut_slice();
    let mut total = 0u64;
    loop {
        let n = match file.read(slice) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok((total, true));
        }
        total += n as u64;
        if sink(&slice[..n]).is_break() {
            return Ok((total, false));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_buffer_is_aligned() {
        for _ in 0..8 {
            let mut b = AlignedBuf::new(VERIFY_BUF_SIZE, VERIFY_BUF_ALIGN);
            let s = b.as_mut_slice();
            assert_eq!(s.len(), VERIFY_BUF_SIZE);
            assert_eq!(s.as_ptr() as usize % VERIFY_BUF_ALIGN, 0);
        }
    }
}
