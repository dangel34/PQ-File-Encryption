//! Small `Read` helpers shared by [`crate::fec`] and [`crate::audit`].

use std::io::{self, Read};

/// Like [`Read::read_exact`] but returns `Ok(n)` with `n < buf.len()` on EOF
/// instead of erroring, so callers can distinguish a clean end (no more
/// blocks/entries) from a genuinely truncated one.
pub(crate) fn fill_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}
