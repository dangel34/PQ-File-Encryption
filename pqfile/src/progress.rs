use std::io::{Read, Write};

/// Wraps a `Read` and calls `callback(bytes_read, total)` after each successful read.
///
/// Used by `encrypt_stream_with_progress` and `MultiEncryptBuilder::with_progress`.
/// `total` is the expected plaintext size (pass 0 when unknown).
pub(crate) struct ProgressReader<'a, R: Read> {
    inner: R,
    bytes_read: u64,
    total: u64,
    callback: &'a dyn Fn(u64, u64),
}

impl<'a, R: Read> ProgressReader<'a, R> {
    pub(crate) fn new(inner: R, total: u64, callback: &'a dyn Fn(u64, u64)) -> Self {
        Self {
            inner,
            bytes_read: 0,
            total,
            callback,
        }
    }
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        (self.callback)(self.bytes_read, self.total);
        Ok(n)
    }
}

/// Wraps a `Write` and calls `callback(bytes_written, total)` after each successful write.
///
/// Used by `decrypt_stream_with_progress`.
/// `total` is the expected plaintext size; pass the `original_size` from
/// `inspect_stream` if known, or 0 when unknown.
pub(crate) struct ProgressWriter<'a, W: Write> {
    inner: W,
    bytes_written: u64,
    total: u64,
    callback: &'a dyn Fn(u64, u64),
}

impl<'a, W: Write> ProgressWriter<'a, W> {
    pub(crate) fn new(inner: W, total: u64, callback: &'a dyn Fn(u64, u64)) -> Self {
        Self {
            inner,
            bytes_written: 0,
            total,
            callback,
        }
    }
}

impl<W: Write> Write for ProgressWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        (self.callback)(self.bytes_written, self.total);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
