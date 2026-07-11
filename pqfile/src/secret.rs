//! Heap-backed secret storage locked into resident memory.
//!
//! `Zeroizing` guarantees the final copy of a secret is wiped on drop, but it
//! cannot stop the OS from swapping the page to disk or including it in a
//! crash dump while the secret is alive, and every by-value move of a
//! stack-held secret leaves an unzeroized copy behind in the old stack slot.
//! [`LockedSecret`] addresses all three: the bytes live at one stable heap
//! address for their whole lifetime, the page is `mlock`ed (`VirtualLock` on
//! Windows, plus `MADV_DONTDUMP` on Linux) while the secret is alive, and the
//! buffer is zeroized before the lock is released on drop.
//!
//! Locking is strictly best-effort. Unprivileged `RLIMIT_MEMLOCK` quotas and
//! the Windows working-set quota are small by default, so a failed lock
//! degrades to plain zeroize-on-drop semantics rather than erroring; on
//! wasm32 there is no page locking at all and the fallback is unconditional.
//!
//! Only small, long-lived key material belongs here: session keys, KEM shared
//! secrets, KDF output. Plaintext and chunk buffers must not be locked - they
//! are large enough to exhaust the lock quota immediately and are not
//! long-lived key material.

use core::fmt;
use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// A fixed-size secret held in `mlock`ed heap memory (best-effort) and
/// zeroized on drop. Mirrors the `Deref`/`AsRef` surface of
/// `Zeroizing<[u8; N]>` so call sites are interchangeable.
pub(crate) struct LockedSecret<const N: usize> {
    buf: Box<[u8; N]>,
    locked: bool,
}

impl<const N: usize> LockedSecret<N> {
    /// Allocates zeroed locked storage. The buffer is all-zero before the
    /// lock is attempted, so no secret ever exists in unlocked memory here.
    pub(crate) fn zeroed() -> Self {
        let mut buf = Box::new([0u8; N]);
        let locked = lock(buf.as_mut_ptr(), N);
        Self { buf, locked }
    }

    /// Whether the page lock actually took effect. Diagnostic only: a `false`
    /// still gives full zeroize-on-drop semantics.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<const N: usize> Deref for LockedSecret<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.buf
    }
}

impl<const N: usize> DerefMut for LockedSecret<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.buf
    }
}

impl<const N: usize> AsRef<[u8]> for LockedSecret<N> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..]
    }
}

impl<const N: usize> AsMut<[u8]> for LockedSecret<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..]
    }
}

impl<const N: usize> fmt::Debug for LockedSecret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LockedSecret<{N}>([REDACTED], locked={})", self.locked)
    }
}

impl<const N: usize> Drop for LockedSecret<N> {
    fn drop(&mut self) {
        // memsec::munlock also zeroizes, but the explicit wipe covers the
        // fallback path where the lock never took effect.
        self.buf.zeroize();
        if self.locked {
            unlock(self.buf.as_mut_ptr(), N);
        }
    }
}

// The raw-pointer mlock/munlock calls are the only sanctioned unsafe in this
// module (crate root carries #![deny(unsafe_code)]), mirroring the mmap
// exception in encrypt.rs. SAFETY: the pointer always comes from the live
// `Box<[u8; N]>` owned by the same `LockedSecret`, so it is valid for exactly
// `N` bytes for the whole span between lock and unlock.
#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_code)]
fn lock(ptr: *mut u8, len: usize) -> bool {
    unsafe { memsec::mlock(ptr, len) }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_code)]
fn unlock(ptr: *mut u8, len: usize) -> bool {
    unsafe { memsec::munlock(ptr, len) }
}

#[cfg(target_arch = "wasm32")]
fn lock(_ptr: *mut u8, _len: usize) -> bool {
    false
}

#[cfg(target_arch = "wasm32")]
fn unlock(_ptr: *mut u8, _len: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroed_starts_all_zero() {
        let s = LockedSecret::<32>::zeroed();
        assert_eq!(*s, [0u8; 32]);
    }

    #[test]
    fn deref_roundtrip() {
        let mut s = LockedSecret::<32>::zeroed();
        s.copy_from_slice(&[0xAB; 32]);
        assert_eq!(s.as_ref(), &[0xAB; 32][..]);
        assert_eq!(&s[..4], &[0xAB; 4][..]);
    }

    #[test]
    fn debug_redacts_contents() {
        let mut s = LockedSecret::<32>::zeroed();
        s.copy_from_slice(&[0x42; 32]);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("42"), "secret bytes leaked into Debug: {dbg}");
    }

    #[test]
    fn lock_status_is_reported() {
        // Can't assert `true`: CI containers and quota-limited hosts may
        // legitimately refuse the lock. Just exercise the accessor on both
        // paths and make sure drop doesn't blow up either way.
        let s = LockedSecret::<32>::zeroed();
        let _ = s.is_locked();
    }
}
