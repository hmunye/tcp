use std::mem::MaybeUninit;

/// Stack-allocated buffer which tracks its initialized length, where the
/// maximum capacity is known at compile-time.
#[derive(Debug, Clone, Copy)]
pub struct FixedBuf<const N: usize> {
    buf: [MaybeUninit<u8>; N],
    // Number of initialized bytes.
    initialized: usize,
}

impl<const N: usize> FixedBuf<N> {
    /// Returns a slice to the initialized portion of this `FixedBuf`.
    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        // SAFETY: `0..self.initialized` contains only initialized bytes.
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr() as *const _, self.initialized) }
    }

    /// Returns a mutable slice to the initialized portion of this `FixedBuf`.
    #[inline]
    #[must_use]
    pub const fn as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: `0..self.initialized` contains only initialized bytes.
        unsafe { std::slice::from_raw_parts_mut(self.buf.as_mut_ptr() as *mut _, self.initialized) }
    }

    /// Returns the number of initialized bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.initialized
    }

    /// Returns `true` if no bytes have been initialized yet.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.initialized == 0
    }

    /// Returns the capacity of this `FixedBuf`.
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of bytes that have not yet been initialized.
    #[inline]
    pub const fn remaining(&self) -> usize {
        self.capacity() - self.initialized
    }

    /// Creates a new, uninitialized, `FixedBuf`.
    #[inline]
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            buf: [const { MaybeUninit::<u8>::uninit() }; N],
            initialized: 0,
        }
    }

    /// Appends data directly to the uninitialized portion of this `FixedBuf`,
    /// advancing the _initialized_ position.
    ///
    /// # Panics
    ///
    /// Panics if `self.remaining() < buf.len()`.
    #[inline]
    pub(crate) fn append(&mut self, buf: &[u8]) {
        assert!(
            self.remaining() >= buf.len(),
            "buf.len() must fit in remaining(); buf.len() = {}, remaining() = {}",
            buf.len(),
            self.remaining()
        );

        let end = self.len() + buf.len();

        // SAFETY: `self.initialized..end` points to uninitialized bytes within
        // bounds, as asserted above.
        unsafe {
            self.buf[self.initialized..end]
                .as_mut_ptr()
                .cast::<u8>()
                .copy_from_nonoverlapping(buf.as_ptr(), buf.len());
        }

        self.initialized = end;
    }
}
