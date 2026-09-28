//! [`Text`]: one decrypted value handed out in fixed-size chunks, which the
//! vault closes when it locks ([`crate::Vault::open_text`]).

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::{Error, Plaintext};

/// Bytes per [`Text::chunk`]. Every chunk has exactly this length, so no
/// buffer that carries content out is ever above 1 KiB.
pub const CHUNK: usize = 960;

/// One decrypted value. Read it with [`Text::chunk`] and close it at once;
/// [`crate::Vault::lock`] closes every one that is still open.
pub struct Text {
    plain: Mutex<Option<Plaintext>>,
}

impl Text {
    pub(crate) fn new(p: Plaintext) -> Text {
        Text {
            plain: Mutex::new(Some(p)),
        }
    }

    /// Content length in bytes; 0 once closed.
    pub fn byte_len(&self) -> u32 {
        guard(&self.plain).as_ref().map_or(0, |p| p.len() as u32)
    }

    /// Bytes `[index * CHUNK, index * CHUNK + CHUNK)`, zero-padded to
    /// exactly [`CHUNK`]. `Malformed` past the end (so an empty text has no
    /// chunk), `Locked` once closed.
    pub fn chunk(&self, index: u32) -> Result<Vec<u8>, Error> {
        let g = guard(&self.plain);
        let p = g.as_ref().ok_or(Error::Locked)?;
        let start = (index as usize)
            .checked_mul(CHUNK)
            .ok_or(Error::Malformed)?;
        if start >= p.len() {
            return Err(Error::Malformed);
        }
        let end = p.len().min(start + CHUNK);
        let mut out = vec![0u8; CHUNK];
        out[..end - start].copy_from_slice(&p[start..end]);
        Ok(out)
    }

    /// Wipes the content now. Idempotent.
    pub fn close(&self) {
        guard(&self.plain).take();
    }
}

/// The lock, recovered if poisoned: a text never fails to close.
fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
