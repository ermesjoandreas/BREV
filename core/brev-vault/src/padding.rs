//! Length-hiding padding (CLAUDE.md §5 Phase 3; docs/PHASE3_DESIGN.md §2.2).
//! Every sealed store column is padded with it, and brev-proto re-exports it
//! for the envelope payload, so both have one implementation.
//!
//! The functions work on buffers the caller owns and wipes; they keep no
//! copy.

/// Largest padded length: 1 MiB (CLAUDE.md §5 Phase 3).
pub const MAX_PADDED: usize = 1 << 20;
const LEN_PREFIX: usize = 4;
/// The fixed buckets: 256 B, 1 KiB, 4 KiB, 16 KiB. Above the last one, a
/// padded length is a multiple of 16 KiB.
pub const BUCKETS: [usize; 4] = [256, 1024, 4096, 16 * 1024];
const STEP: usize = 16 * 1024;

/// Padding errors. Content-free.
#[derive(Debug, PartialEq, Eq)]
pub enum PadError {
    /// The content is above the maximum, or `out` has the wrong length.
    Size,
    /// Not a buffer that [`pad_into`] could have written.
    Malformed,
}

/// Padded length for `n` content bytes: `4 + n` rounded up to 256 B, 1 KiB,
/// 4 KiB or 16 KiB, and above that to a multiple of 16 KiB. `None` above
/// [`MAX_PADDED`].
pub fn padded_len(n: usize) -> Option<usize> {
    let need = n.checked_add(LEN_PREFIX)?;
    let len = match BUCKETS.iter().find(|&&b| need <= b) {
        Some(&b) => b,
        None => need.div_ceil(STEP).checked_mul(STEP)?,
    };
    (len <= MAX_PADDED).then_some(len)
}

/// True exactly for the lengths [`pad_into`] writes: 256, 1024, 4096, and
/// every multiple of 16 384 up to [`MAX_PADDED`]. The relay's check on an
/// envelope's ciphertext.
pub fn is_padded_len(n: usize) -> bool {
    n >= LEN_PREFIX && padded_len(n - LEN_PREFIX) == Some(n)
}

/// Writes `length (u32 BE) || content || zeros` into `out`, which must be
/// exactly `padded_len(content.len())` bytes. The caller owns `out` and
/// wipes it.
pub fn pad_into(content: &[u8], out: &mut [u8]) -> Result<(), PadError> {
    if padded_len(content.len()) != Some(out.len()) {
        return Err(PadError::Size);
    }
    let n = u32::try_from(content.len()).map_err(|_| PadError::Size)?;
    out[..LEN_PREFIX].copy_from_slice(&n.to_be_bytes());
    out[LEN_PREFIX..LEN_PREFIX + content.len()].copy_from_slice(content);
    out[LEN_PREFIX + content.len()..].fill(0);
    Ok(())
}

/// The content inside a buffer written by [`pad_into`], borrowed from it.
/// Refuses anything `pad_into` could not have written: a length that does
/// not match the buffer's bucket, or a non-zero byte in the padding.
pub fn unpad(padded: &[u8]) -> Result<&[u8], PadError> {
    let (len, rest) = padded
        .split_at_checked(LEN_PREFIX)
        .ok_or(PadError::Malformed)?;
    let len: [u8; LEN_PREFIX] = len.try_into().map_err(|_| PadError::Malformed)?;
    let n = usize::try_from(u32::from_be_bytes(len)).map_err(|_| PadError::Malformed)?;
    if padded_len(n) != Some(padded.len()) {
        return Err(PadError::Malformed);
    }
    let (content, zeros) = rest.split_at_checked(n).ok_or(PadError::Malformed)?;
    if zeros.iter().any(|&b| b != 0) {
        return Err(PadError::Malformed);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `is_padded_len` is true exactly on 256, 1 KiB, 4 KiB and the
    /// multiples of 16 KiB up to 1 MiB, checked for every length up to
    /// 1 MiB + 32 KiB.
    #[test]
    fn padded_lengths_only() {
        let mut expected: Vec<usize> = vec![256, 1024, 4096];
        expected.extend((1..=64).map(|k| k * 16384));
        assert_eq!(expected.last(), Some(&MAX_PADDED));
        let found: Vec<usize> = (0..=MAX_PADDED + 2 * STEP)
            .filter(|&n| is_padded_len(n))
            .collect();
        assert_eq!(found, expected);
        assert!(!is_padded_len(usize::MAX));
    }

    /// Exact bucket and bucket + 1 at every step, the maximum and
    /// maximum + 1; each size that fits round-trips.
    #[test]
    fn padding_boundaries() {
        let cases = [
            (0, Some(256)),
            (252, Some(256)),
            (253, Some(1024)),
            (1020, Some(1024)),
            (1021, Some(4096)),
            (4092, Some(4096)),
            (4093, Some(16384)),
            (16380, Some(16384)),
            (16381, Some(32768)),
            (65536, Some(81920)),
            (MAX_PADDED - 4, Some(MAX_PADDED)),
            (MAX_PADDED - 3, None),
            (usize::MAX, None),
        ];
        for (n, want) in cases {
            assert_eq!(padded_len(n), want, "{n}");
            let Some(len) = want else { continue };
            let content = vec![7u8; n];
            let mut out = vec![0xFFu8; len];
            pad_into(&content, &mut out).unwrap();
            assert_eq!(&out[..4], &u32::try_from(n).unwrap().to_be_bytes());
            assert!(out[4 + n..].iter().all(|&b| b == 0), "{n}");
            assert_eq!(unpad(&out).unwrap(), &content[..], "{n}");
        }
        let over = vec![0u8; MAX_PADDED - 3];
        assert_eq!(
            pad_into(&over, &mut vec![0u8; MAX_PADDED]),
            Err(PadError::Size)
        );
    }

    /// `unpad` accepts only what `pad_into` writes, and `pad_into` only an
    /// output of the exact padded length.
    #[test]
    fn padding_is_strict() {
        let mut out = [0u8; 256];
        pad_into(b"abc", &mut out).unwrap();
        assert_eq!(unpad(&out), Ok(&b"abc"[..]));
        let mut bad = out;
        bad[255] = 1; // a non-zero padding byte
        assert_eq!(unpad(&bad), Err(PadError::Malformed));
        let mut bad = out;
        bad[..4].copy_from_slice(&253u32.to_be_bytes()); // a length of another bucket
        assert_eq!(unpad(&bad), Err(PadError::Malformed));
        assert_eq!(unpad(&out[..255]), Err(PadError::Malformed));
        assert_eq!(unpad(&out[..3]), Err(PadError::Malformed));
        assert_eq!(unpad(&[0, 0, 1, 0]), Err(PadError::Malformed));
        assert_eq!(pad_into(b"x", &mut [0u8; 255]), Err(PadError::Size));
        assert_eq!(pad_into(b"x", &mut [0u8; 1024]), Err(PadError::Size));
    }
}
