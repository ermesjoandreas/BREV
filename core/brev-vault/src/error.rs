//! The vault's errors.

/// Errors from the vault. None of them carries content.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The store is locked; unlock with the DEK first.
    #[error("locked")]
    Locked,
    /// `unlock` was given a DEK that is all zeros.
    #[error("wrong key")]
    WrongKey,
    /// Authenticated decryption failed (a tampered or moved column value,
    /// or another key), or a correctly tagged column value is not padded.
    #[error("decryption failed")]
    Crypto,
    /// No row with that id.
    #[error("not found")]
    NotFound,
    /// Input has the wrong shape: a relative store path, a value too large
    /// to pad, a chunk index past the end of a text.
    #[error("malformed")]
    Malformed,
    /// The file is not a store of this configuration and schema version,
    /// or its schema has been altered (for example a planted trigger).
    #[error("not a store of this kind")]
    Corrupt,
    /// The OS random number generator failed.
    #[error("randomness unavailable")]
    Rng,
    /// Creating the store file failed (including: it already exists).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// SQLite error. Only ids, metadata and ciphertext ever reach SQLite, so
    /// its messages cannot contain content.
    #[error("storage: {0}")]
    Storage(rusqlite::Error),
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
            e => Error::Storage(e),
        }
    }
}
