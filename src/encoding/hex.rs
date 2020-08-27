//! Traits for encoding/decoding hex data.

// Rust doesn't provide great utilities within the standard library for
// encoding/decoding data, so it's necessary to bring in third-party libraries
// to do so.
use hex;

/// Represents an error encountered while decoding a hex string to bytes.
///
/// This type is simply re-exported from the [hex
/// library](https://crates.io/crates/hex).
pub use hex::FromHexError as DecodeError;

/// Implemented for types which can be instantiated from hex-encoded data.
pub trait FromHex {
    /// Create a new instance of the type implementing this trait from the
    /// hex-encoded data `src`.
    ///
    /// Decodes the hex-encoded string `src` into raw bytes, and returns a
    /// `Result` containing a new instance of the type if the decoding was
    /// successful, or a [`DecodeError`] otherwise.
    ///
    /// # Errors
    /// This function will return a `DecodeError` when the input `src` is not
    /// valid hex-encoded data: This may occur if the string passed to the
    /// function has non-even length (as valid hex data uses two digits to
    /// represent one byte, corresponding to the `OddLength` variant), or if
    /// there is aninvalid character in the string (i.e: Not 0-9, A-F, or a-f,
    /// corresponding to the `InvalidHexCharacter` variant).
    fn from_hex(src: &str) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

/// Implemented for types which contain raw bytes, and can output these raw
/// bytes as hex-encoded data.
pub trait ToHex {
    /// Encode the data contained within the type as lower-case hex.
    ///
    /// This method should not cause any errors.
    fn to_hex(&self) -> String;

    /// Encode the data contained within the type as upper-case hex.
    ///
    /// This method should not cause any errors.
    fn to_hex_upper(&self) -> String;
}
