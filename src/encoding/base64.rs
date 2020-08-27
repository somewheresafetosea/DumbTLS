//! Traits for encoding/decoding base64 data.

// Rust doesn't provide great utilities within the standard library for
// encoding/decoding data, so it's necessary to bring in third-party libraries
// to do so.
use base64;

/// Represents an error encountered while decoding a base64 string to bytes.
///
/// This type is simplyt re-exported from the [base64
/// library](https://crates.io/crates/base64).
pub use base64::DecodeError;
pub use base64::{CharacterSet, Config};

/// This module contains a number of common mappings used for base64-encoded
/// data.
///
/// Different implementations of base64-encoding use different sets of 64
/// characters to encode the data. You may wish to decode from a source that
/// uses one of these different encodings, rather than the standard mapping, or
/// encode for use in such an encoding. Each member of this module is a
/// [`Config`] instance, and can be passed to `FromBase64::from_base64_config`
/// or `ToBase64::to_base64_config` to customise the mapping used.
///
/// These mappings are simply re-exported from the [base64
/// library](https://crates.io/crates/base64).
pub mod mappings {
    pub use base64::{
        BCRYPT, BINHEX, CRYPT, IMAP_MUTF7, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
    };
}

/// Implemented for types which can be instantiated from base64-encoded data.
pub trait FromBase64 {
    /// Create a new instance of the type implementing this trait from the
    /// standard base64-encoded data `src`.
    ///
    /// Decodes the base64-encoded string `src` into raw bytes, and returns a
    /// `Result` containing a new instance of the type if the decoding was
    /// successful, or a [`DecodeError`] otherwise.
    ///
    /// # Errors
    /// This function will return a `DecodeError` when the input `src` is not
    /// valid base64-encoded data: This may occur if the string passes to the
    /// function has invalid length (corresponding to the `InvalidLength`
    /// variant), includes an invalid byte (`InvalidByte`), or if the last
    /// symbol is not a correct padding symbol (`InvalidLastSymbol`).
    fn from_base64(src: &str) -> Result<Self, DecodeError>
    where
        Self: Sized;

    /// Create a new instance of the type implementing this trait from the
    /// base64-encoded data `src`, using a given configuration.
    ///
    /// Decodes the base64-encoded string `src` into raw bytes, and returns a
    /// `Result` containing a new instance of the type if the decoding was
    /// successful, or a [`DecodeError`] otherwise. A given configuration is
    /// used as the mapping to convert base64 into bytes: tthe [`mappings`]
    /// module contains a number of common mappings.
    ///
    /// # Errors
    /// This function will return a `DecodeError` when the input `src` is
    /// not valid base64-encoded data: This may occur if the string passes to
    /// the function has invalid length (corresponding to the `InvalidLength`
    /// variant), includes an invalid byte (`InvalidByte`), or if the last
    /// symbol is not a correct padding symbol (`InvalidLastSymbol`).
    fn from_base64_config(src: &str, config: Config) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

/// Implemented for types which contain raw bytes, and can output these raw
/// bytes as base64-encoded data.
pub trait ToBase64 {
    /// Encode the data contained within the type as standard base64.
    ///
    /// This method should not cause any errors.
    fn to_base64(&self) -> String;

    /// Encode the data contained within the type as base64, using the given
    /// configuration.
    ///
    /// A number of common configurations for base64-encoding is available
    /// within the [`mappings`] module.
    ///
    /// This method should not cause any errors.
    fn to_base64_config(&self, config: Config) -> String;
}
