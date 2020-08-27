//! Utilities for manipulating raw bytes within memory, and converting between
//! these and human-readable encodings.

use crate::encoding::base64::{Config, DecodeError as Base64DecodeError, FromBase64, ToBase64};
use crate::encoding::hex::{DecodeError as HexDecodeError, FromHex, ToHex};
use std::{error::Error, fmt, ops::BitXor};

// Rust doesn't provide great utilities within the standard library for
// encoding/decoding data, so it's necessary to bring in third party libraries
// to do so.
use base64;
use hex;

/// Error returned if the user tries to xor two byte sequences of different
/// lengths
#[derive(Debug, Clone)]
pub struct XorLengthError;

impl Error for XorLengthError {}
impl fmt::Display for XorLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tried to xor two sequences with different lengths")
    }
}

/// Trait for sequences of bytes that can be xor'd with other sequences of
/// bytes.
pub trait SequenceXor<T: BitXor + Copy> {
    /// Xor this sequence of bytes with `other`.
    ///
    /// Each item in `self` will be xor'd with the item at the same index in
    /// `other` to form a new vector.
    ///
    /// Returns a `Result` containing a vector containing the output of xor'ing
    /// each byte, or an [`XorLengthError`] if the two byte sequences were not
    /// of the same length.
    fn xor(&self, other: &[T]) -> Result<Vec<T::Output>, XorLengthError>;
}

impl<T> SequenceXor<T> for Vec<T>
where
    T: BitXor + Copy,
{
    fn xor(&self, other: &[T]) -> Result<Vec<T::Output>, XorLengthError> {
        if self.len() != other.len() {
            return Err(XorLengthError);
        }
        Ok(self
            .into_iter()
            .enumerate()
            .map(|(i, x)| *x ^ other[i])
            .collect())
    }
}

/// The `Bytes` type represents an arbitrarily long sequence of raw bytes in
/// memory.
///
/// This type is a wrapper around a [`Vector`](std::vec::Vec) containg 8-bit
/// unsigned integers. This is used throughout DumbTLS to represent raw bytes,
/// and to perform operations on these. While the actual differences to simply
/// using a `Vec` are minimal, using this type semantically signfies that the
/// integers stored within are a representation of memory, and may not carry any
/// meaning in their decimal representation.
///
/// This type provides a number of methods for converting between bytes and
/// human-readable encodings, such as hex and base64, and should be used when
/// encoding/decoding user input & output.
///
/// # Examples
///
/// Constructing `Bytes` from a hex string, and outputting the result as base64:
///
/// ```
/// let my_bytes = Bytes::from_hex("cafebabe");
/// println!("Base64: {}", my_bytes.to_base64()); // Outputs: "Base64: yv66vg=="
/// ```
pub type Bytes = Vec<u8>;

impl FromHex for Bytes {
    fn from_hex(src: &str) -> Result<Bytes, HexDecodeError> {
        hex::decode(src)
    }
}

impl ToHex for Bytes {
    fn to_hex(&self) -> String {
        hex::encode(self)
    }

    fn to_hex_upper(&self) -> String {
        hex::encode_upper(self)
    }
}

impl FromBase64 for Bytes {
    fn from_base64(src: &str) -> Result<Bytes, Base64DecodeError> {
        base64::decode(src)
    }

    fn from_base64_config(src: &str, config: Config) -> Result<Bytes, Base64DecodeError> {
        base64::decode_config(src, config)
    }
}

impl ToBase64 for Bytes {
    fn to_base64(&self) -> String {
        base64::encode(self)
    }

    fn to_base64_config(&self, config: Config) -> String {
        base64::encode_config(self, config)
    }
}
