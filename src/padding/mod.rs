//! Utilities for adding/removing padding from bytes.
//!
//! Many modern ciphers are categorised as "block ciphers": they encrypt inputs
//! of a specific, fixed block size, rather than encrypting any sized input.
//! This often allows for easier implementation of important cryptographic
//! principals, such as diffusion, since the entire block can be operated upon
//! at once. However, this does raise an issue for end users: We often wish to
//! encrypt content that is not an exact multiple of the block size in length.
//!
//! Padding is used to resolve this issue. We take the input, however long it
//! is, and add extra characters until its length is a multiple of the input
//! size. For a padding scheme to be effective, it must be easily removable:
//! Simply adding random bytes to the end of some input could definitely work to
//! pad it, but when the time comes to remove the padding, how can you tell
//! where the input ends and the padding begins? Padding schemes will often
//! include the length of the padding as part of the padding itself, or use
//! characters which cannot occur in a valid input, if that input is of a
//! certain type.
//!
//! Furthermore, some ciphers, such as RSA, have deeper issues relating to
//! padding. While RSA does not have a set block-size, "textbook RSA", in which
//! input is simply encrypted without alteration, is actually deeply flawed in
//! terms of security. It is necessary to alter the input in order for it to be
//! secure, which is done via a specific padding scheme.
//!
//! This module contains implementations of PKCS #7 padding, and null byte
//! padding. I plan to implement some more padding schemes in the future.
pub mod null;
pub mod pkcs7;

use crate::bytes::Bytes;

/// Trait for a padding algorithm.
pub trait PaddingScheme {
    /// Pad the given input, so that its length is a multiple of `block_size`.
    fn pad(&self, content: &mut Bytes, block_size: usize);
    /// Remove any padding from the given input.
    fn unpad(&self, padded_content: &mut Bytes);
}

/// PKCS #7 padding.
///
/// See [the `pkcs7` module](./pkcs7/index.html) for much more information on
/// this algorithm.
pub struct PKCS7 { }

impl PaddingScheme for PKCS7 {
    fn pad(&self, content: &mut Bytes, block_size: usize) {
        pkcs7::pad(content, block_size);
    }

    fn unpad(&self, padded_content: &mut Bytes) {
        pkcs7::unpad(padded_content).unwrap();
    }
}

/// Null byte padding.
///
/// See [the `null` module](./null/index.html) for more information on this
/// algorithm.
pub struct NULL { }

impl PaddingScheme for NULL {
    fn pad(&self, content: &mut Bytes, block_size: usize) {
        null::pad(content, block_size);
    }

    fn unpad(&self, padded_content: &mut Bytes) {
        null::unpad(padded_content);
    }
}
