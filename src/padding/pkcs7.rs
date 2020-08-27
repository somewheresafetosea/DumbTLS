//! Functions for adding/removing padding according to the PKCS #7 standard
//!
//! The Public Key Cryptography Standards (PKCS) are a set of standards,
//! originally outlined by RSA Security, used to define how different systems
//! should implement cryptographic protocols, so that interoperability is
//! possible. PKCS #7, defined in
//! [RFC 2315](https://tools.ietf.org/html/rfc2315), outlines syntax for
//! transmitting encrypted data. One detail included in this document is a
//! padding scheme for use with block ciphers, of any block-size < 32 bytes.
//! This padding scheme, often referred to simply as "PKCS #7 padding" has
//! become commonplace when using block ciphers, in part due to its simplicity.
//!
//! The algorithm for padding data is as follows: Suppose that a block cipher
//! has block-size $k \in \mathbb{N}$ bytes. To perform PKCS #7 padding on an
//! input of length $l \in \mathbb{N}$ bytes , add $k - (l\mod k)$ binary octets
//! to the end of the input, with each octet having value $k - (l\mod k)$. It
//! should be noted that, since $nk\mod k = 0 \enspace \forall \enspace n \in
//! \mathbb{N}$, an extra block, filled with octets of value $k$, is added to
//! the input. This behaviour (an extra block being added) does not happen for
//! any other input sizes.
//!
//! To give an example of this padding in use, consider some block cipher with
//! block size 8 bytes ($= k$). We wish to encrypt the (hex-encoded) data
//! `0xabcdef0011`. The length of this data is 5 bytes ($= l$), so $l\mod k =
//! 5,$ and $k - (l\mod k) = 3$. The hex-encoding of 3 is `0x03`, so we need to
//! add $k - (l\mod k) = 3$ octets of data, each with the value `0x03`.
//! Therefore, the input to be sent to the block cipher for encryption
//! is: `0xabcdef0011030303`.
//!
//! To remove the padding from data, so that it may be used, we simply need to
//! consider the value of the last octet, then remove that many bits from the
//! end of the data.
//!
//! PKCS #7 padding may also be referred to as Cryptographic Message Syntax
//! (CMS) padding, or PKCS #5 padding.
use crate::bytes::Bytes;
use std::fmt;
use std::iter;

/// Represents an error encountered when trying to remove padding.
///
/// This should only occur when [`unpad`] is used to try to remove padding from
/// something which has not been padded via PKCS #7.
#[derive(Clone, Debug)]
pub struct InvalidPadding {}

impl fmt::Display for InvalidPadding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "invalid padding: is the content you want to decode definitely padded?"
        )
    }
}

/// Pad the given content using PKCS #7.
///
/// Pads `content`, mutating the given vector, to a block size given by
/// `block_size` in bytes.
///
/// This function should not encounter any errors.
pub fn pad(content: &mut Bytes, block_size: usize) {
    let pad_size = block_size - (content.len() % block_size);
    let mut padding: Vec<u8> = iter::repeat(pad_size as u8).take(pad_size).collect();
    content.append(&mut padding);
}

/// Remnove PKCS #7 padding from the given content.
///
/// Removes PKCS #7 padding from `padded_content`, mutating the given vector.
///
/// This function will return a `Result`, containing an empty type if the
/// removal was successful, or an `InvalidPadding` error if the content does not
/// appear to be padded using PKCS #7. In the case that an error is returned,
/// the content will not have been mutated, so this may be used to conditionally
/// remove padding without concern about losing the original data.
pub fn unpad(padded_content: &mut Bytes) -> Result<(), InvalidPadding> {
    let content_len = padded_content.len();

    if content_len == 0 {
        return Ok(());
    }

    let pad_size = padded_content[content_len - 1] as usize;
    if pad_size > content_len {
        return Err(InvalidPadding {});
    }

    for i in (content_len - pad_size)..content_len {
        if padded_content[i] != pad_size as u8 {
            return Err(InvalidPadding {});
        }
    }

    padded_content.truncate(content_len - pad_size);

    Ok(())
}
