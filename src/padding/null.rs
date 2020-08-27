//! Functions for adding/removing null-byte padding.
//!
//! In some programming languages, strings are terminated by a null-byte (i.e:
//! `0x00`, the byte with all bits set to false). Therefore, if one is padding
//! string data for use with a block cipher, it is often convenient to pad the
//! data with repeated null bytes, up until it has length equal to a multiple of
//! the block size. To remove the padding, simply remove all null bytes from the
//! end of the final block.
use crate::bytes::Bytes;
use std::iter;

/// Pad the given content using null bytes.
///
/// Pads `content`, mutating the given vector, to a block size given by
/// `block_size` in bytes.
///
/// This function should not encounter any errors.
pub fn pad(content: &mut Bytes, block_size: usize) {
    let pad_size = block_size - (content.len() % block_size);
    let mut padding: Vec<u8> = iter::repeat(0b0).take(pad_size).collect();
    content.append(&mut padding);
}

/// Remove null padding from the given content.
///
/// Removes null bytes from the end of `padded_content`, mutating the given
/// vector.
///
/// This function should not encounter any errors.
pub fn unpad(padded_content: &mut Bytes) {
    let mut final_null = padded_content.len();
    for (i, byte) in padded_content.into_iter().enumerate().rev() {
        if *byte != 0b0 {
            break;
        } else {
            final_null = i;
        }
    }
    padded_content.truncate(final_null);
}
