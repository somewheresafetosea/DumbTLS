//! Hash functions.
//!
//! The content of this module is, unfortunately, not currently implemented in
//! DumbTLS, and we instead rely on the external
//! [`sha-1`](https://crates.io/crates/sha-1) and
//! [`sha2`](https://crates.io/crates/sha2) crates to provide the algorithms.
//! In the future, I plan to actually implement these hash functions (and more!)
//! but for the time being, dependencies are used.
pub mod sha1;
pub mod sha2;

use crate::bytes::Bytes;

/// Trait for a generic hash function.
pub trait HashFunction {
    /// Hash the input.
    ///
    /// Should produce an output of size `HashFunction::output_size()`.
    fn hash(input: &Bytes) -> Bytes;
    /// Returns the (fixed) output size of the function.
    fn output_size() -> usize;
    /// Returns the maximum input size of the function.
    fn max_input_size() -> u128;
}
