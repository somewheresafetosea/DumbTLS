pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
pub use sha2::Digest;
use crate::hashes::HashFunction;
use crate::bytes::Bytes;

/// The SHA-2 hashing algorithm.
pub struct Sha2<T: Digest> {
    pub hasher: T
}

impl<T: Digest> HashFunction for Sha2<T> {
    fn hash(input: &Bytes) -> Bytes {
        let mut hasher = T::new();
        hasher.update(input);
        hasher.finalize().into_iter().collect()
    }

    fn output_size() -> usize {
        T::output_size()
    }

    fn max_input_size() -> u128 {
        (2 as u128).pow(61) - 1
    }
}
