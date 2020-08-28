use sha1;
use sha1::Digest;
use crate::hashes::HashFunction;
use crate::bytes::Bytes;

/// The SHA-1 hashing algorithm.
pub struct Sha1 { }

impl HashFunction for Sha1 {
    fn hash(input: &Bytes) -> Bytes {
        let mut hasher = sha1::Sha1::new();
        hasher.update(input);
        hasher.finalize().into_iter().collect()
    }

    fn output_size() -> usize {
        20
    }

    fn max_input_size() -> u128 {
        (2 as u128).pow(61) - 1
    }
}
