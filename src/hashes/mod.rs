pub mod sha1;
pub mod sha2;

use crate::bytes::Bytes;

pub trait HashFunction {
    fn hash(input: &Bytes) -> Bytes;
    fn output_size() -> usize;
    fn max_input_size() -> u128;
}
