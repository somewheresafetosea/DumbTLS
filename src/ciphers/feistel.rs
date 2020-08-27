//! Traits and structs for implementing ciphers built around Feistel Networks.
//!
//! Feistel networks are a generic structure for implementing block ciphers with
//! heavy confusion and diffusion, originally designed by Horst Feistel. For a
//! cipher to implement confusion and diffusion, a common technique is to
//! perform multiple "rounds": In each round, the key is used to encrypt the
//! text somehow, then the text is shuffled round, with the next round depending
//! on the previous round. With sufficient rounds, this technique can be very
//! easily used to implement very strong confusion and diffusion, however, to
//! reverse the encryption, it is necessary to invert each round, which may be
//! mathematically impossible.
//!
//! Feistel networks provide a simple solution to implementing multiple-round
//! ciphers. In each round, the text to encrypt is split into two halves. The
//! second half is run through a round function with the key as an input, and
//! the result is then Xor'd with the first half. The output of the round is
//! then created by concatenating the second half (entirely unaltered), with
//! this Xor'd first half, so that the alteed first half is now placed second.
//! In the next round, the same process is done, so the new second half is run
//! through the round function, then Xor'd with the new first half (which was
//! the second half in the previous round). The output of each round only
//! encrypts half of the message. This means that a Feistel cipher is extremely
//! easy to invert, given the key: You simply do the same operations in reverse.
//!
//! The layout of a Feistel cipher is shown in the diagram below, with `F`
//! denoting the round function.
//!
//! ```
//!       Encryption:          Decryption:
//!     L0           R0    RN+1          LN+1
//!     |             |      |             |
//!     |     Key     |      |     Key     |
//!     |      |      |      |      |      |
//!     v      v      |      v      v      |
//!    Xor <-- F <----+     Xor <-- F <----+
//!     |             |      |             |
//!     v             v      v             v
//!     R1           L1      LN           RN
//!     |             |      |             |
//!     |     Key     |      |     Key     |
//!     |      |      |      |      |      |
//!     |      v      v      |      v      v
//!     +----> F --> Xor     +----> F --> Xor
//!     |             |      |             |
//!     v             v      v             v
//!     L2           R2    RN-1          LN-1
//!          . . .                . . .
//!     |             |      |             |
//!     v             v      v             v
//!     LN           RN      R1           L1
//!     |             |      |             |
//!     |     Key     |      |     Key     |
//!     |      |      |      |      |      |
//!     v      v      |      v      v      |
//!    Xor <-- F <----+     Xor <-- F <----+
//!     |             |      |             |
//!     v             v      v             v
//!    RN+1         LN+1     L0           R0
//! ```
//!
//! The Feistel Network structure is made use of by a number of well known
//! ciphers, including DES and RSAES-OAEP.
use crate::bytes::{Bytes, SequenceXor};
use crate::ciphers::block::BlockCipher;

/// Errors encountered while encrypting/decrypting using a Feistel Network.
#[derive(Clone, Debug)]
pub enum FeistelCipherError {
    /// The cipher in used decided the provided block was invalid for some
    /// reason.
    InvalidBlock(Option<String>),
    /// The cipher in used decided the provided key was invalid for some reason.
    InvalidKey(Option<String>),
    /// There was an error in deriving the subkey for some round.
    SubkeyDerivation(Option<String>),
    /// There was an error in the round function for some round.
    RoundFunction(Option<String>),
    /// There was a generic error according to the cipher.
    GenericDecryptionError(Option<String>),
    /// Tried to XOR two byte strings of different lengths.
    XorError,
}

pub type FeistelResult<T> = Result<T, FeistelCipherError>;

/// Trait for ciphers which work using a Feistel network.
///
/// Types implementing this trait are intended for internal use within the
/// [`FeistelNetwork`] struct, which runs the actual encryption/decryption using
/// the primitives provided by the `FeistelCipher` instance.
pub trait FeistelCipher {
    /// Get the number of rounds to perform.
    ///
    /// At least two rounds are necessary for the entire message to have been
    /// encrypted. The FeistelNetwork will run this number of rounds.
    fn get_num_rounds(&mut self, plaintext: &Bytes) -> u32;
    /// Get the block size used by the cipher.
    fn get_block_size(&mut self, plaintext: &Bytes) -> usize;
    /// Derive the subkey for a given round.
    ///
    /// This subkey will be provided to the round function.
    fn derive_round_subkey(&mut self, round_num: u32) -> FeistelResult<Bytes>;
    /// Perform the round function, and return the data to be Xor'd against the
    /// current left hand side.
    fn round_function(&mut self, rhs: &Bytes, subkey: &Bytes, round_num: u32) -> FeistelResult<Bytes>;

    /// Perfom any transformations to the plaintext that are required before
    /// encryption begins.
    ///
    /// Don't raise any errors here, do that in the `is_valid_plaintext_block`
    /// method.
    fn pre_encrypt_block(&mut self, _plaintext: &mut Bytes) { }
    /// Retuns an error if the plaintext is invalid.
    fn is_valid_plaintext_block(&mut self, plaintext: &Bytes) -> FeistelResult<()>;
    /// Split the plaintext into left and right hand sides.
    ///
    /// These don't necessarily have to be of equal length, so long as the
    /// round function can deal with that an output appropriate-length data.
    fn split_plaintext(&mut self, plaintext: &Bytes) -> (Bytes, Bytes);
    /// Perform any transformations to the ciphertext that are required after
    /// encryption ends.
    fn post_encrypt_block(&mut self, _ciphertext: &mut Bytes) { }

    /// Perfom any transformations to the ciphertext that are required before
    /// decryption begins.
    ///
    /// Don't raise any errors here, do that in the `is_valid_ciphertext_block`
    /// method.
    ///
    /// Default implementation just calls [`self.pre_encrypt_block`]
    fn pre_decrypt_block(&mut self, ciphertext: &mut Bytes) {
        self.pre_encrypt_block(ciphertext);
    }
    /// Returns an error if the ciphertext is invalid.
    fn is_valid_ciphertext_block(&mut self, ciphertext: &Bytes) -> FeistelResult<()>;
    /// Split the ciphertext into left and right hand sides.
    ///
    /// These don't necessarily have to be of equal length, so long as the
    /// round function can deal with that an output appropriate-length data.
    fn split_ciphertext(&mut self, ciphertext: &Bytes) -> (Bytes, Bytes);
    /// Perfom any transformations to the plaintext that are required after
    /// decryption ends.
    ///
    /// Default implementation just calls [`self.post_encrypt_block`]
    fn post_decrypt_block(&mut self, plaintext: &mut Bytes) {
        self.post_encrypt_block(plaintext);
    }
}

/// Feistel Network implementation
///
/// Used to perfom encryption/decryption with the given cipher, via a Feistel
/// Network.
pub struct FeistelNetwork<T: FeistelCipher> {
    /// Cipher to use, should be an instance of [`FeistelCipher`].
    pub cipher: T,
}

impl<T: FeistelCipher> FeistelNetwork<T> {
    /// Create a new instance of `FeistelNetwork` from the given cipher.
    pub fn from_cipher(cipher: T) -> FeistelNetwork<T> {
        FeistelNetwork { cipher }
    }

    /// Runs the Feistel Network round iteration.
    ///
    /// This method shouldn't be used directly: Use the
    /// `FeistelNetwork::encrypt_block` and `FeistelNetwork::decrypt_block`
    /// methods instead (implemented as part of the [`BlockCipher`] trait.
    pub fn run_network<I>(
        &mut self,
        mut lhs: Bytes,
        mut rhs: Bytes,
        iter: I,
    ) -> FeistelResult<Bytes>
    where
        I: Iterator<Item = u32>,
    {
        for i in iter {
            let subkey = self.cipher.derive_round_subkey(i)?;
            let rf_output = self.cipher.round_function(&rhs, &subkey, i)?;
            let lhs_enc = match lhs.xor(&rf_output) {
                Ok(b) => b,
                Err(_) => return Err(FeistelCipherError::XorError),
            };

            lhs = rhs;
            rhs = lhs_enc;
        }

        rhs.append(&mut lhs);
        Ok(rhs)
    }
}

impl<T: FeistelCipher> BlockCipher for FeistelNetwork<T> {
    type Error = FeistelCipherError;

    /// Encrypt the given plaintext.
    ///
    /// Runs the number of rounds required by the internal cipher of the Feistel
    /// Network. First calls `cipher.is_valid_plaintext_block`, then
    /// `cipher.pre_encrypt_block`. Splits plaintext using
    /// `cipher.split_plaintext`, then cals [`self.run_network`]. Finally calls
    /// `cipher.post_encrypt_block`.
    fn encrypt_block(&mut self, mut plaintext: Bytes) -> FeistelResult<Bytes> {
        self.cipher.is_valid_plaintext_block(&plaintext)?;

        self.cipher.pre_encrypt_block(&mut plaintext);

        let (lhs, rhs) = self.cipher.split_plaintext(&plaintext);

        let num_rounds = self.cipher.get_num_rounds(&plaintext);
        let mut ciphertext = self.run_network(lhs, rhs, 0..num_rounds)?;

        self.cipher.post_encrypt_block(&mut ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt the given ciphertext.
    ///
    /// Runs the number of rounds required by the internal cipher of the Feistel
    /// Network. First calls `cipher.is_valid_ciphertext_block`, then
    /// `cipher.pre_decrypt_block`. Splits ciphertext using
    /// `cipher.split_ciphertext`, then cals [`self.run_network`]. Finally calls
    /// `cipher.post_decrypt_block`.
    fn decrypt_block(&mut self, mut ciphertext: Bytes) -> FeistelResult<Bytes> {
        self.cipher.is_valid_ciphertext_block(&ciphertext)?;

        self.cipher.pre_decrypt_block(&mut ciphertext);

        let (lhs, rhs) = self.cipher.split_ciphertext(&ciphertext);

        let num_rounds = self.cipher.get_num_rounds(&ciphertext);
        let mut plaintext = self.run_network(lhs, rhs, (0..num_rounds).rev())?;

        self.cipher.post_decrypt_block(&mut plaintext);
        Ok(plaintext)
    }

    fn get_block_size(&mut self, msg: &Bytes) -> usize {
        self.cipher.get_block_size(&msg)
    }
}
