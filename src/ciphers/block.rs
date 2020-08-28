//! Modes of operation for symmetric block ciphers.
//!
//! As discussed in the documentation for this module, block ciphers work using
//! fixed-length blocks of input. However, we often wish to work with
//! arbitrarily large (or small) input texts. For this, it may seem that block
//! ciphers are not applicable: If an input is too long to fit in a block, it
//! cannot be encrypted by a block cipher. It is for this reason that we
//! implement generic "modes of operation" for block ciphers, which allow them
//! to be used to encrypt and decrypt inputs of sizes greater than a single
//! block.
//!
//! These modes of operation are simply techniques for splitting the plaintext,
//! and then applying the cipher multiple times to ensure the entire plaintext
//! is encrypted. However, the choice of block cipher mode has important
//! security implications, which must be considered when using them.
use crate::bytes::{Bytes, SequenceXor};
use crate::padding::{PaddingScheme, PKCS7};

/// Trait for a generic block cipher.
///
/// This trait is to be implemented by structs representing a block cipher
/// algorithm: They must be able to encrypt a single block of data, and decrypt
/// a single block of data. They must also be able to provide their block size.
///
/// It is structs that implement this trait that are operated on by the block
/// cipher modes of operation in the `block` module.
pub trait BlockCipher {
    /// Error type returned when this cipher encounters an error.
    type Error: Sized;
    /// Retrieve the block size of the cipher, in bytes.
    fn get_block_size(&mut self, msg: &Bytes) -> usize;
    /// Encrypt the given plaintext.
    ///
    /// This function should return the `Ok` option, containing the bytes
    /// representing the ciphertext if and only if the encryption was
    /// successful, otherwise the `Err` variant should be returned.
    fn encrypt_block(&mut self, plaintext: Bytes) -> Result<Bytes, Self::Error>;
    /// Decrypt the given plaintext.
    ///
    /// This function should return the `Ok` option, containing the bytes
    /// representing the plaintext if and only if the decryption was
    /// successful, otherwise the `Err` variant should be returned.
    fn decrypt_block(&mut self, ciphertext: Bytes) -> Result<Bytes, Self::Error>;
}

/// Electronic CodeBook mode for block ciphers.
///
/// Electronic CodeBook mode is the most intuitive approach to using a block
/// cipher to encrypt data that is larger than a single block: You simply pad
/// the data so that its length is a multiple of the block size, then split it
/// into sequential chunks of size equal to the block size. Each of these blocks
/// is encrypted individually, then they are all concatenated back together in
/// the order they were split (so each block of output corresponds to a block of
/// input in the same location).
///
/// This approach is simple to reason about, and implement, however is has a
/// major flaw: If two blocks contain identical data, then they will have
/// identical output. This is because there is no difference in the encryption
/// process applied to the two blocks: It's the same input, with the same key.
/// This allows an attacker to gain information about the structure of the
/// input, by looking for repetition (or lack thereof) within the output.
/// Consider, for example, the image below, created by Wikipedia user
/// "Lunkwill", and derived from the Tux mascot, originally created by Larry
/// Ewing (lewing@isc.tamu.edu) using The GIMP photo editor:
///
/// ![Comparison of ECB mode to other modes](https://i.ibb.co/Qv3VJvC/ecb.png)
///
/// As can be seen in the comparison, although ECB mode encrypts each block
/// individually so that it cannot be converted back to the original without a
/// key, inferences can still be made about the structure of the data.
///
/// It is for this reason that **ECB IS NOT SECURE** for cryptographic use.
pub struct ECBMode<T: BlockCipher, U: PaddingScheme> {
    /// Block cipher to use for encryption/decryption.
    ///
    /// The block cipher may use any block size or algorithm, so long that this
    /// is consistent for different ciphertexts. Each block of input will be
    /// encrypted and decrypted using this cipher.
    ///
    /// In practice, `T` must be an instance of [`BlockCipher`].
    pub cipher: T,
    /// Padding scheme with which to pad the plaintext for encryption/unpad the
    /// ciphertext after decryption.
    ///
    /// In practice, `U` must be an instance of [`PaddingScheme`], and will
    /// usually be PKCS #7 padding.
    pub padding: U,
}

impl<T> ECBMode<T, PKCS7>
where
    T: BlockCipher
{
    /// Create a new instance of the struct using the given cipher and a
    /// reasonable padding scheme.
    ///
    /// Returns a new instance of `ECBMode` using the provided cipher, and
    /// [PKCS #7 padding](PKCS7).
    pub fn new(cipher: T) -> ECBMode<T, PKCS7> {
        let padding = PKCS7 { };
        ECBMode {
            cipher,
            padding,
        }
    }
}

impl<T, U> ECBMode<T, U>
where
    T: BlockCipher,
    U: PaddingScheme,
{
    /// Create a new instance of the struct using the given cipher and padding
    /// scheme.
    ///
    /// Returns a new instance of `ECBMode` using the provided cipher and
    /// padding.
    pub fn with_padding(cipher: T, padding: U) -> ECBMode<T, U> {
        ECBMode {
            cipher,
            padding,
        }
    }

    /// Encrypt the given plaintext in ECB mode.
    ///
    /// Pads the plaintext using the padding scheme specified in the creation of
    /// the struct, then encrypts it in ECB mode.
    ///
    /// This function will return a `Result`, containing either the result of
    /// the encryption, in bytes, or an error returned by the cipher during
    /// encryption.
    pub fn encrypt(&mut self, plaintext: &Bytes) -> Result<Bytes, T::Error> {
        let mut plaintext = plaintext.clone();
        let bs = self.cipher.get_block_size(&plaintext);
        
        self.padding.pad(&mut plaintext, bs);

        let mut output = vec![];

        for i in 0..(plaintext.len() / bs) {
            let mut in_buf = vec![0; bs];
            in_buf.copy_from_slice(&plaintext[(i * bs)..((i + 1) * bs)]);
            let mut enc = self.cipher.encrypt_block(in_buf)?;
            output.append(&mut enc);
        }

        Ok(output)
    }

    /// Decrypt the given ciphertext in ECB mode.
    ///
    /// Decrypts the ciphertext in ECB mode, then removes any padding using the
    /// padding scheme specified in the creation of the struct.
    ///
    /// This function will return a `Result`, containing either the result of
    /// the decryption, in bytes, or an error returned by the cipher during
    /// decryption.
    pub fn decrypt(&mut self, ciphertext: &Bytes) -> Result<Bytes, T::Error> {
        let bs = self.cipher.get_block_size(&ciphertext);

        let mut output = vec![];

        for i in 0..(ciphertext.len() / bs) {
            let mut in_buf = vec![0; bs];
            in_buf.copy_from_slice(&ciphertext[(i * bs)..((i + 1) * bs)]);
            let mut dec = self.cipher.decrypt_block(in_buf)?;
            output.append(&mut dec);
        }

        self.padding.unpad(&mut output);

        Ok(output)
    }
}

/// Cipher Block Chaining mode for block ciphers.
///
/// CBC mode is extremely popular for use when encrypting/decrypting data,
/// likely due to the combination of its ease of implementation, and massive
/// benefits over ECB mode. In CBC mode, like with ECB mode, the plaintext is
/// padded and then split into blocks. However, before each block is encrypted,
/// it is first XOR'd with the output of encrypting the previous block. This
/// ensures that the input to each block depends not only on the plaintext, but
/// also on the (pseudo-random) output of encrypting the previous block.
///
/// For the first block to be encrypted, there is no "output of the previous
/// block's encryption" to use for the XOR function, so instead we use an
/// Initialisation Vector (IV). This is just a set of bytes, generated using a
/// Cryptographically Secure Pseudo-Random Number Generator (CSPRNG), of length
/// equal to the block size. The IV is not secret, and may be transmitted
/// alongside the encrypted message in plain text. However, it must be different
/// for every run of the cipher, otherwise it is useless. If the IV was not
/// present, then all plaintexts starting with the same first block of input
/// would have identical first blocks of output.
///
/// Below is a diagram, illustrating the encryption process in CBC mode:
///
/// ```
///      Block 1         Block 2                 Block n-1       Block n
///         |              |                         |              |
///         v              v                         v              v
/// IV --> Xor       +--> Xor       +--> . . . ---> Xor       +--> Xor
///         |        |     |        |                |        |     |
///         v        |     v        |                v        |     v
///      Encrypt     |  Encrypt     |             Encrypt     |  Encrypt
///         |--------+     |--------+                |--------+     |
///         v              v                         v              v
///     Output 1        Output 2                Output n-1      Output n
/// ```
///
/// Decryption is similarly simple: Decrypt each block of ciphertext as-is, then
/// for the output, XOR it with the previous (encrypted) block, as shown in the
/// following diagram:
///
/// ```
///      Block 1        Block 2                  Block n-1       Block n
///         |--------+     |--------+                |--------+     |
///         v        |     v        |                v        |     v
///      Decrypt     |  Decrypt     |             Decrypt     |  Decrypt
///         |        |     |        |                |        |     |
///         v        |     v        |                v        |     v
/// IV --> Xor       +--> Xor       +--> . . . ---> Xor       +--> Xor
///         |              |                         |              |
///         v              v                         v              v
///     Output 1        Output 2                Output n-1      Output n
/// ```
pub struct CBCMode<T: BlockCipher, U: PaddingScheme> {
    /// Block cipher to use for encryption/decryption.
    ///
    /// The block cipher may use any block size or algorithm, so long that this
    /// is consistent for different ciphertexts. Each block of input will be
    /// encrypted and decrypted using this cipher.
    ///
    /// In practice, `T` must be an instance of [`BlockCipher`].
    pub cipher: T,
    /// Padding scheme with which to pad the plaintext for encryption/unpad the
    /// ciphertext after decryption.
    ///
    /// In practice, `U` must be an instance of [`PaddingScheme`], and will
    /// usually be PKCS #7 padding.
    pub padding: U,
}

impl<T, U> CBCMode<T, U>
where
    T: BlockCipher,
    U: PaddingScheme,
{
    /// Create a new instance of the struct using the given cipher and a
    /// reasonable padding scheme.
    ///
    /// Returns a new instance of `CBCMode` using the provided cipher, and
    /// [PKCS #7 padding](PKCS7).
    pub fn new(cipher: T) -> CBCMode<T, PKCS7> {
        let padding = PKCS7 { };
        CBCMode {
            cipher,
            padding,
        }
    }

    /// Create a new instance of the struct using the given cipher and padding
    /// scheme.
    ///
    /// Returns a new instance of `CBCMode` using the provided cipher and
    /// padding.
    pub fn with_padding(cipher: T, padding: U) -> CBCMode<T, U> {
        CBCMode {
            cipher,
            padding,
        }
    }
    /// Encrypt the given plaintext in CBC mode.
    ///
    /// Pads the plaintext using the padding scheme specified in the creation of
    /// the struct, then encrypts it in CBC mode, using the initialisation
    /// vector given by `iv`.
    ///
    /// This function will return a `Result`, containing either the result of
    /// the encryption, in bytes, or an error returned by the cipher during
    /// encryption.
    ///
    /// # Panics
    /// This function will panic if the length of `iv` is not the same as the
    /// block size of the cipher.
    pub fn encrypt(&mut self, plaintext: &Bytes, iv: &Bytes) -> Result<Bytes, T::Error> {
        let bs = self.cipher.get_block_size(&plaintext);
        
        if iv.len() != bs {
            panic!("IV length must equal block size");
        }

        let mut plaintext = plaintext.clone();
        self.padding.pad(&mut plaintext, bs);

        let mut output = vec![];
        let mut prev_block = iv.clone();

        for i in 0..(plaintext.len() / bs) {
            let mut in_buf = vec![0; bs];
            in_buf.copy_from_slice(&plaintext[(i * bs)..((i + 1) * bs)]);
            let mut enc = self.cipher.encrypt_block(in_buf.xor(&prev_block).unwrap())?;
            prev_block = enc.clone();
            output.append(&mut enc);
        }
        
        Ok(output)

    }
    /// Decrypt the given ciphertext in CBC mode.
    ///
    /// Decrypts the given ciphertext in CBC mode, using the initialisation
    /// vector given by `iv`, then removes any padding using the padding scheme
    /// specified in the creation of the struct.
    ///
    /// This function will return a `Result`, containing either the result of
    /// the decryption, in bytes, or an error returned by the cipher during
    /// decryption.
    ///
    /// # Panics
    /// This function will panic if the length of `iv` is not the same as the
    /// block size of the cipher.
    pub fn decrypt(&mut self, ciphertext: &Bytes, iv: &Bytes) -> Result<Bytes, T::Error> {
        let bs = self.cipher.get_block_size(&ciphertext);
        
        if iv.len() != bs {
            panic!("IV length must equal block size");
        }

        let mut output = vec![];
        let mut prev_block = iv.clone();

        for i in 0..(ciphertext.len() / bs) {
            let mut in_buf = vec![0; bs];
            in_buf.copy_from_slice(&ciphertext[(i * bs)..((i + 1) * bs)]);
            let dec = self.cipher.decrypt_block(in_buf.clone())?;
            output.append(&mut dec.xor(&prev_block).unwrap());
            prev_block = in_buf;
        }


        self.padding.unpad(&mut output);

        Ok(output)
    }
}
