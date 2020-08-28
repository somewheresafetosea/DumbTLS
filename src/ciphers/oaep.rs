//! Implementation of RSAES-OAEP (RSA with Optimal Asymmetric Encryption
//! Padding).
//!
//! This module implements RSAES-OAEP as outlined in [PKCS #1 (version
//! 2.2)](https://tools.ietf.org/html/rfc8017).
//!
//! RSA, as initially described within the academic literature, is not suitable
//! for cryptographic use: Encryption is entirely deterministic, so the same
//! plaintext will always encrypt to the same ciphertext when the same key is
//! used. Furthermore, RSA is highly mathematically structured, and has some
//! vulnerabilities (e.g: via multiplicativity) due to this. It is for this
//! reason that RSA must only be used with a secure padding scheme. One such
//! scheme, which is recommended for modern use, is Optimal Asymmetric
//! Encryption Padding (OAEP).
//!
//! OAEP uses a Feistel network in order to introduce a random element to RSA
//! encryption: a random seed is generated, with fixed length (normally equal to
//! the output length of a hash function). The message to be encrypted is padded
//! with zeroes, until the total length of the input (message + padding + seed)
//! equals the length of the RSA modulus to be used. The message and padding are
//! concatenated to form the left hand side of the input for the Feistel
//! Network, and the seed forms the right hand side. A mask generating function
//! is used to form the round function: This uses the selected hash function to
//! generate an arbitrary sized mask from its input. First a mask is generated
//! from the random seed, then Xor'd with the message & padding to form the left
//! hand side of the output. Then, a mask is generated from this output, and
//! Xor'd with the random seed to form the right hand side of the output.
//!
//! To reverse OAEP, simply reverse the Feistel network, as normal.
//!
//! # Example usage
//! ``` rust
//! use dumbtls::bytes::Bytes;
//! use dumbtls::ciphers::block::BlockCipher;
//! use dumbtls::ciphers::oaep::OAEP;
//! use dumbtls::ciphers::rsa::{RSAKeysize, RSAKey};
//! use dumbtls::encoding::hex::{ToHex, FromHex};
//! use dumbtls::keygen::gen_key_rsa;
//! 
//! fn main() {
//!     let keypair = gen_key_rsa(RSAKeysize::Key1024Bit);
//!     println!("Key modulus: {}", keypair.public.get_modulus());
//!     println!("Public exponent: {}", keypair.public.get_exponent());
//!     println!("Private exponent: {}", keypair.private.get_exponent());
//!     let plaintext = Bytes::from_hex("cafebabe").unwrap();
//!     println!("Plaintext: {}", plaintext.to_hex());
//!     let pubkey = keypair.public.clone();
//!     let mut enc_cipher = OAEP::new(pubkey);
//!     let ciphertext = enc_cipher.encrypt_block(plaintext).unwrap();
//!     println!("Ciphertext: {}", ciphertext.to_hex());
//!     let mut dec_cipher = OAEP::new(keypair.private.clone());
//!     let plaintext = dec_cipher.decrypt_block(ciphertext).unwrap();
//!     println!("Decrypted ciphertext: {}", plaintext.to_hex());
//!     // Example output:
//!     // Key modulus: 92923642353856878160738108776523986341734... (Truncated)
//!     // Public exponent: 65537
//!     // Private exponent: 379613905318714845754840008795561112... (Truncated)
//!     // Plaintext: cafebabe
//!     // Ciphertext: 5bf31b4ed6a1f5e53684ef0d738d5595c89dcbe33b... (Truncated)
//!     // Decrypted ciphertext: cafebabe
//! }
//! ```
use crate::bytes::Bytes;
use crate::ciphers::feistel::{FeistelCipher, FeistelNetwork, FeistelCipherError, FeistelResult};
use crate::ciphers::rsa::{RSAKey, RSAResult, bytes_to_integer, integer_to_bytes, encrypt_int, decrypt_int};
use crate::hashes::{HashFunction, sha2::{Sha2, Sha256, Digest}};
use rand::{thread_rng, RngCore};
use rug::Integer;
use std::iter;

pub type OAEP<T, U, V> = FeistelNetwork<OAEPBlock<T, U, V>>;

impl<T> OAEP<T, Sha2<Sha256>, MGF1>
where
    T: RSAKey,
{
    pub fn new(key: T) -> OAEP<T, Sha2<Sha256>, MGF1> {
        let mut seed = vec![0; 32];
        thread_rng().fill_bytes(&mut seed);
        let cipher = OAEPBlock {
            label: vec![],
            seed,
            key, 
            hash_function: Sha2 { hasher: Sha256::new() },
            mask_generator: MGF1 { },
        };
        FeistelNetwork {
            cipher,
        }
    }
}

pub struct OAEPBlock<T, U, V>
where
    T: RSAKey,
    U: HashFunction,
    V: MaskGenerationFunction<U>
{
    pub label: Bytes,
    pub seed: Bytes,
    pub key: T,
    pub hash_function: U,
    pub mask_generator: V,
}

impl<T, U, V> OAEPBlock<T, U, V>
where
    T: RSAKey,
    U: HashFunction,
    V: MaskGenerationFunction<U>
{
    fn remove_padding(&mut self, plaintext: &Bytes) -> FeistelResult<Bytes> {
        let mut msg_start: usize = 0;
        let mut encountered_boundary = false;

        for (i, byte) in plaintext.into_iter().enumerate() {
            if *byte == 0x01 {
                msg_start = i + 1;
                encountered_boundary = true;
                break;
            } else if *byte != 0x00 {
                let err = String::from("decryption error");
                return Err(FeistelCipherError::GenericDecryptionError(Some(err)));
            }
        }

        if !encountered_boundary {
            let err = String::from("decryption error");
            return Err(FeistelCipherError::GenericDecryptionError(Some(err)));
        }

        let mut output = vec![0; plaintext.len() - msg_start];
        output.copy_from_slice(&plaintext[msg_start..]);

        Ok(output)
    }
}

impl<T, U, V> FeistelCipher for OAEPBlock<T, U, V>
where
    T: RSAKey,
    U: HashFunction,
    V: MaskGenerationFunction<U>
{
    fn get_num_rounds(&mut self, _msg: &Bytes) -> u32 {
        2
    }

    fn get_block_size(&mut self, _msg: &Bytes) -> usize {
        self.key.get_size_bytes()
    }

    fn derive_round_subkey(&mut self, _: u32) -> FeistelResult<Bytes> {
        // Subkeys aren't used in RSA-OAEP
        Ok(vec![])
    }

    fn round_function(&mut self, rhs: &Bytes, _: &Bytes, round_num: u32) -> FeistelResult<Bytes> {
        let key_len = self.key.get_size_bytes();
        let hash_len = U::output_size();

        let mask_len = match round_num {
            0 => key_len - hash_len - 1,
            1 => hash_len,
            _ => panic!("unreachable"),
        };

        match V::generate_mask(rhs, mask_len) {
            Ok(mask) => Ok(mask),
            Err(_) => {
                let err = String::from("mask too long");
                Err(FeistelCipherError::RoundFunction(Some(err)))
            }
        }
    }

    fn is_valid_plaintext_block(&mut self, plaintext: &Bytes) -> FeistelResult<()> {
        if self.label.len() as u128 > U::max_input_size() {
            let err = String::from("label too long");
            return Err(FeistelCipherError::InvalidBlock(Some(err)));
        }

        let msg_len = plaintext.len();
        let key_len = self.key.get_size_bytes();
        let hash_len = U::output_size();
        if msg_len > key_len - (2 * hash_len) - 2 {
            let err = String::from("message too long");
            return Err(FeistelCipherError::InvalidBlock(Some(err)));
        }

        Ok(())
    }

    fn pre_encrypt_block(&mut self, plaintext: &mut Bytes) {
        let mut label_hash = U::hash(&self.label);

        let msg_len = plaintext.len();
        let key_len = self.key.get_size_bytes();
        let hash_len = U::output_size();
        let padding_size = key_len - msg_len - (2 * hash_len) - 2;
        let mut padding: Bytes = iter::repeat(0x00).take(padding_size).collect();

        let mut data_block: Bytes = vec![];
        data_block.append(&mut label_hash);
        data_block.append(&mut padding);
        data_block.push(0x01);
        data_block.append(plaintext);
        plaintext.truncate(0);
        plaintext.append(&mut data_block);

        self.seed = vec![0; hash_len];
        thread_rng().fill_bytes(&mut self.seed);
    }

    fn split_plaintext(&mut self, plaintext: &Bytes) -> (Bytes, Bytes) {
        (plaintext.clone(), self.seed.clone())
    }

    fn post_encrypt_block(&mut self, ciphertext: &mut Bytes) {
        let mut message: Bytes = vec![0x00];
        message.append(ciphertext);
        let message_int = bytes_to_integer(&message);
        let encrypted_message_int = encrypt_int(&self.key, message_int).unwrap();
        let key_len = self.key.get_size_bytes();
        let mut encrypted_message = integer_to_bytes(encrypted_message_int, key_len as u32).unwrap();
        ciphertext.truncate(0);
        ciphertext.append(&mut encrypted_message);
    }

    fn is_valid_ciphertext_block(&mut self, ciphertext: &Bytes) -> FeistelResult<()> {
        if self.label.len() as u128 > U::max_input_size() {
            let err = String::from("decryption error");
            return Err(FeistelCipherError::GenericDecryptionError(Some(err)));
        }

        let key_len = self.key.get_size_bytes();
        if ciphertext.len() != key_len {
            let err = String::from("decryption error");
            return Err(FeistelCipherError::GenericDecryptionError(Some(err)));
        }

        let hash_len = U::output_size();
        if key_len < (2 * hash_len) + 2 {
            let err = String::from("decryption error");
            return Err(FeistelCipherError::GenericDecryptionError(Some(err)));
        }

        Ok(())
    }

    fn pre_decrypt_block(&mut self, ciphertext: &mut Bytes) {
        let key_len = self.key.get_size_bytes() as u32;
        let encrypted_message_int = bytes_to_integer(&ciphertext);
        let message_int = decrypt_int(&self.key, encrypted_message_int).unwrap();
        let mut message = integer_to_bytes(message_int, key_len).unwrap();
        message.remove(0);
        ciphertext.truncate(0);
        ciphertext.append(&mut message);
    }

    fn split_ciphertext(&mut self, ciphertext: &Bytes) -> (Bytes, Bytes) {
        let key_len = self.key.get_size_bytes();
        let hash_len = U::output_size();
        let mut masked_data: Bytes = vec![0; key_len - hash_len - 1];
        let mut masked_seed: Bytes = vec![0; hash_len];
        masked_data.copy_from_slice(&ciphertext[hash_len..key_len - 1]);
        masked_seed.copy_from_slice(&ciphertext[0..hash_len]);
        (masked_seed, masked_data)
    }

    fn post_decrypt_block(&mut self, plaintext: &mut Bytes) {
        let key_len = self.key.get_size_bytes();
        let hash_len = U::output_size();
        let mut data_block: Bytes = vec![0; key_len - (2 * hash_len) - 1];
        data_block.copy_from_slice(&plaintext[hash_len..(key_len - hash_len - 1)]);
        let mut msg = self.remove_padding(&data_block).unwrap();
        plaintext.truncate(0);
        plaintext.append(&mut msg);
    }
}

pub trait MaskGenerationFunction<T: HashFunction> {
    fn generate_mask(seed: &Bytes, length: usize) -> RSAResult<Bytes>;
}

pub struct MGF1 { }

impl<T: HashFunction> MaskGenerationFunction<T> for MGF1 {
    fn generate_mask(seed: &Bytes, length: usize) -> RSAResult<Bytes> {
        let mut mask = vec![];

        for i in 0..(length as f64 / T::output_size() as f64).ceil() as usize {
            let mut octet_str = integer_to_bytes(Integer::from(i), 4)?;
            let mut seed = seed.clone();
            seed.append(&mut octet_str);
            mask.append(&mut T::hash(&seed));
        }

        Ok(mask.into_iter().take(length).collect())
    }
}
