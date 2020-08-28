//! Implementation of DES.
//!
//! DES is a block cipher based around a Feistel Network, and as such, it is
//! implemented in DumbTLS using the [`FeistelCipher`] and [`FeistelNetwork`]
//! structures.
//!
//! DES was originally developed by IBM in the 1970s, with input from the NSA,
//! and was published for public use. Being one of the first modern ciphers to
//! be made publicly available, DES was widely used throughout the late 20th
//! century. The cipher uses a key size of 64 bits (= 8 bytes), although 8 of
//! those bits are not used during encryption, so it should really be thought of
//! as using a 56-bit key. DES operates on blocks of size 64 bits.
//! This cipher is now known to be insecure due to its short keysize, and
//! **should not be used for cryptographic purposes**.
//!
//! As DES is based on a Feistel Network, in each round, the right hand side is
//! passed through a round function, to derive an intermediate value with which
//! the left hand side is Xor'd. The round function combines the RHS with a
//! round key. The process for doing so is as follows:
//!
//! 1. **Expansion**: The 32-bit right hand side is expanded from 8 4-bit blocks
//! (= 32 bits) to 8 6-bit blocks (= 48 bits). This is done to increase
//! diffusion: 16 of the 32 bits appear twice in the output of the expansion,
//! but an input bit never occurs twice in the same 6-bit output block. This bit
//! mapping is done according to the DES expansion permutation table, E.
//! 2. **XOR**: A 48-bit subkey for this round is derived from the original key,
//! and the output of the expansion is Xor'd with it.
//! 3. **Substitution**: The 48-bit result of the XOR is split into 8 6-bit
//! blocks, each of which is passed through a Subsitution Box (or S-Box). The
//! S-Boxes provide confusion for the cipher. They also provide non-linearity,
//! which defends DES against known plaintext attacks. Each S-Box maps 6 bits
//! to 4 bits, so the output of the substitution is 32 bits long.
//! 4. **Permutation**: Permutation is used to ensure that the outputs of the
//! S-Boxes will pass through different S-Boxes in the next round, increasing
//! diffusion. It is a 1:1 mapping of bits, so its output is 32 bits long.
//!
//! The NSA are known to have heavily influenced the design of the S-Boxes for
//! the substitution round, which was originally a major concern for many, due
//! to the possibility of there being a backdoor. However, it was later revealed
//! that the NSA's input was intended to strengthen DES against the (at the
//! time) non-public differential cryptanalysis attack.
//!
//! # Example usage
//! ``` rust
//! use dumbtls::bytes::Bytes;
//! use dumbtls::ciphers::block::{BlockCipher, CBCMode};
//! use dumbtls::ciphers::des::DES;
//! use dumbtls::encoding::hex::{FromHex, ToHex};
//! use dumbtls::keygen;
//! use dumbtls::padding::PKCS7;
//! 
//! fn main() {
//!     // Encrypting a single block:
//!     let key = keygen::gen_key_des();
//!     println!("Key: {}", key.to_hex());
//!     let mut cipher = DES::new(&key);
//!     let plaintext = Bytes::from_hex("cafebabecafebabe").unwrap();
//!     println!("Plaintext: {}", plaintext.to_hex());
//!     let ciphertext = cipher.encrypt_block(plaintext).unwrap();
//!     println!("Ciphertext: {}", ciphertext.to_hex());
//!     let plaintext = cipher.decrypt_block(ciphertext).unwrap();
//!     println!("Decrypted Ciphertext: {}", plaintext.to_hex());
//!     // Example output:
//!     // Key: 29ab5b939fb28c69
//!     // Plaintext: cafebabecafebabe
//!     // Ciphertext: c5e99a6ae10903af
//!     // Decrypted Ciphertext: cafebabecafebabe
//! 
//!     // Using CBC mode to encrypt an arbitrary-length message:
//!     let key = keygen::gen_key_des();
//!     let iv = keygen::gen_key_des();
//!     println!("Key: {}", key.to_hex());
//!     println!("IV: {}", iv.to_hex());
//!     let cipher = DES::new(&key);
//!     let padding = PKCS7 { };
//!     let mut cbc = CBCMode::with_padding(cipher, padding);
//!     // n.b: Plaintext is no longer a multiple of the block size
//!     let plaintext = Bytes::from_hex("0011223344556677889900aa").unwrap();
//!     println!("Plaintext: {}", plaintext.to_hex());
//!     let ciphertext = cbc.encrypt(&plaintext, &iv).unwrap();
//!     println!("Ciphertext: {}", ciphertext.to_hex());
//!     let plaintext = cbc.decrypt(&ciphertext, &iv).unwrap();
//!     println!("Decrypted Ciphertext: {}", plaintext.to_hex());
//!     // Example output:
//!     // Key: 72a5ea8842c1d5eb
//!     // IV: 7cac5a01a9f5c831
//!     // Plaintext: 0011223344556677889900aa
//!     // Ciphertext: d73325924d1ed98604f92772f31e4d79
//!     // Decrypted Ciphertext: 0011223344556677889900aa
//! }
//! ```
use crate::bytes::{Bytes, SequenceXor};
use crate::ciphers::feistel::{FeistelCipher, FeistelCipherError, FeistelNetwork, FeistelResult};

/// DES cipher
///
/// Wrapper around a Feistel Network with the DES internal block cipher.
pub type DES = FeistelNetwork<DESBlock>;

impl DES {
    /// Create a new instance of the DES cipher.
    ///
    /// The given key should be 8 bytes long
    pub fn new(key: &Bytes) -> DES {
        let block_cipher = DESBlock {
            key: key.clone(),
            key_cur: key.clone(),
        };
        DES {
            cipher: block_cipher
        }
    }
}

/// DES internal block ciper.
///
/// Used within a [`FeistelNetwork`] instance. Please don't use this directly:
/// Use [`DES`] instead.
pub struct DESBlock {
    pub key: Bytes,
    key_cur: Bytes,
}

impl DESBlock {
    /// Get a given bit's value (0 or 1) from an integer.
    pub fn get_bit(&self, byte: u8, bit_pos: u8) -> u8 {
        return (byte >> (7 - bit_pos)) & 1;
    }

    /// Maps the bits of a collection of Bytes to new locations.
    ///
    /// Takes an instance of [`Bytes`] and a slice containing the indices of
    /// bits within the first collection, in the positions where they should be
    /// placed. Mutates the first to move bits to where they should go.
    pub fn map_bits(&self, unmapped_bytes: &mut Bytes, map: &[usize]) {
        let mut mapped_output = Bytes::with_capacity(map.len() / 8);

        let mut cur_byte: u8 = 0;
        for (i, bit_pos) in map.into_iter().enumerate() {
            let quotient = bit_pos / 8;
            let remainder = (bit_pos % 8) as u8;

            let byte = unmapped_bytes[quotient];

            cur_byte <<= 1;
            cur_byte += self.get_bit(byte, remainder);

            if i % 8 == 7 {
                mapped_output.push(cur_byte);
                cur_byte = 0;
            }
        }

        unmapped_bytes.truncate(0);
        unmapped_bytes.append(&mut mapped_output);
    }

    /// Perform the initial permutation on plaintext, prior to performing the
    /// DES rounds.
    pub fn initial_permutation(&self, plaintext: &mut Bytes) {
        const IP_MAPPING: [usize; 64] = [
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
            56, 48, 40, 32, 24, 16, 8, 0,
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 24, 6,
        ];

        self.map_bits(plaintext, &IP_MAPPING);
    }

    /// Perform the final permutation on ciphertext, after having performed the
    /// DES rounds.
    pub fn final_permutation(&self, ciphertext: &mut Bytes) {
        const FP_MAPPING: [usize; 64] = [
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25,
            32, 0, 40, 8, 48, 16, 56, 24,
        ];

        self.map_bits(ciphertext, &FP_MAPPING);
    }

    /// Perform permuted choice 1, to initialise the key, before performing
    /// encryption/decryption.
    pub fn permuted_choice_1(&mut self) {
        const PC1_MAPPING: [usize; 56] = [
            56, 48, 40, 32, 24, 16, 8, 0,
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 60, 52, 44, 36,
            28, 20, 12, 4, 27, 19, 11, 3,
        ];

        let mut key_tmp = self.key_cur.clone();
        self.map_bits(&mut key_tmp, &PC1_MAPPING);
        self.key_cur = key_tmp;
    }

    /// Rotate the two halves of the key one place left.
    ///
    /// Each half of the key must be rotated individually. Unfortunately, the
    /// break between the two halves falls in the middle of the byte, so we've
    /// got to do some pretty arcane stuff to get this working.
    pub fn rotate_key_left(&self, key: &Bytes) -> Bytes {
        let mut out = vec![];

        for i in 0..3 {
            let byte = key[i];
            out.push((byte << 1) | (key[i + 1] >> 7));
        }

        let first_half = key[3] & 0b11110000;
        let second_half = key[3] & 0b00000111;
        let first_rot = (first_half << 1) | ((key[0] >> 3) & 0b0010000);
        let second_rot = (second_half << 1) | (key[4] >> 7);
        out.push(first_rot | second_rot);

        for i in 4..6 {
            let byte = key[i];
            out.push((byte << 1) | (key[i + 1] >> 7));
        }

        out.push((key[6] << 1) | ((key[3] >> 3) & 1));

        out
    }

    /// Perform permuted choice 2 to derive a round subkey.
    pub fn permuted_choice_2(&self, round_num: u32) -> Bytes {
        const PC2_MAPPING: [usize; 48] = [
            13, 16, 10, 23, 0, 4, 2, 27,
            14, 5, 20, 9, 22, 18, 11, 3,
            25, 7, 15, 6, 26, 19, 12, 1,
            40, 51, 30, 36, 46, 54, 29, 39,
            50, 44, 32, 47, 43, 48, 38, 55,
            33, 52, 45, 41, 49, 35, 28, 31,
        ];

        let mut subkey = self.rotate_key_left(&self.key_cur);

        for i in 1..(round_num + 1) {
            if ![1, 8, 15].contains(&i) {
                subkey = self.rotate_key_left(&subkey);
            }
            subkey = self.rotate_key_left(&subkey);
        }

        self.map_bits(&mut subkey, &PC2_MAPPING);
        subkey
    }

    /// Expand the right hand side, for use in the round function.
    pub fn half_block_expansion(&self, rhs: &mut Bytes) {
        const EXPANSION_MAPPING: [usize; 48] = [
            31, 0, 1, 2, 3, 4, 3, 4,
            5, 6, 7, 8, 7, 8, 9, 10,
            11, 12, 11, 12, 13, 14, 15, 16,
            15, 16, 17, 18, 19, 20, 19, 20,
            21, 22, 23, 24, 23, 24, 25, 26,
            27, 28, 27, 28, 29, 30, 31, 0,
        ];

        self.map_bits(rhs, &EXPANSION_MAPPING)
    }

    /// Splits 6 8-bit bytes into 8 6-bit bytes.
    pub fn six_byte_split(&self, rhs: &Bytes) -> Bytes {
        let mut cur_byte = 0;
        let mut output = vec![];

        for i in 0..(rhs.len() * 8) {
            let quotient = i / 8;
            let remainder = (i % 8) as u8;

            cur_byte <<= 1;
            cur_byte += self.get_bit(rhs[quotient], remainder);

            if i % 6 == 5 {
                output.push(cur_byte);
                cur_byte = 0;
            }
        }

        output
    }

    /// Applies an S-box to convert a 6-bit byte to a 4-bit byte.
    pub fn apply_s_box(&self, byte: u8, s_box: usize) -> u8 {
        const S_BOXES: [[[u8; 16]; 4]; 8] = [
            [
                // S1
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
            ],
            [
                // S2
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
            ],
            [
                // S3
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
            ],
            [
                // S4
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
            ],
            [
                // S5
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
            ],
            [
                // S6
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
            ],
            [
                // S7
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
            ],
            [
                // S8
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
            ],
        ];

        let row = (byte & 1) | ((byte >> 4) & 0b10);
        let column = (byte & 0b011110) >> 1;

        S_BOXES[s_box][row as usize][column as usize]
    }

    /// Apply permutation at the end of the round function.
    pub fn apply_p_box(&self, rhs: &mut Bytes) {
        const P_BOX: [usize; 32] = [
            15, 6, 19, 20, 28, 11, 27, 16,
            0, 14, 22, 25, 4, 17, 30, 9,
            1, 7, 23, 13, 31, 26, 2, 8,
            18, 12, 29, 5, 21, 10, 3, 24,
        ];

        self.map_bits(rhs, &P_BOX);
    }
}

impl FeistelCipher for DESBlock {
    fn get_num_rounds(&mut self, _msg: &Bytes) -> u32 {
        16
    }

    fn get_block_size(&mut self, _msg: &Bytes) -> usize {
        8
    }

    fn derive_round_subkey(&mut self, round_num: u32) -> FeistelResult<Bytes> {
        Ok(self.permuted_choice_2(round_num))
    }

    fn round_function(&mut self, rhs: &Bytes, subkey: &Bytes, _: u32) -> FeistelResult<Bytes> {
        let mut rhs = rhs.clone();

        self.half_block_expansion(&mut rhs);
        let xor_res = rhs.xor(subkey).unwrap();
        let split = self.six_byte_split(&xor_res);

        let mut substituted = vec![];
        for i in 0..8 {
            let byte = self.apply_s_box(split[i], i);
            if i % 2 == 0 {
                substituted.push(byte << 4);
            } else {
                substituted[(i - 1) / 2] |= byte;
            }
        }

        self.apply_p_box(&mut substituted);
        Ok(substituted)
    }

    fn pre_encrypt_block(&mut self, plaintext: &mut Bytes) {
        self.key_cur = self.key.clone();
        self.initial_permutation(plaintext);
        self.permuted_choice_1();
    }

    fn post_encrypt_block(&mut self, ciphertext: &mut Bytes) {
        self.final_permutation(ciphertext);
    }

    fn is_valid_plaintext_block(&mut self, plaintext: &Bytes) -> FeistelResult<()> {
        // DES has a block size & key length of 64 bits = 8 * 8 bytes
        if plaintext.len() != 8 {
            let err = String::from("block must be 64 bits");
            Err(FeistelCipherError::InvalidBlock(Some(err)))
        } else if self.key.len() != 8 {
            let err = String::from("key must be 64 bits");
            Err(FeistelCipherError::InvalidKey(Some(err)))
        } else {
            Ok(())
        }
    }

    fn split_plaintext(&mut self, plaintext: &Bytes) -> (Bytes, Bytes) {
        let mut lhs = vec![0, 0, 0, 0];
        let mut rhs = vec![0, 0, 0, 0];
        lhs.copy_from_slice(&plaintext[0..4]);
        rhs.copy_from_slice(&plaintext[4..8]);
        (lhs, rhs)
    }

    fn is_valid_ciphertext_block(&mut self, ciphertext: &Bytes) -> FeistelResult<()> {
        self.is_valid_plaintext_block(ciphertext)
    }

    fn split_ciphertext(&mut self, ciphertext: &Bytes) -> (Bytes, Bytes) {
        self.split_plaintext(ciphertext)
    }
}
