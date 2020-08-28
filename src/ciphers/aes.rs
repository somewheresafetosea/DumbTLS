//! Implementation of AES-128.
//!
//! AES was developed as the result of a competition by NIST to produce a
//! replacement to DES. Originally published by Vincent Rijmen and Joan Daemen
//! in 1999 as Rijndael, NIST ratified it as being the Advanced Encryption
//! Standard in 2001. AES is a block cipher, and uses a block size of 128 bits
//! (= 16 bytes). It may use a key size of 128, 192, or 256 bits (= 16, 24, or
//! 32 bytes), corresponding to to the designations AES-128, AES-192, and
//! AES-256 respectively. AES uses either 10, 12, or 14 bits, corresponding to
//! the increasing key sizes. AES is regarded as suitable for the majority of
//! modern cryptographic applications where a symmetric block cipher is
//! required, and finds widespread usage in TLS, SSH, and many other secure
//! protocols. This is in part due to the fact that modern x86 processors
//! include specific instructions for encryption/decryption with AES, which make
//! it one of the most perfomant algorithms available.
//!
//! Due to time constraints, I was unfortunately only able to implement AES-128,
//! however I plan to implement AES-192 and AES-256 in the future, and the
//! software is designed to be fairly easily extensible.
//!
//! The design of AES relies heavily on Galois Field arithmetic: Briefly, a
//! field is a (mathematical) set of elements, on which addition, subtraction,
//! multiplication, and inversion are all defined and closed (the result of the
//! operation is another element within the field). A Galois Field is a field
//! which only has a finite number of elements. As such, the field operations
//! must often be done modulo some element of the field, for closure to be
//! retained. For prime fields (Galois fields where the number of elements is
//! prime) this is simple: One just performs the operation modulo the size of
//! the field. For extension fields (Galois fields where the number of elements
//! is a prime to a certain power) this is not so simple. One must treat each
//! element as a polynomial, and take the operations modulo some irreducible
//! polynomial. AES works on the prime extension field $GF(2^8)$, and defines a
//! single irreducible polynomial (the AES polynomial) which operators are
//! performed modulo: $p(x) = x^8 + x^4 + x^3 + x + 1$. Christof Paar's [Lecture
//! on Galois Fields](https://www.youtube.com/watch?v=x1v2tX4_dkQ) explains this
//! in more depth.
//!
//! Unlike DES, AES does not use a Feistel network design. Instead, each layer
//! of encryption is actually inverted, and applied in reverse, in order to
//! decrypt. When encrypting text with AES, the message is first Xor'd with the
//! original key. Then, 10 rounds of encryption are applied, with the following
//! steps being conducted in each round:
//!
//! 1. **Byte Substitution**: The Byte Susbstitution layer applies an S-Box to
//! each byte of the input. This provides confusion, and introduces
//! non-linearity to AES. Unlike with DES, the design of the AES S-Box is
//! actually public, and is based in very specific algebra. The S-Box works as
//! follows: First, the input is inverted in the Galois field $GF(2^8)$, using
//! the AES polynomial. This inversion is defined for all elements except the
//! zero byte, so this is instead simply mapped to itself. Using Galois field
//! inversion provides a high degree of non-linearity, however, it has a strong
//! algebraic structure, which could be used in cryptanalysis. Because of this,
//! an affine mapping is then applied to the output of the inversion, which
//! prevents this structure from being used. In the majority of implementations
//! of AES, since one byte may only have 256 possible values, all possible
//! mappings are pre-calculated and hardcoded, rather than calculating
//! substitutions on the fly.
//! 2. **Diffusion**: Two layers of diffusion are used within AES:
//!     1. **Shift Rows**: The order of the bytes is altered: The message is
//!        split into 4-byte words, then bytes are moved between words such that
//!        each final word contains one byte from each original word.
//!     2. **Mix Columns**: Each word is multiplied by a matrix of polynomials
//!        in $GF(2^8)$. In practise, this is implemented via a set of look-up
//!        tables.
//! 3. **Key Addition**: A round subkey is derived from the original key, and
//!    the message is Xor'd with it.
//!
//! To decrypt AES, the inverse of each operation is applied in reverse order.
//!
//! # Example usage
//! ``` rust
//! use dumbtls::bytes::Bytes;
//! use dumbtls::ciphers::block::{BlockCipher, CBCMode};
//! use dumbtls::ciphers::aes::{AES, AESKey, AESKeysize};
//! use dumbtls::encoding::hex::{FromHex, ToHex};
//! use dumbtls::keygen;
//! use dumbtls::padding::PKCS7;
//! 
//! fn main() {
//!     // Encrypting a single block:
//!     let key = keygen::gen_key_aes(AESKeysize::Key128Bit);
//!     println!("Key: {}", match &key {
//!         AESKey::Key128Bit(k) => k.to_hex(),
//!     });
//!     let mut cipher = AES::new(&key);
//!     let plaintext = Bytes::from_hex("00112233445566778899aabbccddeeff").unwrap();
//!     println!("Plaintext: {}", plaintext.to_hex());
//!     let ciphertext = cipher.encrypt_block(plaintext).unwrap();
//!     println!("Ciphertext: {}", ciphertext.to_hex());
//!     let plaintext = cipher.decrypt_block(ciphertext).unwrap();
//!     println!("Decrypted Ciphertext: {}", plaintext.to_hex());
//!     // Example output:
//!     // Key: 53b1c6e417f237855289fbe6a49b91a3
//!     // Plaintext: 00112233445566778899aabbccddeeff
//!     // Ciphertext: 489d00143440107f7b7768228eae98ff
//!     // Decrypted Ciphertext: 00112233445566778899aabbccddeeff
//!      
//!     // Using CBC mode to encrypt an arbitrary-length message:
//!     let key = keygen::gen_key_aes(AESKeysize::Key128Bit);
//!     let iv = keygen::gen_aes_iv();
//!     println!("Key: {}", match &key {
//!         AESKey::Key128Bit(k) => k.to_hex(),
//!     });
//!     println!("IV: {}", iv.to_hex());
//!     let cipher = AES::new(&key);
//!     let padding = PKCS7 { };
//!     let mut cbc = CBCMode::with_padding(cipher, padding);
//!     // n.b: Plaintext is no longer a multiple of the block size
//!     let plaintext = Bytes::from_hex("00112233445566778899aabbccddeeffcafebabe").unwrap();
//!     println!("Plaintext: {}", plaintext.to_hex());
//!     let ciphertext = cbc.encrypt(&plaintext, &iv).unwrap();
//!     println!("Ciphertext: {}", ciphertext.to_hex());
//!     let plaintext = cbc.decrypt(&ciphertext, &iv).unwrap();
//!     println!("Decrypted Ciphertext: {}", plaintext.to_hex());
//!     // Example output:
//!     // Key: f254592613b11eef615a2d0419ce83d1
//!     // IV: 325544bd7add0817862daf2c0b914ff1
//!     // Plaintext: 00112233445566778899aabbccddeeffcafebabe
//!     // Ciphertext: f583b3775bad1eaa6d29ae9fc4a7e8eac85fc47af9ecc25916294385e2af86ac
//!     // Decrypted Ciphertext: 00112233445566778899aabbccddeeffcafebabe
//! }
//! ```
use crate::bytes::{Bytes, SequenceXor};
use crate::ciphers::block::BlockCipher;

/// Error encountered during AES encryption/decryption.
#[derive(Clone, Copy, Debug)]
pub enum AESError {
    /// Returned if the block to be encrypted is not 16 bytes.
    IncorrectBlocksize,
}

/// Represents possible keysizes for use with AES.
///
/// Ideally, in the future, this will also include 192 and 256-bit AES, but for
/// the time being, only 128-bit AES is implemented.
#[derive(Clone, Copy, Debug)]
pub enum AESKeysize {
    Key128Bit,
}

/// Contains an AES key.
///
/// Ideally, in the future, this will also include 192 and 256-bit AES, but for
/// the time being, only 128-bit AES is implemented.
#[derive(Clone, Debug)]
pub enum AESKey {
    Key128Bit(Bytes),
}

/// Converts a keysize to the length a key of that keysize should be, in bytes.
pub fn keysize_to_len(keysize: AESKeysize) -> usize {
    match keysize {
        AESKeysize::Key128Bit => 16,
    }
}

/// Converts a key to the length it should be, in bytes.
pub fn key_to_len(key: AESKey) -> usize {
    let size = match key {
        AESKey::Key128Bit(_) => AESKeysize::Key128Bit,
    };

    keysize_to_len(size)
}

type AESResult<T> = Result<T, AESError>;

/// The AES Cipher.
pub struct AES {
    pub key: AESKey,
}

impl AES {
    const BLOCK_SIZE: usize = 16;

    pub fn new(key: &AESKey) -> AES {
        AES {
            key: key.clone(),
        }
    }

    /// Get the number of rounds of encryption/decryption to perform.
    ///
    /// This varies for different keysizes, so it won't be a constant in the
    /// future, although for the time being (as AES-128 is the only implemented
    /// keysize) it always returns 10.
    pub fn get_num_rounds(&self) -> usize {
        match self.key {
            AESKey::Key128Bit(_) => 10,
        }
    }

    /// Apply the AES S-Box to `byte`.
    ///
    /// This function performs substitution on a single byte, as part of the
    /// AES Byte Substitution layer. Internally, it works using a simple look-up
    /// table, which is pre-calculated by taking all values from 0 to 255,
    /// inverting them within $GF(2^8)$, and then applying the affine mapping.
    pub fn s_box(&self, byte: u8) -> u8 {
        const S_BOX: [u8; 256] = [
            99,  124, 119, 123, 242, 107, 111, 197, 48,  1,   103, 43,  254, 215, 171, 118,
            202, 130, 201, 125, 250, 89,  71,  240, 173, 212, 162, 175, 156, 164, 114, 192,
            183, 253, 147, 38,  54,  63,  247, 204, 52,  165, 229, 241, 113, 216, 49,  21,
            4,   199, 35,  195, 24,  150, 5,   154, 7,   18,  128, 226, 235, 39,  178, 117,
            9,   131, 44,  26,  27,  110, 90,  160, 82,  59,  214, 179, 41,  227, 47,  132,
            83,  209, 0,   237, 32,  252, 177, 91,  106, 203, 190, 57,  74,  76,  88,  207,
            208, 239, 170, 251, 67,  77,  51,  133, 69,  249, 2,   127, 80,  60,  159, 168,
            81,  163, 64,  143, 146, 157, 56,  245, 188, 182, 218, 33,  16,  255, 243, 210,
            205, 12,  19,  236, 95,  151, 68,  23,  196, 167, 126, 61,  100, 93,  25,  115,
            96,  129, 79,  220, 34,  42,  144, 136, 70,  238, 184, 20,  222, 94,  11,  219,
            224, 50,  58,  10,  73,  6,   36,  92,  194, 211, 172, 98,  145, 149, 228, 121,
            231, 200, 55,  109, 141, 213, 78,  169, 108, 86,  244, 234, 101, 122, 174, 8,
            186, 120, 37,  46,  28,  166, 180, 198, 232, 221, 116, 31,  75,  189, 139, 138,
            112, 62,  181, 102, 72,  3,   246, 14,  97,  53,  87,  185, 134, 193, 29,  158,
            225, 248, 152, 17,  105, 217, 142, 148, 155, 30,  135, 233, 206, 85,  40,  223,
            140, 161, 137, 13,  191, 230, 66,  104, 65,  153, 45,  15,  176, 84,  187, 22,
        ];
        S_BOX[byte as usize]
    }

    /// Apply the AES Byte Substitution layer.
    ///
    /// Applies the `s_box` method to each byte of the input.
    pub fn byte_substitution(&self, bytes: Bytes) -> Bytes {
        bytes.iter().map(|&byte| self.s_box(byte)).collect()
    }

    /// Apply the AES inverse S-Box to `byte`.
    ///
    /// This function performs substitution on a single byte, as part of the
    /// AES Inverse Byte Substitution Layer. The AES S-Box is bijective, so
    /// there exists an inverse S-Box. This is constructed by first inverting
    /// the affine mapping, and then inverting the $GF(2^8)$ inversion. Once
    /// again, these values are pre-calculated, and a look-up-table is used to
    /// apply the inverse S-box.
    fn inverse_s_box(&self, byte: u8) -> u8 {
        const INV_S_BOX: [u8; 256] = [
            82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
            124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
            84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
            8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
            114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
            108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
            144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
            208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
            58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
            150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
            71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
            252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
            31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
            96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
            160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
            23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
        ];
        INV_S_BOX[byte as usize]
    }

    /// Apply the AES Inverse Byte Substitution layer.
    ///
    /// Applies the `inverse_s_box` method to each byte of the input.
    pub fn inverse_byte_substitution(&self, bytes: Bytes) -> Bytes {
        bytes.iter().map(|&byte| self.inverse_s_box(byte)).collect()
    }

    /// Apply the AES Shift Rows layer.
    pub fn shift_rows(&self, bytes: Bytes) -> Bytes {
        let mut output = vec![];

        for i in 0..16 {
            output.push(bytes[(5 * i) % 16]);
        }

        output
    }

    /// Apply the AES Inverse Shift Rows layer.
    fn inverse_shift_rows(&self, bytes: Bytes) -> Bytes {
        let mut output = vec![];

        for i in 0..16 {
            let index = (((-3 * i) % 16) + 16) % 16;
            output.push(bytes[index as usize]);
        }

        output
    }

    /// Multiply a polynomial by $x$ in $GF(2^8)$.
    ///
    /// Takes a representation of a polynomial within $GF(2^8)$, multiplies it
    /// by $x$, then reduces the result modulo the AES polynomial,
    /// $p(x) = x^8 + x^4 + x^3 + x + 1$.
    pub fn poly_mult_2(&self, polynomial: u8) -> u8 {
        const MAP: [u8; 256] = [
            0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
            32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
            64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
            96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126,
            128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158,
            160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190,
            192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222,
            224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254,
            27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5,
            59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
            91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
            123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101,
            155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133,
            187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165,
            219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197,
            251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229,
        ];

        MAP[polynomial as usize]
    }

    /// Multiply a polynomial by $x + 1$ in $GF(2^8)$.
    ///
    /// Takes a representation of a polynomial within $GF(2^8)$, multiplies it
    /// by $x + 1$, then reduces the result modulo the AES polynomial,
    /// $p(x) = x^8 + x^4 + x^3 + x + 1$.
    pub fn poly_mult_3(&self, polynomial: u8) -> u8 {
        const MAP: [u8; 256] = [
            0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17,
            48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33,
            96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113,
            80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65,
            192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209,
            240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225,
            160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177,
            144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129,
            155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138,
            171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186,
            251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234,
            203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218,
            91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74,
            107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122,
            59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42,
            11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26,
        ];

        MAP[polynomial as usize]
    }

    /// Multiply a polynomial by $x^3 + 1$ in $GF(2^8)$.
    ///
    /// Takes a representation of a polynomial within $GF(2^8)$, multiplies it
    /// by $x^3 + 1$, then reduces the result modulo the AES polynomial,
    /// $p(x) = x^8 + x^4 + x^3 + x + 1$.
    pub fn poly_mult_9(&self, polynomial: u8) -> u8 {
        const MAP: [u8; 256] = [
            0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119,
            144, 153, 130, 139, 180, 189, 166, 175, 216, 209, 202, 195, 252, 245, 238, 231,
            59, 50, 41, 32, 31, 22, 13, 4, 115, 122, 97, 104, 87, 94, 69, 76,
            171, 162, 185, 176, 143, 134, 157, 148, 227, 234, 241, 248, 199, 206, 213, 220,
            118, 127, 100, 109, 82, 91, 64, 73, 62, 55, 44, 37, 26, 19, 8, 1,
            230, 239, 244, 253, 194, 203, 208, 217, 174, 167, 188, 181, 138, 131, 152, 145,
            77, 68, 95, 86, 105, 96, 123, 114, 5, 12, 23, 30, 33, 40, 51, 58,
            221, 212, 207, 198, 249, 240, 235, 226, 149, 156, 135, 142, 177, 184, 163, 170,
            236, 229, 254, 247, 200, 193, 218, 211, 164, 173, 182, 191, 128, 137, 146, 155,
            124, 117, 110, 103, 88, 81, 74, 67, 52, 61, 38, 47, 16, 25, 2, 11,
            215, 222, 197, 204, 243, 250, 225, 232, 159, 150, 141, 132, 187, 178, 169, 160,
            71, 78, 85, 92, 99, 106, 113, 120, 15, 6, 29, 20, 43, 34, 57, 48,
            154, 147, 136, 129, 190, 183, 172, 165, 210, 219, 192, 201, 246, 255, 228, 237,
            10, 3, 24, 17, 46, 39, 60, 53, 66, 75, 80, 89, 102, 111, 116, 125,
            161, 168, 179, 186, 133, 140, 151, 158, 233, 224, 251, 242, 205, 196, 223, 214,
            49, 56, 35, 42, 21, 28, 7, 14, 121, 112, 107, 98, 93, 84, 79, 70,
        ];

        MAP[polynomial as usize]
    }

    /// Multiply a polynomial by $x^3 + x + 1$ in $GF(2^8)$.
    ///
    /// Takes a representation of a polynomial within $GF(2^8)$, multiplies it
    /// by $x^3 + x + 1$, then reduces the result modulo the AES polynomial,
    /// $p(x) = x^8 + x^4 + x^3 + x + 1$.
    pub fn poly_mult_b(&self, polynomial: u8) -> u8 {
        const MAP: [u8; 256] = [
            0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69, 116, 127, 98, 105,
            176, 187, 166, 173, 156, 151, 138, 129, 232, 227, 254, 245, 196, 207, 210, 217,
            123, 112, 109, 102, 87, 92, 65, 74, 35, 40, 53, 62, 15, 4, 25, 18,
            203, 192, 221, 214, 231, 236, 241, 250, 147, 152, 133, 142, 191, 180, 169, 162,
            246, 253, 224, 235, 218, 209, 204, 199, 174, 165, 184, 179, 130, 137, 148, 159,
            70, 77, 80, 91, 106, 97, 124, 119, 30, 21, 8, 3, 50, 57, 36, 47,
            141, 134, 155, 144, 161, 170, 183, 188, 213, 222, 195, 200, 249, 242, 239, 228,
            61, 54, 43, 32, 17, 26, 7, 12, 101, 110, 115, 120, 73, 66, 95, 84,
            247, 252, 225, 234, 219, 208, 205, 198, 175, 164, 185, 178, 131, 136, 149, 158,
            71, 76, 81, 90, 107, 96, 125, 118, 31, 20, 9, 2, 51, 56, 37, 46,
            140, 135, 154, 145, 160, 171, 182, 189, 212, 223, 194, 201, 248, 243, 238, 229,
            60, 55, 42, 33, 16, 27, 6, 13, 100, 111, 114, 121, 72, 67, 94, 85,
            1, 10, 23, 28, 45, 38, 59, 48, 89, 82, 79, 68, 117, 126, 99, 104,
            177, 186, 167, 172, 157, 150, 139, 128, 233, 226, 255, 244, 197, 206, 211, 216,
            122, 113, 108, 103, 86, 93, 64, 75, 34, 41, 52, 63, 14, 5, 24, 19,
            202, 193, 220, 215, 230, 237, 240, 251, 146, 153, 132, 143, 190, 181, 168, 163,
        ];

        MAP[polynomial as usize]
    }

    /// Multiply a polynomial by $x^3 + x^2 + 1$ in $GF(2^8)$.
    ///
    /// Takes a representation of a polynomial within $GF(2^8)$, multiplies it
    /// by $x^3 + x^2 + 1$, then reduces the result modulo the AES polynomial,
    /// $p(x) = x^8 + x^4 + x^3 + x + 1$.
    pub fn poly_mult_d(&self, polynomial: u8) -> u8 {
        const MAP: [u8; 256] = [
            0, 13, 26, 23, 52, 57, 46, 35, 104, 101, 114, 127, 92, 81, 70, 75,
            208, 221, 202, 199, 228, 233, 254, 243, 184, 181, 162, 175, 140, 129, 150, 155,
            187, 182, 161, 172, 143, 130, 149, 152, 211, 222, 201, 196, 231, 234, 253, 240,
            107, 102, 113, 124, 95, 82, 69, 72, 3, 14, 25, 20, 55, 58, 45, 32,
            109, 96, 119, 122, 89, 84, 67, 78, 5, 8, 31, 18, 49, 60, 43, 38,
            189, 176, 167, 170, 137, 132, 147, 158, 213, 216, 207, 194, 225, 236, 251, 246,
            214, 219, 204, 193, 226, 239, 248, 245, 190, 179, 164, 169, 138, 135, 144, 157,
            6, 11, 28, 17, 50, 63, 40, 37, 110, 99, 116, 121, 90, 87, 64, 77,
            218, 215, 192, 205, 238, 227, 244, 249, 178, 191, 168, 165, 134, 139, 156, 145,
            10, 7, 16, 29, 62, 51, 36, 41, 98, 111, 120, 117, 86, 91, 76, 65,
            97, 108, 123, 118, 85, 88, 79, 66, 9, 4, 19, 30, 61, 48, 39, 42,
            177, 188, 171, 166, 133, 136, 159, 146, 217, 212, 195, 206, 237, 224, 247, 250,
            183, 186, 173, 160, 131, 142, 153, 148, 223, 210, 197, 200, 235, 230, 241, 252,
            103, 106, 125, 112, 83, 94, 73, 68, 15, 2, 21, 24, 59, 54, 33, 44,
            12, 1, 22, 27, 56, 53, 34, 47, 100, 105, 126, 115, 80, 93, 74, 71,
            220, 209, 198, 203, 232, 229, 242, 255, 180, 185, 174, 163, 128, 141, 154, 151,
        ];

        MAP[polynomial as usize]
    }

    /// Multiply a polynomial by $x^3 + x^2 + x$ in $GF(2^8)$.
    ///
    /// Takes a representation of a polynomial within $GF(2^8)$, multiplies it
    /// by $x^3 + x^2 + x$, then reduces the result modulo the AES polynomial,
    /// $p(x) = x^8 + x^4 + x^3 + x + 1$.
    pub fn poly_mult_e(&self, polynomial: u8) -> u8 {
        const MAP: [u8; 256] = [
            0, 14, 28, 18, 56, 54, 36, 42, 112, 126, 108, 98, 72, 70, 84, 90,
            224, 238, 252, 242, 216, 214, 196, 202, 144, 158, 140, 130, 168, 166, 180, 186,
            219, 213, 199, 201, 227, 237, 255, 241, 171, 165, 183, 185, 147, 157, 143, 129,
            59, 53, 39, 41, 3, 13, 31, 17, 75, 69, 87, 89, 115, 125, 111, 97,
            173, 163, 177, 191, 149, 155, 137, 135, 221, 211, 193, 207, 229, 235, 249, 247,
            77, 67, 81, 95, 117, 123, 105, 103, 61, 51, 33, 47, 5, 11, 25, 23,
            118, 120, 106, 100, 78, 64, 82, 92, 6, 8, 26, 20, 62, 48, 34, 44,
            150, 152, 138, 132, 174, 160, 178, 188, 230, 232, 250, 244, 222, 208, 194, 204,
            65, 79, 93, 83, 121, 119, 101, 107, 49, 63, 45, 35, 9, 7, 21, 27,
            161, 175, 189, 179, 153, 151, 133, 139, 209, 223, 205, 195, 233, 231, 245, 251,
            154, 148, 134, 136, 162, 172, 190, 176, 234, 228, 246, 248, 210, 220, 206, 192,
            122, 116, 102, 104, 66, 76, 94, 80, 10, 4, 22, 24, 50, 60, 46, 32,
            236, 226, 240, 254, 212, 218, 200, 198, 156, 146, 128, 142, 164, 170, 184, 182,
            12, 2, 16, 30, 52, 58, 40, 38, 124, 114, 96, 110, 68, 74, 88, 86,
            55, 57, 43, 37, 15, 1, 19, 29, 71, 73, 91, 85, 127, 113, 99, 109,
            215, 217, 203, 197, 239, 225, 243, 253, 167, 169, 187, 181, 159, 145, 131, 141,
        ];

        MAP[polynomial as usize]
    }

    /// Apply the AES Mix Columns matrix multiplication to a single word (4
    /// bytes).
    fn mix_columns_word(&self, word: Bytes) -> Bytes {
        let mut output = vec![];

        output.push(self.poly_mult_2(word[0]) ^ self.poly_mult_3(word[1]) ^ word[2] ^ word[3]);
        output.push(word[0] ^ self.poly_mult_2(word[1]) ^ self.poly_mult_3(word[2]) ^ word[3]);
        output.push(word[0] ^ word[1] ^ self.poly_mult_2(word[2]) ^ self.poly_mult_3(word[3]));
        output.push(self.poly_mult_3(word[0]) ^ word[1] ^ word[2] ^ self.poly_mult_2(word[3]));

        output
    }

    /// Apply the AES Mix Columns layer.
    pub fn mix_columns(&self, bytes: Bytes) -> Bytes {
        let mut output = vec![];

        for i in 0..4 {
            let mut word = vec![0; 4];
            word.copy_from_slice(&bytes[4 * i..4 * (i + 1)]);
            output.append(&mut self.mix_columns_word(word));
        }

        output
    }


    /// Apply the AES Inverse Mix Columns matrix multiplication to a single
    /// word (4 bytes).
    fn inverse_mix_columns_word(&self, word: Bytes) -> Bytes {
        let mut output = vec![];

        output.push(self.poly_mult_e(word[0]) ^ self.poly_mult_b(word[1]) ^ self.poly_mult_d(word[2]) ^ self.poly_mult_9(word[3]));
        output.push(self.poly_mult_9(word[0]) ^ self.poly_mult_e(word[1]) ^ self.poly_mult_b(word[2]) ^ self.poly_mult_d(word[3]));
        output.push(self.poly_mult_d(word[0]) ^ self.poly_mult_9(word[1]) ^ self.poly_mult_e(word[2]) ^ self.poly_mult_b(word[3]));
        output.push(self.poly_mult_b(word[0]) ^ self.poly_mult_d(word[1]) ^ self.poly_mult_9(word[2]) ^ self.poly_mult_e(word[3]));

        output
    }

    /// Apply the AES Inverse Mix Columns layer.
    pub fn inverse_mix_columns(&self, bytes: Bytes) -> Bytes {
        let mut output = vec![];

        for i in 0..4 {
            let mut word = vec![0; 4];
            word.copy_from_slice(&bytes[4 * i..4 * (i + 1)]);
            output.append(&mut self.inverse_mix_columns_word(word));
        }

        output
    }

    /// Get the AES Round Constant.
    ///
    /// The Round Constant (RC) is used within the AES key schedule to alter the
    /// derived key further for each round.
    pub fn get_round_constant(&self, round_num: usize) -> u8 {
        if round_num <= 8 {
            1 << (round_num - 1)
        } else {
            match round_num {
                9 => 0x1b,
                10 => 0x36,
                _ => 0,
            }
        }
    }

    /// Apply the AES Key Schedule Round Function.
    ///
    /// The AES key schedule round function involves simply rotating the bytes
    /// left by one place, then applying the standard AES S-Box to each byte,
    /// before Xor'ing the first byte with the round constant.
    pub fn key_schedule_round_function(&self, word: &[u8], round_num: usize) -> Bytes {
        let mut intermediate = vec![];
        for i in 0..4 {
            intermediate.push(word[(i + 1) % 4]);
        }

        let mut output = vec![];
        intermediate = intermediate.iter().map(|&byte| self.s_box(byte)).collect();
        output.append(&mut intermediate);
        output[0] ^= self.get_round_constant(round_num);
        output
    }

    /// Generate the AES Key Schedule for the number of required rounds.
    ///
    /// The AES Key Schedule works as follows: First, the key is split into four
    /// 4-byte words. For each round, the final word is then run through the
    /// round function, and the result is Xor'd with the first word to become
    /// the first output word. This result is then Xor'd with the second word
    /// to become the second output word, and this with the third, and so on.
    #[allow(unreachable_patterns)]
    pub fn generate_key_schedule(&self) -> Vec<Bytes> {
        let mut output = vec![];

        let mut round_key = match &self.key {
            AESKey::Key128Bit(k) => k.clone(),
            _ => panic!("unreachable"),
        };

        output.push(round_key.clone());

        for i in 1..11 {
            let mut buf: Vec<Bytes> = vec![];
            let mut prev = self.key_schedule_round_function(&round_key[12..16], i);

            for j in 0..4 {
                buf.push(vec![0; 4]);
                buf[j].copy_from_slice(&round_key[(j * 4)..((j + 1) * 4)]);
                buf[j] = buf[j].xor(&prev).unwrap();
                prev = buf[j].clone();
            }

            round_key.truncate(0);
            for j in 0..4 {
                round_key.append(&mut buf[j]);
            }
            output.push(round_key.clone());
        }

        output
    }
}

impl BlockCipher for AES {
    type Error = AESError;

    fn get_block_size(&mut self, _msg: &Bytes) -> usize {
        AES::BLOCK_SIZE
    }

    fn encrypt_block(&mut self, plaintext: Bytes) -> AESResult<Bytes> {
        if plaintext.len() != AES::BLOCK_SIZE {
            return Err(AESError::IncorrectBlocksize);
        }

        let key_schedule = self.generate_key_schedule();
        let nr = self.get_num_rounds();
        let mut intermediate = plaintext.xor(&key_schedule[0]).unwrap();

        for i in 0..nr {
            // Confusion layer: Byte substitution
            intermediate = self.byte_substitution(intermediate);

            // Diffusion layer: Shift rows & mix columns
            intermediate = self.shift_rows(intermediate);
            if i != nr - 1 {
                // We don't mix columns on the final round, since it would have
                // no security benefit
                intermediate = self.mix_columns(intermediate);
            }

            // Encryption layer: XOR with the current round key
            intermediate = intermediate.xor(&key_schedule[i + 1]).unwrap();
        }

        Ok(intermediate)
    }

    fn decrypt_block(&mut self, ciphertext: Bytes) -> AESResult<Bytes> {
        if ciphertext.len() != AES::BLOCK_SIZE {
            return Err(AESError::IncorrectBlocksize);
        }

        let key_schedule = self.generate_key_schedule();
        let nr = self.get_num_rounds();
        let mut intermediate = ciphertext;

        for i in (0..nr).rev() {
            intermediate = intermediate.xor(&key_schedule[i + 1]).unwrap();

            if i != nr - 1 {
                intermediate = self.inverse_mix_columns(intermediate);
            }
            intermediate = self.inverse_shift_rows(intermediate);

            intermediate = self.inverse_byte_substitution(intermediate);
        }

        Ok(intermediate.xor(&key_schedule[0]).unwrap())
    }
}
