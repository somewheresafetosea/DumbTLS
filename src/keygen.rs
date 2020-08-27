//! Functions for generating keys for use in ciphers.
//!
//! Different ciphers have different requirements as to the keys they use for
//! encryption/decryption. This module is intended to provide utilities for
//! generating (cryptographically secure) pseudo-random keys for use with the
//! ciphers implemented in DumbTLS.
//!
//! The random-number generation used in this module is implemented within the
//! [rand crate](https://crates.io/crates/rand), which uses the Operating
//! System's entropy pool to seed a CSPRNG (Cryptographically Secure
//! Pseudo-Random Number Generator).

use rand::{thread_rng, RngCore, Rng};
use rug::{Integer, integer::IsPrime};
use crate::bytes::Bytes;
use crate::encoding::hex::ToHex;
use crate::ciphers::rsa::{RSAPublicKey, RSAPrivateKey, RSAKeypair, RSAKeysize, keysize_map};
use crate::ciphers::aes::{AESKey, AESKeysize, keysize_to_len as aes_keysize_to_len};

pub fn gen_key_des() -> Bytes {
    let mut out = vec![0; 8];
    thread_rng().fill_bytes(&mut out);
    out
}

pub fn gen_key_aes(size: AESKeysize) -> AESKey {
    let mut out = vec![0; aes_keysize_to_len(size)];
    thread_rng().fill_bytes(&mut out);
    match size {
        AESKeysize::Key128Bit => AESKey::Key128Bit(out),
    }
}

fn gen_odd(num_bytes: usize) -> Integer {
    let mut bytes: Bytes = vec![0; num_bytes];
    thread_rng().fill_bytes(&mut bytes);
    bytes[num_bytes - 1] |= 1;
    let hex_rep = bytes.to_hex();
    Integer::from_str_radix(&hex_rep, 16).unwrap()
}

fn gen_prime(num_bytes: usize) -> Integer {
    let mut possible_prime = gen_odd(num_bytes);
    // Rug uses a combination of trial divisions, a Baille-PSW probable prime
    // test, and Miller-Rabin probabilistic primality tests to determine whether
    // an integer is likely prime. It will perform the argument - 24
    // Miller-Rabin rounds, and we wish to perform 40 (at which point the
    // probability of the test being wrong is lower than the probability of
    // random hardware failure), so the argument is 40 + 24 = 64.
    while let IsPrime::No = possible_prime.is_probably_prime(64) {
        possible_prime += 2;
    }
    
    possible_prime
}

pub fn gen_key_rsa(size: RSAKeysize) -> RSAKeypair {
    const RSA_PUBLIC_EXPONENT: u32 = 65537;

    let num_bytes = keysize_map(&size) / 2;
    let diff_num_bytes = rand::thread_rng().gen_range(1, 6);
    let mut p = Integer::from(0);
    let mut q = Integer::from(0);
    let mut lambda = Integer::from(RSA_PUBLIC_EXPONENT);

    while Integer::from(RSA_PUBLIC_EXPONENT).gcd(&lambda) != 1 {
        p = gen_prime(num_bytes + diff_num_bytes);
        q = gen_prime(num_bytes - diff_num_bytes);
        // Carmichael's totient function: Generally produces smaller modulus than
        // Euler's totient function, still works for RSA
        lambda = (&p - Integer::from(1)).lcm(&(&q - Integer::from(1)));
    }

    let n = p * q;
    let e = Integer::from(RSA_PUBLIC_EXPONENT);
    let d = e.invert(&lambda).unwrap();

    RSAKeypair {
        public: RSAPublicKey {
            n: n.clone(),
            e: Integer::from(RSA_PUBLIC_EXPONENT),
            size: size,
        },
        private: RSAPrivateKey {
            n: n.clone(),
            d: d.clone(),
            size: size,
        }
    }
}
