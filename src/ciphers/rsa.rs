//! RSA encryption/decryption primitives.
//!
//! This module implements the data conversion and cryptographic primitives for
//! RSA outlined in [PKCS #1](https://tools.ietf.org/html/rfc8017). Textbook
//! RSA, as implemented in this module, is **not suitable for cryptographic
//! use.** See the [OAEP module](../oaep/index.html) for an implementation of
//! Optimal Asymmetric Encryption Padding (RSAES-OAEP) according to PKCS #1.
//! OAEP is designed to make textbook RSA safe for use in real-world encryption.
//!
//! RSA is one of the most important ciphers ever developed. Originally
//! developed by Clifford Cocks of GCHQ (and kept secret), then later
//! independently developed and publicly released by Rivest, Shamir, and
//! Adleman; RSA is believed to be the first public key asymmetric cryptosystem
//! to have ever been developed, and was certainly the first to be publicly
//! released. While RSA is now less used, in favour of elliptic curve
//! cryptography, it laid the groundwork for many cryptosystems we rely on every
//! day in the modern age, and is still supported in many cryptographic systems.
//!
//! RSA's security relies on the difficulty of finding the prime factors of
//! large numbers. This is a well known problem in computational number theory:
//! For certain semi-primes (the product of two prime numbers), where each of
//! the two prime factors is sufficiently large, it is computationally
//! infeasible to factor this number (no polynomial-time algorithm exists).
//!
//! To understand RSA, it is necessary to have some background in number theory,
//! specifically in modular arithmetic: [Khan Academy's Modular Arithmetic
//! Course](https://bit.ly/3hvHegs) is more than sufficient to understand all
//! that is necessary for RSA. It is also necessary to be familiar with Euler's
//! Totient Function, $\phi(n): \mathbb{N} \mapsto \mathbb{N}$. Euler's totient
//! function simply returns the number of integers less than its input which are
//! coprime to that input (i.e: their greatest common denominator with $n$ is
//! 1). From Euler's theory, for $n, a \in \mathbb{N}: \gcd(a, n) = 1$, we have
//! that:
//!
//! $$
//! a^{\phi(n)} \equiv 1 \mod{n}
//! $$
//!
//! We can now begin to understand how the algorithm works. First, two large
//! prime numbers, $p, q$ are chosen, and kept secret. We calculate their
//! product, $n = pq$, which is the first half of the public key, called the
//! *modulus*. It's okay for $n$ to be made public, since there's no efficient
//! way to calculate $p$ or $q$ given $n$. We next calculate $\phi(n)$. This is
//! computationally infeasible given only $n$, but we (helpfully!) also know
//! $n$'s prime factors. For all prime numbers $a, \phi(a) = a - 1$, since all
//! numbers less than a prime are coprime to it. Furthermore, for $d = \gcd(a,
//! b), \phi(ab) = \phi(a) \cdot \phi(b) \cdot \frac{d}{\phi(d)}$. We know that
//! $n = pq$, so (since the gcd of two primes is always 1):
//!
//! $$
//! \begin{aligned}
//! \phi(n) & = \phi(p) \cdot \phi(q) \cdot \frac{\gcd(p, q)}{\phi(\gcd(p, q))} \\\\
//! & = \phi(p) \cdot \phi(q) \\\\
//! & = (p - 1) \cdot (q - 1)
//! \end{aligned}
//! $$
//!
//! It is important that this value is kept secret. We now choose the *public
//! exponent*, $e$, an integer that constitutes the second half of the public
//! key. The public exponent is chosen such that it is relatively prime to
//! $\phi(n)$. In practice, we normally set the public exponent to a fixed
//! value, and then choose primes such that $\gcd(e, \phi(n)) = 1$, rather than
//! choosing the primes first.
//!
//! Having selected $e$, we calculate its modular inverse: $d = e^{-1} \mod
//! \phi(n)$, so $de \equiv 1 \mod \phi(n)$. This was why $e$ had to be coprime
//! to $\phi(n)$: The modular inverse only exists if $e$ and $\phi(n)$ are
//! coprime. $d$ is called the *private exponent*, and together with $n$, makes
//! up the private key. We now have everything necessary to conduct RSA.
//!
//! The actual RSA algorithm operates on integers, not bytes. The RSA standards
//! define an algorithm for converting a byte string to an integer, which we
//! will not cover here, but is implemeneted within this module. To encrypt a
//! message $m \in \mathbb{N}$ with the public key, simply calculate $c = m^e
//! \mod n$. (n.b: $m$ must be less than $n$, and $m^e$ must be greater than $n$).
//! $c$ is the ciphertext, and may be released publicly. Due to the discrete
//! logarithm problem, $m$ cannot be recovered from $c$, without the use of the
//! private key. To decrypt, simply compute $m = c^d \mod n$.
//!
//! Why does this work? Recall Euler's theorem: $a^{\phi(n)} \equiv 1 \mod{n}$.
//! We know that $de \equiv 1 (\mod \phi(n))$, which can also be written as
//! $de = k \cdot \phi(n) + 1$ for some $k \in \mathbb{N}$. So,
//! $m^{de} = m^{k \cdot \phi(n) + 1}$ for some $k$. Now:
//!
//! $$
//! \begin{aligned}
//! m^{k \cdot \phi(n) + 1} & \equiv m \cdot m^{k \cdot \phi(n)} \mod n \\\\
//! & \equiv m \cdot (m^{\phi(n)})^k \mod n \\\\
//! & \equiv m \cdot 1^k \mod n \\\\
//! & \equiv m \mod n
//! \end{aligned}
//! $$
//!
//! Throughout this description, we have ignored an important development in
//! computational number theory which has occured since the development of RSA:
//! quantum computation. [Shor's
//! Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm), invented in
//! 1994, provides a polynomial-time algorithm for factorising integers. While
//! quantum computers are not yet powerful enough to factorise numbers on the
//! scale of those used by RSA, the possibility of RSA's key assumptions being
//! undermined must be a serious consideration for anyone using RSA in the
//! modern age.
use crate::bytes::{Bytes};
use rug::{Integer, ops::Pow};

/// Represents the size of an RSA key.
///
/// This represents the size of the modulus in an RSA key, which tends to be
/// chosen such that it is a power of two, or a low multiple of a power of 2.
/// Key sizes shorter than 2048 bits are no longer considered secure, and should
/// not be used. Ideally, all new implementations of RSA should default to using
/// a 4096-bit modulus, although this may not be feasible for low-power devices.
#[derive(Clone, Copy, Debug)]
pub enum RSAKeysize {
    Key512Bit,
    Key1024Bit,
    Key2048Bit,
    Key3072Bit,
    Key4096Bit,
}

/// Maps RSA keysizes to the length of the modulus, in bytes.
pub fn keysize_map(size: &RSAKeysize) -> usize {
    match size {
        RSAKeysize::Key512Bit => 64,
        RSAKeysize::Key1024Bit => 128,
        RSAKeysize::Key2048Bit => 256,
        RSAKeysize::Key3072Bit => 384,
        RSAKeysize::Key4096Bit => 512,
    }
}

/// Trait for types which contain RSA keys.
///
/// This trait is intentionally generic: It can refer to either a public or
/// private key.
pub trait RSAKey {
    /// Get the (always public) modulus stored in the key.
    fn get_modulus(&self) -> Integer;
    /// Get the (public or private) exponent stored in the key.
    fn get_exponent(&self) -> Integer;
    /// Get the size of the modulus.
    fn get_size(&self) -> RSAKeysize;
    /// Get the size of the modulus, in bytes
    fn get_size_bytes(&self) -> usize;
}

/// Represents an RSA private key.
#[derive(Clone, Debug)]
pub struct RSAPrivateKey {
    pub n: Integer,
    pub d: Integer,
    pub size: RSAKeysize,
}

impl RSAKey for RSAPrivateKey {
    fn get_modulus(&self) -> Integer {
        self.n.clone()
    }

    fn get_exponent(&self) -> Integer {
        self.d.clone()
    }

    fn get_size(&self) -> RSAKeysize {
        self.size.clone()
    }

    fn get_size_bytes(&self) -> usize {
        keysize_map(&self.size)
    }
}

/// Represents an RSA public key.
#[derive(Clone, Debug)]
pub struct RSAPublicKey {
    pub n: Integer,
    pub e: Integer,
    pub size: RSAKeysize,
}

impl RSAKey for RSAPublicKey {
    fn get_modulus(&self) -> Integer {
        self.n.clone()
    }

    fn get_exponent(&self) -> Integer {
        self.e.clone()
    }

    fn get_size(&self) -> RSAKeysize {
        self.size.clone()
    }

    fn get_size_bytes(&self) -> usize {
        keysize_map(&self.size)
    }
}

/// Represents an RSA keypair (public & private).
#[derive(Clone, Debug)]
pub struct RSAKeypair {
    pub public: RSAPublicKey,
    pub private: RSAPrivateKey,
}

/// Errors that can occur while attempting to perform RSA.
///
/// These errors correspond with the error messages defined in PKCS #1.
#[derive(Clone, Debug)]
pub enum RSAError {
    /// Occurs when trying to convert an integer to bytes, and the integer
    /// requires more space than the given length to be stored.
    IntTooLarge,
    /// Occurs if the message is greater than the key modulus.
    MessageOutOfRange,
    /// Occurs if the ciphertext is greater than the key modulus.
    CiphertextOutOfRange,
    /// Occurs if the signature is greater than the key modulus.
    SignatureOutOfRange,
}

pub type RSAResult<T> = Result<T, RSAError>;

/// Convert an integer to a sequence of octets.
///
/// This is an implementation of the I2OSP primitive, as defined in PKCS #1
/// version 2.2. It converts an integer, given by the first parameter, `x`, to
/// an octet string of a length specified by `length`.
///
/// Returns an error if the integer is too large to store in the space specified
/// by the length.
pub fn integer_to_bytes(mut x: Integer, length: u32) -> RSAResult<Bytes> {
    let base = Integer::from(256);
    if x > Integer::from((&base).pow(length)) {
        return Err(RSAError::IntTooLarge);
    }

    let mut output = vec![];
    for i in (0..length).rev() {
        let (quotient, rem) = x.clone().div_rem_floor(Integer::from((&base).pow(i)));
        // None variant is impossible here: The quotient will definitely be less
        // than 256
        output.push(quotient.to_u8().unwrap());
        x = rem;
    }

    Ok(output)
}

/// Convert a sequence of octets to an integer.
///
/// This is an implementation of the OS2IP primitive, as defined in PKCS #1
/// version 2.2. It converts an octet string, given by the `bytes` parameter,
/// to an integer.
pub fn bytes_to_integer(bytes: &Bytes) -> Integer {
    let mut output = Integer::from(0);
    let base = Integer::from(256);
    let len = bytes.len() as u32 - 1;

    for (i, byte) in bytes.into_iter().enumerate() {
        output += Integer::from((&base).pow(len - i as u32)) * byte;
    }

    output
}

/// Encrypt an integer with the given RSA public key.
///
/// This is an implementation of the RSAEP primitive, as defined in PKCS #1
/// version 2.2. It encrypts the integer `message` using the public key `key`.
/// In RSA, this operation is performed by simply raising the message to the
/// power $e$, modulo $n$: The ciphertext $c = m^e \mod n$.
///
/// This function will return an error in the case that the message is larger
/// than $n - 1$, but will otherwise return the result of the encryption.
///
/// It should be noted that encryption/decryption are the same operation in RSA,
/// so this function both encrypts and decrypts with the public key. However, if
/// something is encrypted with the private key, this should be for signature
/// purposes rather than encryption, and so there is a separate (but identical)
/// primitive for decryption with the public key.
pub fn encrypt_int<T: RSAKey>(key: &T, message: Integer) -> RSAResult<Integer> {
    if message >= key.get_modulus() {
        return Err(RSAError::MessageOutOfRange);
    }
    // The error variant here is unreachable
    Ok(message.pow_mod(&key.get_exponent(), &key.get_modulus()).unwrap())
}

/// Decrypt an integer with the given RSA private key.
///
/// This is an implementation of the RSADP primitive, as defined in PKCS #1
/// version 2.2. It decrypts the integer `ciphertext` using the private key
/// `key`. In RSA, this operation is performed by simply raising the ciphertext
/// to the power $d$, modulo $n$: The message $m = c^d \mod n$.
///
/// This function will return an error in the case that the ciphertext is larger
/// than $n - 1$, but will otherwise return the result of the decryption.
///
/// It should be noted that encryption/decryption are the same operation in RSA,
/// so this function both encrypts and decrypts with the private key. However,
/// if something is encrypted with the private key, this should be for signature
/// purposes rather than encryption, and so there is a separate (but identical)
/// primitive for encryption with the private key.
pub fn decrypt_int<T: RSAKey>(key: &T, ciphertext: Integer) -> RSAResult<Integer> {
    if ciphertext >= key.get_modulus() {
        return Err(RSAError::CiphertextOutOfRange);
    }
    // The error variant here is unreachable
    Ok(ciphertext.pow_mod(&key.get_exponent(), &key.get_modulus()).unwrap())
}

/// Sign an integer with the given RSA private key.
///
/// This is an implementation of the RSASP1 primitive, as defined in PKCS #1
/// version 2.2. It signs the integer `message` using the private key `key`.
/// This is simply a wrapper around [`decrypt_int`].
pub fn sign_int(key: &RSAPrivateKey, message: Integer) -> RSAResult<Integer> {
    match decrypt_int(key, message) {
        Ok(i) => Ok(i),
        Err(_) => Err(RSAError::MessageOutOfRange),
    }
}

/// Verify an integer has been signed by a given RSA private key, using the
/// corresponding public key.
///
/// This is an implementation of the RSAVP1 primitive, as defined in PKCS #1
/// version 2.2. It attempts to decrypt the integer `message` using the public
/// key `key`, returning the result. This is simply a wrapper around
/// [`encrypt_int`].
pub fn verify_sig_int(key: &RSAPublicKey, signature: Integer) -> RSAResult<Integer> {
    match encrypt_int(key, signature) {
        Ok(i) => Ok(i),
        Err(_) => Err(RSAError::SignatureOutOfRange),
    }
}
