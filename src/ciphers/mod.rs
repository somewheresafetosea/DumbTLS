//! Implementations of various cryptographic ciphers.
//!
//! The concept of a cipher is likely the most fundamental primitive within
//! cryptography: An algorithm which allows someone (we'll call them "A") to
//! transform some data (the "plaintext") to a form that is unreadable to anyone
//! (the "ciphertext"), except a person with some specific knowledge ("B"). This
//! knowledge allows them to transform the ciphertext back into the plaintext
//! from which it was derived.
//!
//! When ciphers were first being developed, the knowledge required for B to be
//! able to decrypt A's message was simply the algorithm that the cipher used.
//! For example, consider the Caeser Cipher, in which one simply "rotates" each
//! letter of the plaintext 13 places to obtain the ciphertext (so the letter
//! "a" becomes "n", "b" becomes "o", and so on, with wrapping, so "l" becomes
//! "z", then "n" becomes "a"). The knowledge that "B" needs to have is simply
//! that a Caeser Cipher has been used, and it is then trivial to reverse the
//! encryption.
//!
//! As time progressed, this approach was challenged. In 1883,
//! Auguste Kerckhoffs published an article describing desirable properties for
//! military ciphers, one of which was that it should not be a problem if the
//! cipher falls into enemy hands. Claude Shannon, now widely considered as the
//! "father of information theory", further clarified Kerckhoffs' principle, and
//! contributed several other important principles of modern cryptography (which
//! still apply today) in his 1945 report *A Mathematical Theory of
//! Cryptography*: Ciphers should be designed such that we assume the enemy also
//! knows the design of the system, and they are still secure. It is now the
//! norm for new ciphers to be made public, and in general, it is believed that
//! having "more eyes" to look over these algorithms ensures that any security
//! issues are more likely to be found.
//
//! The modern approach to encryption is to add a second input (other than just
//! the plaintext) to the cipher: a key. The key changes how the algorithm is
//! applied to the input, such that the output of the cipher then depends on
//! both on both the plaintext used and the key. The same key is then necessary
//! to decrypt the ciphertext back into plaintext. There is one essential
//! property of a cipher which uses keys: Given any number of plaintexts and
//! their corresponding ciphertexts, it should not be possible to derive the key
//! that is in use. The intention of such a design is that the algorithm used
//! can be published, and it's only the key that needs to be kept secret for the
//! encryption to be secure.
//!
//! When evaluating ciphers, it is necessary to consider how well they obscure
//! the relationship between the input and the output: How easy is it to tell
//! what the plaintext was, or gain information about the plaintext, given the
//! ciphertext? Once again, in *A Mathematic Theory of Cryptography*, Shannon
//! outlined two properties of ciphers which ensure that they successfully
//! conceal this relationship: Confusion and diffusion. Confusion refers to the
//! way in which each bit of the ciphertext relates to the key: Each bit of the
//! ciphertext must depend on multiple parts of the key. This is in contrast to
//! a classic one-time-pad, in which bit of the ciphertext corresponds to one
//! bit of the key. Diffusion refers to each bit of the ciphertext depending on
//! multiple parts of the plaintext: If one bit of the plaintext is changed,
//! then at least half of the ciphertext should change, on average. These two
//! properties ensure that ciphers are resistant to differential analysis, an
//! attack in which multiple similar plaintexts are encrypted, and the
//! differences in the resulting ciphertexts are compared.
//!
//! # Types of Cipher
//! We tend to categorise ciphers using either their mode of operation (block or
//! stream), or their usage of keys (symmetric or asymmetric).
//!
//! Stream ciphers encrypt each bit of the plaintext individually, before moving
//! on to the next bit, and encrypting that. A bit "B" in the plaintext that is
//! encrypted after bit "A" cannot affect the resulting output of "A"'s
//! encryption (although the output of "A"'s encryption could affect that of
//! "B", if cipher feedback is in use). In block ciphers, on the other hand, the
//! plaintext is split into "blocks" of a set size, which are all operated on at
//! once: Each bit of output depends on the content of the entire plaintext
//! block, rather than a single bit of input (and potentially the bits before
//! that). This design feature means that block ciphers are more easily made to
//! include diffusion, and it is because of this that the vast majority of
//! ciphers in use in the real world today operate as block ciphers, rather than
//! stream ciphers.
//!
//! Symmetric ciphers work using only one key: This is used to encrypt the
//! plaintext, then the same key is used to decrypt the resulting ciphertext. In
//! asymmetric ciphers, there are two keys: a public key, and a private key. If
//! one is used to encrypt a message, then only the other can decrypt it. The
//! benefit of this approach is twofold: Firstly, the system can be used to
//! encrypt messages intended for a single recipient, by encrypting with the
//! public key, such that only the person with the private key can decrypt it,
//! like with symmetric encryption. Secondly, a person with a private key can
//! "sign" a message by encrypting it with their private key, such that anyone
//! with the public key can decrypt it, and in doing so, verify that it was the
//! person with the public key who encrypted it. This allows non-repudiation,
//! and identity verification. The drawback to asymmetric encryption is that it
//! often requires considerably larger keys to have the same security as
//! symmetric encryption, and it is difficult to find an effective method of
//! key distribution.
pub mod aes;
pub mod block;
pub mod des;
pub mod feistel;
pub mod rsa;
pub mod oaep;
