//! # DumbTLS
//! DumbTLS is intended as a tool to help explain the relationship between the
//! theoretical mathematics underpinning the security of cryptographic
//! algorithms, and their practical implementation details. The goal of this
//! project is *not* to implement a production-ready cryptosystem: Attention has
//! not been paid to securing this library against side-channel attacks of any
//! kind, and the techniques used will be inefficient compared to the internal
//! details of any modern cryptography library. Instead, attention has been paid
//! to code readability, commenting, and documentation.
//!
//! The documentation you are reading currently will clearly cover some of the
//! maths involved in many cryptosystems, and point to resources to learn more.
//! I also intend to talk about some of the implementation details, and how some
//! techniques are used to improve the efficiency of these algorithms.
//!
//! If you're not familiar with the Rust documentation style, on any page, you
//! can click the "\[src\]" link in the top-right to view the source.
//! Alternatively, you can read the source code on
//! [Github](https://github.com/somewheresafetosea/DumbTLS).
//!
//! The most interesting stuff is definitely contained within the [`ciphers`]
//! module:
//!
//! * [Implementation of a Feistel Network](ciphers/feistel/index.html)
//!   ([src](../src/dumbtls/ciphers/feistel.rs.html))
//! * [DES](ciphers/des/index.html) ([src](../src/dumbtls/ciphers/des.rs.html))
//! * [AES](ciphers/aes/index.html) ([src](../src/dumbtls/ciphers/aes.rs.html))
//! * [RSA](ciphers/rsa/index.html) ([src](../src/dumbtls/ciphers/rsa.rs.html))
//! * [RSAES-OAEP](ciphers/oaep/index.html)
//!   ([src](../src/dumbtls/ciphers/oaep.rs.html))
//! * [Block cipher modes of operation](ciphers/block/index.html)
//!   ([src](../src/dumbtls/ciphers/block.rs.html))
//!
//! ## Building
//! DumbTLS is written in Rust, and requires the Rust toolchain to be installed
//! in order to be built, please see [rustup.rs](https://rustup.rs) for
//! installation instructions.
//!
//! We use the `rug` crate to provide arbitrary-precision arithmetic, which
//! internally depends on GMP, MPFR, and MPC. You will likely need to install
//! further tools to build this crate: See [gmp-mpfr-sys
//! docs](https://docs.rs/gmp-mpfr-sys/1.3.1/gmp_mpfr_sys/index.html#building-on-gnulinux)
//!
//! Once you have the required dependencies installed, building should be as
//! simple as running:
//!
//! ```
//! $ cargo build
//! ```

pub mod bytes;
pub mod ciphers;
pub mod encoding;
pub mod hashes;
pub mod keygen;
pub mod padding;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
