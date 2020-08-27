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
//! The documentation you are reading currently will clearly cover the maths
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
