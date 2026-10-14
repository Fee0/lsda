//! `lsda` is a library for reading and writing the language-specific data
//! area (LSDA) of GCC-compatible exception handling, as stored in the
//! `.gcc_except_table` section.
//!
//! An LSDA describes, for one function, which call sites may throw, where
//! their landing pads are, and which exception types each landing pad
//! handles. The personality routine (such as `__gxx_personality_v0`) finds it
//! through the `L` augmentation of the function's FDE in `.eh_frame`, or,
//! on Arm, at the end of the function's `.ARM.extab` entry.
//!
//! The format has no standalone specification. It is defined by its producers
//! and consumers, which this crate follows:
//!
//! * GCC `gcc/except.cc` (`output_one_function_exception_table`), the
//!   original producer;
//! * libstdc++ `libsupc++/eh_personality.cc` and libgcc `unwind-pe.h`, the
//!   reference consumer, including its Arm EHABI and SJLJ variants;
//! * LLVM `CodeGen/AsmPrinter/EHStreamer.cpp` and libc++abi
//!   `cxa_personality.cpp`.
//!
//! Pointer encodings are the `DW_EH_PE_*` values of the Linux Standard Base
//! Core Specification 5.0, "Exception Frames".
//!
//! The API is organised as follows:
//!
//! * The [`read`] module parses an LSDA at a given offset through the
//!   [`Reader`](read::Reader) trait, with zero-copy
//!   [`EndianSlice`](read::EndianSlice) as the usual implementation.
//!   Iterators return `Result<Option<T>>`.
//!
//! * The [`write`](mod@write) module builds an in-memory
//!   [`GccExceptTable`](write::GccExceptTable) and writes it to a
//!   [`Writer`](write::Writer) such as [`EndianVec`](write::EndianVec),
//!   optionally recording relocations.
//!
//! * [`Encoding`] and [`Format`] are shared by both.
//!
//! The [`read`] and [`write`](mod@write) module documentation each start with
//! a complete example.
//!
//! ## Cargo features
//!
//! * `read` (default): the [`read`] module.
//! * `write` (default): the [`write`](mod@write) module.
//! * `fallible-iterator`: implement `fallible_iterator::FallibleIterator`
//!   for the iterators.
//!
//! The crate is `no_std` and requires `alloc`. The error types implement
//! `core::error::Error`.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(elided_lifetimes_in_paths)]
// Iterators have an inherent `next` returning `Result<Option<T>>`, so that
// errors propagate with `?`; they also implement `Iterator`.
#![allow(clippy::should_implement_trait)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

mod common;
pub use crate::common::*;

pub mod constants;

mod endianity;
pub use crate::endianity::*;

pub mod leb128;

#[cfg(feature = "read")]
pub mod read;

#[cfg(feature = "write")]
pub mod write;
