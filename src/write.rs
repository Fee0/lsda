//! Write LSDAs to `.gcc_except_table`.
//!
//! ## API Structure
//!
//! This module works by building up a representation of the LSDAs in memory
//! with [`GccExceptTable`] and [`Lsda`], and then writing them all at once to
//! a [`Writer`].
//!
//! * An [`Lsda`] holds the call-site table ([`CallSite`]), the action table
//!   ([`Action`]), the type table, and the exception specifications
//!   ([`ExceptionSpec`]). Entries refer to each other through ids, which are
//!   indices into those tables; the writer computes the encoded offsets.
//!
//! * Addresses are [`Address`] values: either constants, which are encoded
//!   relative to the bases in [`BaseAddresses`](crate::BaseAddresses), or
//!   symbols, which require a writer that records relocations (see
//!   [`RelocateWriter`]).
//!
//! * With the `read` feature, [`GccExceptTable::from_read`] converts parsed
//!   tables so they can be modified and written again.
//!
//! ## Example Usage
//!
//! ```rust
//! use lsda::write::{Action, Address, CallSite, EndianVec, Filter, GccExceptTable, Lsda};
//! use lsda::{BaseAddresses, Encoding, Format, LittleEndian};
//!
//! # fn example() -> lsda::write::Result<()> {
//! // try { g(); } catch (int) { ... }
//! let mut lsda = Lsda::new();
//! lsda.ttype_encoding = Encoding::INDIRECT_PCREL_SDATA4;
//! let int = lsda.add_type(Some(Address::Constant(0x2000))); // DW.ref._ZTIi
//! let catch_int = lsda.add_action(Action {
//!     filter: Filter::Catch(int),
//!     next: None,
//! });
//! lsda.call_sites.push(CallSite {
//!     start: 0x10,
//!     length: 0x08,
//!     landing_pad: 0x40,
//!     action: Some(catch_int),
//! });
//!
//! let mut table = GccExceptTable::new(Format::new(8));
//! table.add_lsda(lsda);
//!
//! let mut section = EndianVec::new(LittleEndian);
//! let bases = BaseAddresses::default().set_section(0x1000);
//! table.write(&mut section, &bases)?;
//! assert_eq!(
//!     section.slice(),
//!     [
//!         0xff, 0x9b, 0x0d, 0x01, 0x04, // header
//!         0x10, 0x08, 0x40, 0x01, // call site
//!         0x01, 0x00, // action
//!         0x00, // padding
//!         0xf4, 0x0f, 0x00, 0x00, // type 1
//!     ]
//! );
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```

mod error;
pub use self::error::*;

mod writer;
pub use self::writer::Writer;

mod endian_vec;
pub use self::endian_vec::*;

mod relocate;
pub use self::relocate::*;

mod table;
pub use self::table::*;

#[cfg(feature = "read")]
mod convert;
#[cfg(feature = "read")]
pub use self::convert::*;

/// An address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    /// A fixed address that does not require relocation.
    Constant(u64),
    /// An address that is relative to a symbol which may be relocated.
    Symbol {
        /// The symbol that the address is relative to.
        ///
        /// The meaning of this value is decided by the writer, but will
        /// typically be an index into a symbol table.
        symbol: usize,
        /// The offset of the address relative to the symbol.
        ///
        /// This will typically be used as the addend in a relocation.
        addend: i64,
    },
}
