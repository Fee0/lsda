//! Read LSDAs from `.gcc_except_table` (or `.ARM.extab`).
//!
//! ## Example Usage
//!
//! Find the landing pad and the types caught for a call site:
//!
//! ```rust
//! use lsda::read::{Filter, GccExceptTable};
//! use lsda::{BaseAddresses, Format, LittleEndian, LsdaOffset};
//!
//! # fn example() -> lsda::read::Result<()> {
//! // One call site [0x10, 0x18) with a landing pad at 0x40 and an action
//! // that catches type 1, then a type table with a pc-relative indirect
//! // entry (`DW.ref._ZTIi`) at 0x0c.
//! let data = [
//!     0xff, // @LPStart: omitted, so the function start
//!     0x9b, // @TType: DW_EH_PE_indirect|DW_EH_PE_pcrel|DW_EH_PE_sdata4
//!     0x0d, // @TType base offset: 3 + 13 = 16
//!     0x01, // call-site encoding: DW_EH_PE_uleb128
//!     0x04, // call-site table length
//!     0x10, 0x08, 0x40, 0x01, // start, length, landing pad, action + 1
//!     0x01, 0x00, // action: filter 1, no next action
//!     0x00, // alignment padding
//!     0xf4, 0x0f, 0x00, 0x00, // type 1: 0x1000 + 0xc + 0xff4 = 0x2000
//! ];
//! let table = GccExceptTable::new(&data, LittleEndian, Format::new(8));
//! let lsda = table.lsda_at(LsdaOffset(0))?;
//!
//! // The program counter is at offset 0x14 in the function.
//! let call_site = lsda.find_call_site(0x14)?.expect("covered by a call site");
//! assert_eq!(call_site.landing_pad, 0x40);
//!
//! let bases = BaseAddresses::default().set_section(0x1000);
//! let mut actions = lsda.actions(call_site.action.expect("has an action"));
//! while let Some(action) = actions.next()? {
//!     if let Filter::Catch(index) = action.filter {
//!         let type_info = lsda.type_entry(index)?;
//!         assert_eq!(type_info.address(&bases)?, 0x2000);
//!     }
//! }
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
//!
//! ## API Structure
//!
//! * [`GccExceptTable`] holds the section. LSDAs are not self-delimiting, so
//!   they are reached by offset, normally from the `L` augmentation of an FDE
//!   in `.eh_frame` or from an `.ARM.extab` entry.
//!
//! * [`Lsda`] gives access to the header, the call-site table
//!   ([`CallSite`]), the action table ([`Action`]), the type table, and the
//!   exception specification table. [`Lsda::parse_tables`] decodes all of
//!   them at once and finds the extent of the LSDA.
//!
//! * Every encoded pointer is returned as a [`Pointer`], which records its
//!   encoding and section offset so that it can be resolved against
//!   [`BaseAddresses`].
//!
//! * For relocatable objects, wrap the section data in a [`RelocateReader`]
//!   so that relocated fields are seen as they would be after linking.

use crate::common::{BaseAddresses, Encoding, padding, sign_extend, size_mask};
use crate::constants::{DW_EH_PE_ALIGNED, DW_EH_PE_SLEB128};

/// Implement `Iterator` (and `FallibleIterator`) for a type with an inherent
/// `fn next(&mut self) -> Result<Option<Item>>` that stops after an error.
macro_rules! impl_iterators {
    ($name:ident, $item:ty) => {
        impl<R: $crate::read::Reader> Iterator for $name<R> {
            type Item = $crate::read::Result<$item>;

            fn next(&mut self) -> Option<Self::Item> {
                $name::next(self).transpose()
            }
        }

        #[cfg(feature = "fallible-iterator")]
        impl<R: $crate::read::Reader> fallible_iterator::FallibleIterator for $name<R> {
            type Item = $item;
            type Error = $crate::read::Error;

            fn next(&mut self) -> $crate::read::Result<Option<Self::Item>> {
                $name::next(self)
            }
        }
    };
}

mod error;
pub use self::error::*;

mod reader;
pub use self::reader::*;

mod endian_slice;
pub use self::endian_slice::*;

mod relocate;
pub use self::relocate::*;

mod lsda;
pub use self::lsda::*;

/// An encoded pointer.
///
/// The value is stored as read (after relocation, if any), so that it can be
/// resolved later against [`BaseAddresses`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pointer {
    offset: usize,
    encoding: Encoding,
    value: u64,
    address_size: u8,
}

impl Pointer {
    /// Return the offset of the field within its section.
    #[inline]
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Return the encoding of the pointer.
    #[inline]
    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Return the value of the field, sign-extended for signed formats.
    #[inline]
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Return true if the field is zero in its low `address_size` bytes.
    ///
    /// A zero field is a null pointer whatever its application: in the type
    /// table it means `catch (...)`. As in libgcc and libc++abi, the value
    /// is truncated to the address size first, so an 8-byte field with only
    /// its high half set is null for 4-byte addresses.
    #[inline]
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.value & size_mask(self.address_size) == 0
    }

    /// Return true if the resolved address is the address of a pointer to the
    /// real value (`DW_EH_PE_indirect`), such as a `DW.ref._ZTI*` slot.
    #[inline]
    #[must_use]
    pub fn is_indirect(&self) -> bool {
        self.encoding.is_indirect()
    }

    /// Resolve the pointer to an address, by adding the base address for its
    /// application. An indirect pointer is not followed.
    ///
    /// As in libgcc, a null pointer stays null whatever its application.
    /// The result is truncated to the address size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if the base address that the
    /// application needs is not set.
    pub fn address(&self, bases: &BaseAddresses) -> Result<u64> {
        if self.is_null() {
            return Ok(0);
        }
        let base = bases
            .relative_base(self.encoding, self.offset)
            .map_err(Error::MissingBaseAddress)?;
        Ok(self.value.wrapping_add(base) & size_mask(self.address_size))
    }
}

/// Read a pointer with the given encoding.
pub(crate) fn read_pointer<R: Reader>(
    input: &mut R,
    section: &R,
    encoding: Encoding,
    address_size: u8,
) -> Result<Pointer> {
    // This also rejects DW_EH_PE_omit.
    if !encoding.is_valid() {
        return Err(Error::InvalidEncoding(encoding));
    }
    let aligned = encoding.application() == DW_EH_PE_ALIGNED;
    if aligned {
        let offset = input.offset_from(section);
        input.skip(padding(offset, usize::from(address_size)))?;
    }
    let offset = input.offset_from(section);
    let value = match encoding.size(address_size) {
        Some(size) if encoding.is_signed() && !aligned => {
            sign_extend(input.read_relocatable(size)?, size)
        }
        Some(size) => input.read_relocatable(size)?,
        // A LEB128 value must fit in an address: libgcc's decoding of a
        // wider value is undefined.
        None if encoding.format() == DW_EH_PE_SLEB128 => {
            let value = input.read_sleb128()?.cast_unsigned();
            if sign_extend(value, address_size) != value {
                return Err(Error::BadSignedLeb128);
            }
            value
        }
        None => {
            let value = input.read_uleb128()?;
            if value & !size_mask(address_size) != 0 {
                return Err(Error::BadUnsignedLeb128);
            }
            value
        }
    };
    Ok(Pointer {
        offset,
        encoding,
        value,
        address_size,
    })
}

/// Construct a pointer for an Arm EHABI exception specification entry: a
/// raw `R_ARM_TARGET2` word.
pub(crate) fn target2_pointer(offset: usize, value: u64) -> Pointer {
    Pointer {
        offset,
        encoding: Encoding::UDATA4,
        value,
        address_size: 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Base;
    use crate::endianity::LittleEndian;

    fn read(data: &[u8], skip: usize, encoding: u8, address_size: u8) -> Result<Pointer> {
        let section = EndianSlice::new(data, LittleEndian);
        let mut input = section.range_from(skip)?;
        read_pointer(&mut input, &section, Encoding(encoding), address_size)
    }

    #[test]
    fn test_read_pointer() {
        let data = [0xfc, 0xff, 0xff, 0xff, 0x10, 0x20, 0x30, 0x40];
        let bases = BaseAddresses::default().set_section(0x1000);

        let p = read(&data, 0, 0x1b, 8).unwrap();
        assert_eq!(p.value(), (-4i64).cast_unsigned());
        assert_eq!(p.address(&bases), Ok(0x0ffc));
        assert_eq!(read(&data, 0, 0x03, 8).unwrap().value(), 0xffff_fffc);
        assert_eq!(read(&data, 0, 0x00, 4).unwrap().value(), 0xffff_fffc);
        assert_eq!(
            read(&data, 0, 0x00, 8).unwrap().value(),
            0x4030_2010_ffff_fffc
        );
        assert_eq!(
            read(&[0x7c], 0, 0x09, 8).unwrap().value(),
            (-4i64).cast_unsigned()
        );
        // pcrel at offset 4: 0x1004 + 0x40302010, truncated to 32 bits.
        let p = read(&data, 4, 0x13, 4).unwrap();
        assert_eq!(p.offset(), 4);
        assert_eq!(p.address(&bases), Ok(0x4030_3014));

        // Aligned: skip to the next 4-byte boundary.
        let p = read(&data, 1, 0x50, 4).unwrap();
        assert_eq!((p.offset(), p.value()), (4, 0x4030_2010));

        let p = read(&data, 4, 0x23, 4).unwrap();
        assert_eq!(
            p.address(&BaseAddresses::default()),
            Err(Error::MissingBaseAddress(Base::Text))
        );
        assert_eq!(
            read(&data, 0, 0xff, 4),
            Err(Error::InvalidEncoding(Encoding::OMIT))
        );
        assert_eq!(
            read(&data, 0, 0x05, 4),
            Err(Error::InvalidEncoding(Encoding(5)))
        );
        assert_eq!(read(&data, 6, 0x03, 4), Err(Error::UnexpectedEof));
        // DW_EH_PE_aligned is only valid on its own.
        assert_eq!(
            read(&data, 0, 0x53, 4),
            Err(Error::InvalidEncoding(Encoding(0x53)))
        );

        // LEB128 pointers must fit in an address.
        let wide = [0x80, 0x80, 0x80, 0x80, 0x10];
        assert_eq!(read(&wide, 0, 0x01, 8).unwrap().value(), 0x1_0000_0000);
        assert_eq!(read(&wide, 0, 0x01, 4), Err(Error::BadUnsignedLeb128));
        assert_eq!(read(&wide, 0, 0x09, 4), Err(Error::BadSignedLeb128));
        let negative = [0x80, 0x80, 0x80, 0x80, 0x78];
        assert_eq!(
            read(&negative, 0, 0x09, 4).unwrap().value(),
            (-0x8000_0000i64).cast_unsigned()
        );
    }

    #[test]
    fn test_null_pointer() {
        let data = [0, 0, 0, 0];
        let p = read(&data, 0, 0x9b, 4).unwrap();
        assert!(p.is_null() && p.is_indirect());
        assert_eq!(p.address(&BaseAddresses::default()), Ok(0));

        // A value is truncated to the address size before the null check.
        let data = [0, 0, 0, 0, 1, 0, 0, 0];
        let bases = BaseAddresses::default().set_section(0x1000);
        let p = read(&data, 0, 0x14, 4).unwrap();
        assert!(p.is_null());
        assert_eq!(p.address(&bases), Ok(0));
        let p = read(&data, 0, 0x14, 8).unwrap();
        assert!(!p.is_null());
        assert_eq!(p.address(&bases), Ok(0x1_0000_1000));
    }
}
