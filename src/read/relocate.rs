use alloc::borrow::Cow;
use core::fmt;

use crate::read::{Reader, Result};

/// Trait for relocating fields while reading a section.
///
/// In a relocatable object, the `type_info` references in the type table
/// (and any other non-constant encoded pointer) are the targets of
/// relocations, such as `R_X86_64_PC32` against a `DW.ref._ZTI*` symbol, or
/// `R_ARM_TARGET2`. An implementation of this trait computes what the field
/// would contain after linking, for some layout of the sections chosen by the
/// caller. Use the same layout for [`BaseAddresses`](crate::BaseAddresses).
///
/// For REL relocations the addend is the original field value; for RELA it
/// is part of the relocation and the field value can be ignored.
pub trait Relocate {
    /// Relocate a field of `size` bytes which was read from the given section
    /// offset, with the given zero-extended value.
    ///
    /// Return the value unchanged if there is no relocation at this offset.
    /// The result is truncated to `size` bytes by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the relocation at `offset` cannot be applied.
    fn relocate(&self, offset: usize, size: u8, value: u64) -> Result<u64>;
}

impl<T: Relocate + ?Sized> Relocate for &T {
    fn relocate(&self, offset: usize, size: u8, value: u64) -> Result<u64> {
        (**self).relocate(offset, size, value)
    }
}

/// A [`Reader`] which applies relocations to relocatable fields.
///
/// This is useful for reading sections in a relocatable object file. It is
/// generally not needed for executables and shared libraries.
///
/// The reader is cloned for every table that is parsed, and `relocate` with
/// it, so `T` should be cheap to clone: a reference (`&T` implements
/// [`Relocate`]) or an `Rc`/`Arc` rather than an owned table.
///
/// ```
/// use lsda::read::{EndianSlice, GccExceptTable, Relocate, RelocateReader, Result};
/// use lsda::{BaseAddresses, Format, LittleEndian, LsdaOffset};
///
/// /// One `R_X86_64_PC32` against `DW.ref._ZTIi` (placed at 0x3000) at
/// /// offset 12, for a layout that places the section at `section`.
/// #[derive(Clone)]
/// struct Relocations {
///     section: u64,
/// }
///
/// impl Relocate for Relocations {
///     fn relocate(&self, offset: usize, _size: u8, value: u64) -> Result<u64> {
///         Ok(match offset {
///             12 => 0x3000u64.wrapping_sub(self.section + offset as u64),
///             _ => value,
///         })
///     }
/// }
///
/// # fn main() -> Result<()> {
/// // An LSDA with one call site [0x4, 0x8) whose landing pad at 0x10 catches
/// // type 1: header, call site, action record, padding, and a type table
/// // entry whose relocated field holds only zero.
/// let data = [
///     0xff, 0x9b, 0x0d, 0x01, 0x04, 0x04, 0x04, 0x10, 0x01, 0x01, 0x00, 0x00, //
///     0x00, 0x00, 0x00, 0x00,
/// ];
/// let section = 0x2000;
/// let table = GccExceptTable::from_reader(
///     RelocateReader::new(EndianSlice::new(&data, LittleEndian), Relocations { section }),
///     Format::new(8),
/// );
/// let lsda = table.lsda_at(LsdaOffset(0))?;
/// let bases = BaseAddresses::default().set_section(section);
/// let type_info = lsda.type_entry(1)?;
/// assert!(type_info.is_indirect());
/// assert_eq!(type_info.address(&bases)?, 0x3000);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct RelocateReader<R: Reader, T: Relocate> {
    section: R,
    reader: R,
    relocate: T,
}

impl<R: Reader, T: Relocate> RelocateReader<R, T> {
    /// Create a new `RelocateReader` which applies relocations to the given
    /// section reader.
    pub fn new(section: R, relocate: T) -> Self {
        let reader = section.clone();
        RelocateReader {
            section,
            reader,
            relocate,
        }
    }

    /// Return the underlying reader, at the current position.
    pub fn inner(&self) -> &R {
        &self.reader
    }
}

impl<R: Reader, T: Relocate> fmt::Debug for RelocateReader<R, T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("RelocateReader")
            .field(&self.reader)
            .finish()
    }
}

impl<R, T> Reader for RelocateReader<R, T>
where
    R: Reader,
    T: Relocate + Clone,
{
    type Endian = R::Endian;

    fn read_relocatable(&mut self, size: u8) -> Result<u64> {
        let offset = self.reader.offset_from(&self.section);
        let value = self.reader.read_sized(size)?;
        let value = self.relocate.relocate(offset, size, value)?;
        Ok(value & crate::common::size_mask(size))
    }

    #[inline]
    fn endian(&self) -> Self::Endian {
        self.reader.endian()
    }

    #[inline]
    fn len(&self) -> usize {
        self.reader.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.reader.empty();
    }

    #[inline]
    fn truncate(&mut self, len: usize) -> Result<()> {
        self.reader.truncate(len)
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> usize {
        self.reader.offset_from(&base.reader)
    }

    #[inline]
    fn skip(&mut self, len: usize) -> Result<()> {
        self.reader.skip(len)
    }

    #[inline]
    fn split(&mut self, len: usize) -> Result<Self> {
        let mut other = self.clone();
        other.reader.truncate(len)?;
        self.reader.skip(len)?;
        Ok(other)
    }

    #[inline]
    fn to_slice(&self) -> Result<Cow<'_, [u8]>> {
        self.reader.to_slice()
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()> {
        self.reader.read_slice(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::read::EndianSlice;

    #[derive(Debug, Clone)]
    struct AddAtFour;

    impl Relocate for AddAtFour {
        fn relocate(&self, offset: usize, _size: u8, value: u64) -> Result<u64> {
            Ok(if offset == 4 {
                value + 0x1_0000_0100
            } else {
                value
            })
        }
    }

    #[test]
    fn test_relocate_reader() {
        let buf = [1, 0, 0, 0, 2, 0, 0, 0];
        let mut reader = RelocateReader::new(EndianSlice::new(&buf, LittleEndian), AddAtFour);
        assert_eq!(reader.read_relocatable(4), Ok(1));
        let mut tail = reader.split(4).unwrap();
        // Truncated to the field size.
        assert_eq!(tail.read_relocatable(4), Ok(0x102));
    }
}
