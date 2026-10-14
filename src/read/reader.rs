use alloc::borrow::Cow;
use core::fmt::Debug;

use crate::endianity::Endianity;
use crate::leb128;
use crate::read::{Error, Result};

/// A trait for reading the data from a section that holds LSDAs.
///
/// All read operations advance the offset of the reader unless specified
/// otherwise.
#[allow(clippy::len_without_is_empty)]
pub trait Reader: Debug + Clone {
    /// The endianity of bytes that are read.
    type Endian: Endianity;

    /// Return the endianity of bytes that are read.
    fn endian(&self) -> Self::Endian;

    /// Return the number of bytes remaining.
    fn len(&self) -> usize;

    /// Set the number of bytes remaining to zero.
    fn empty(&mut self);

    /// Set the number of bytes remaining to the specified length.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `len` bytes remain.
    fn truncate(&mut self, len: usize) -> Result<()>;

    /// Return the offset of this reader's data relative to the start of the
    /// given base reader's data.
    ///
    /// May panic if this reader's data is not contained within the given base
    /// reader's data.
    fn offset_from(&self, base: &Self) -> usize;

    /// Discard the specified number of bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `len` bytes remain.
    fn skip(&mut self, len: usize) -> Result<()>;

    /// Split a reader in two.
    ///
    /// A new reader is returned that can be used to read the next `len` bytes,
    /// and `self` is advanced so that it reads the remainder.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `len` bytes remain.
    fn split(&mut self, len: usize) -> Result<Self>;

    /// Return all remaining data as a clone-on-write slice.
    ///
    /// Does not advance the reader.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be provided as a slice.
    fn to_slice(&self) -> Result<Cow<'_, [u8]>>;

    /// Read exactly `buf.len()` bytes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `buf.len()` bytes remain.
    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()>;

    /// Read a fixed-size field of `size` bytes (1, 2, 4 or 8) that may be the
    /// target of a relocation, zero-extended to 64 bits.
    ///
    /// Encoded pointers of a fixed size are read with this method. The
    /// default implementation reads the field as-is, which is correct for
    /// linked images. [`RelocateReader`](crate::read::RelocateReader)
    /// overrides it to apply relocations in relocatable objects.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `size` bytes remain, if `size` is not
    /// supported, or if relocating the field fails.
    #[inline]
    fn read_relocatable(&mut self, size: u8) -> Result<u64> {
        self.read_sized(size)
    }

    /// Return true if there are no bytes remaining.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if no bytes remain.
    #[inline]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0; 1];
        self.read_slice(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 2 bytes remain.
    #[inline]
    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0; 2];
        self.read_slice(&mut buf)?;
        Ok(self.endian().read_u16(&buf))
    }

    /// Read a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 4 bytes remain.
    #[inline]
    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0; 4];
        self.read_slice(&mut buf)?;
        Ok(self.endian().read_u32(&buf))
    }

    /// Read a `u64`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 8 bytes remain.
    #[inline]
    fn read_u64(&mut self) -> Result<u64> {
        let mut buf = [0; 8];
        self.read_slice(&mut buf)?;
        Ok(self.endian().read_u64(&buf))
    }

    /// Read an unsigned field of `size` bytes (1, 2, 4 or 8), zero-extended
    /// to 64 bits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedSize`] for any other size, and an error if
    /// fewer than `size` bytes remain.
    fn read_sized(&mut self, size: u8) -> Result<u64> {
        match size {
            1 => self.read_u8().map(u64::from),
            2 => self.read_u16().map(u64::from),
            4 => self.read_u32().map(u64::from),
            8 => self.read_u64(),
            _ => Err(Error::UnsupportedSize(size)),
        }
    }

    /// Read an unsigned LEB128 value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadUnsignedLeb128`] if the value does not fit in a
    /// `u64`, and [`Error::UnexpectedEof`] if it is truncated.
    fn read_uleb128(&mut self) -> Result<u64> {
        read_leb128(
            self,
            |bytes| leb128::read_unsigned(bytes),
            Error::BadUnsignedLeb128,
        )
    }

    /// Read a signed LEB128 value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BadSignedLeb128`] if the value does not fit in an
    /// `i64`, and [`Error::UnexpectedEof`] if it is truncated.
    fn read_sleb128(&mut self) -> Result<i64> {
        read_leb128(
            self,
            |bytes| leb128::read_signed(bytes),
            Error::BadSignedLeb128,
        )
    }

    /// Return a reader for the data starting at `offset`, without changing
    /// this reader.
    ///
    /// # Errors
    ///
    /// Returns an error if `offset` is greater than the number of bytes
    /// remaining.
    #[inline]
    fn range_from(&self, offset: usize) -> Result<Self> {
        let mut reader = self.clone();
        reader.skip(offset)?;
        Ok(reader)
    }
}

/// Decode a LEB128 value with one of the [`leb128`] decoders, which return
/// `None` both at the end of input and on overflow.
fn read_leb128<R: Reader, T>(
    reader: &mut R,
    decode: impl FnOnce(&mut dyn Iterator<Item = u8>) -> Option<T>,
    overflow: Error,
) -> Result<T> {
    let mut eof = false;
    let mut bytes = core::iter::from_fn(|| {
        let byte = reader.read_u8().ok();
        eof = byte.is_none();
        byte
    });
    match decode(&mut bytes) {
        Some(value) => Ok(value),
        None if eof => Err(Error::UnexpectedEof),
        None => Err(overflow),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::{BigEndian, LittleEndian};
    use crate::read::EndianSlice;

    #[test]
    fn test_leb128() {
        let buf = [0xe5, 0x8e, 0x26, 0x7f, 0x80, 0x7f, 0x80];
        let mut r = EndianSlice::new(&buf, LittleEndian);
        assert_eq!(r.read_uleb128(), Ok(624_485));
        assert_eq!(r.read_sleb128(), Ok(-1));
        assert_eq!(r.read_sleb128(), Ok(-128));
        assert_eq!(r.read_uleb128(), Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_sized() {
        let buf = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut r = EndianSlice::new(&buf, BigEndian);
        assert_eq!(r.read_sized(2), Ok(0x0102));
        assert_eq!(r.read_sized(3), Err(Error::UnsupportedSize(3)));
        assert_eq!(r.range_from(0).unwrap().read_sized(8).ok(), None);
        assert_eq!(
            EndianSlice::new(&buf, BigEndian).read_u64(),
            Ok(0x0102_0304_0506_0708)
        );
    }
}
