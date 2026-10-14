use alloc::borrow::Cow;
use core::ops::Deref;

use crate::endianity::Endianity;
use crate::read::{Error, Reader, Result};

/// A `&[u8]` slice with endianity metadata.
///
/// This implements the [`Reader`] trait, which is used for all reading of
/// LSDA sections.
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndianSlice<'input, Endian>
where
    Endian: Endianity,
{
    slice: &'input [u8],
    endian: Endian,
}

impl<'input, Endian> EndianSlice<'input, Endian>
where
    Endian: Endianity,
{
    /// Construct a new `EndianSlice` with the given slice and endianity.
    #[inline]
    pub fn new(slice: &'input [u8], endian: Endian) -> EndianSlice<'input, Endian> {
        EndianSlice { slice, endian }
    }

    /// Return a reference to the raw slice.
    #[inline]
    pub fn slice(&self) -> &'input [u8] {
        self.slice
    }

    /// Return the offset of the start of this slice relative to the start of
    /// the given slice.
    ///
    /// Returns `None` if this slice is not contained within the given slice.
    #[inline]
    pub fn offset_from_checked(&self, base: EndianSlice<'input, Endian>) -> Option<usize> {
        let base_ptr = base.slice.as_ptr() as usize;
        let ptr = self.slice.as_ptr() as usize;
        if ptr >= base_ptr && ptr + self.slice.len() <= base_ptr + base.slice.len() {
            Some(ptr - base_ptr)
        } else {
            None
        }
    }
}

impl<Endian> Deref for EndianSlice<'_, Endian>
where
    Endian: Endianity,
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.slice
    }
}

impl<Endian> core::fmt::Debug for EndianSlice<'_, Endian>
where
    Endian: Endianity,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_tuple("EndianSlice")
            .field(&self.endian)
            .field(&DebugBytes(self.slice))
            .finish()
    }
}

struct DebugBytes<'input>(&'input [u8]);

impl core::fmt::Debug for DebugBytes<'_> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = fmt.debug_list();
        list.entries(self.0.iter().take(8).copied().map(DebugByte));
        if self.0.len() > 8 {
            list.entry(&DebugLen(self.0.len()));
        }
        list.finish()
    }
}

struct DebugByte(u8);

impl core::fmt::Debug for DebugByte {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(fmt, "0x{:02x}", self.0)
    }
}

struct DebugLen(usize);

impl core::fmt::Debug for DebugLen {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(fmt, "...; {}", self.0)
    }
}

impl<Endian> Reader for EndianSlice<'_, Endian>
where
    Endian: Endianity,
{
    type Endian = Endian;

    #[inline]
    fn endian(&self) -> Endian {
        self.endian
    }

    #[inline]
    fn len(&self) -> usize {
        self.slice.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.slice = &[];
    }

    #[inline]
    fn truncate(&mut self, len: usize) -> Result<()> {
        if self.slice.len() < len {
            Err(Error::UnexpectedEof)
        } else {
            self.slice = &self.slice[..len];
            Ok(())
        }
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> usize {
        let base_ptr = base.slice.as_ptr() as usize;
        let ptr = self.slice.as_ptr() as usize;
        debug_assert!(base_ptr <= ptr);
        debug_assert!(ptr + self.slice.len() <= base_ptr + base.slice.len());
        ptr - base_ptr
    }

    #[inline]
    fn skip(&mut self, len: usize) -> Result<()> {
        if self.slice.len() < len {
            Err(Error::UnexpectedEof)
        } else {
            self.slice = &self.slice[len..];
            Ok(())
        }
    }

    #[inline]
    fn split(&mut self, len: usize) -> Result<Self> {
        if self.slice.len() < len {
            return Err(Error::UnexpectedEof);
        }
        let (head, tail) = self.slice.split_at(len);
        self.slice = tail;
        Ok(EndianSlice::new(head, self.endian))
    }

    #[inline]
    fn to_slice(&self) -> Result<Cow<'_, [u8]>> {
        Ok(Cow::Borrowed(self.slice))
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()> {
        let head = self.split(buf.len())?;
        buf.copy_from_slice(head.slice);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::{BigEndian, LittleEndian};

    #[test]
    fn test_reads() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mut le = EndianSlice::new(&buf, LittleEndian);
        assert_eq!(le.read_u16(), Ok(0x0201));
        assert_eq!(le.read_u32(), Ok(0x0605_0403));
        assert_eq!(le.read_u8(), Err(Error::UnexpectedEof));

        let mut be = EndianSlice::new(&buf, BigEndian);
        assert_eq!(be.read_u32(), Ok(0x0102_0304));
        let base = EndianSlice::new(&buf, BigEndian);
        assert_eq!(be.offset_from(&base), 4);
        assert_eq!(be.offset_from_checked(base), Some(4));
    }

    #[test]
    fn test_split() {
        let buf = [1, 2, 3, 4];
        let mut reader = EndianSlice::new(&buf, LittleEndian);
        let head = reader.split(1).unwrap();
        assert_eq!(head.slice(), &[1]);
        assert_eq!(reader.slice(), &[2, 3, 4]);
        assert_eq!(reader.split(4), Err(Error::UnexpectedEof));
    }
}
