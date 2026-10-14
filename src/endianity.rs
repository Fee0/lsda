//! Types for compile-time and run-time endianity.

use core::fmt::Debug;

/// A trait describing the endianity of some buffer.
pub trait Endianity: Debug + Default + Clone + Copy + PartialEq + Eq {
    /// Return true for big endian byte order.
    fn is_big_endian(self) -> bool;

    /// Return true for little endian byte order.
    #[inline]
    fn is_little_endian(self) -> bool {
        !self.is_big_endian()
    }

    /// Reads an unsigned 16 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 2`.
    #[inline]
    fn read_u16(self, buf: &[u8]) -> u16 {
        let bytes: [u8; 2] = buf[..2].try_into().unwrap();
        if self.is_big_endian() {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    }

    /// Reads an unsigned 32 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 4`.
    #[inline]
    fn read_u32(self, buf: &[u8]) -> u32 {
        let bytes: [u8; 4] = buf[..4].try_into().unwrap();
        if self.is_big_endian() {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }

    /// Reads an unsigned 64 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 8`.
    #[inline]
    fn read_u64(self, buf: &[u8]) -> u64 {
        let bytes: [u8; 8] = buf[..8].try_into().unwrap();
        if self.is_big_endian() {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        }
    }

    /// Writes an unsigned 16 bit integer `n` to `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 2`.
    #[inline]
    fn write_u16(self, buf: &mut [u8], n: u16) {
        let bytes = if self.is_big_endian() {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        };
        buf[..2].copy_from_slice(&bytes);
    }

    /// Writes an unsigned 32 bit integer `n` to `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 4`.
    #[inline]
    fn write_u32(self, buf: &mut [u8], n: u32) {
        let bytes = if self.is_big_endian() {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        };
        buf[..4].copy_from_slice(&bytes);
    }
    /// Writes an unsigned 64 bit integer `n` to `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 8`.
    #[inline]
    fn write_u64(self, buf: &mut [u8], n: u64) {
        let bytes = if self.is_big_endian() {
            n.to_be_bytes()
        } else {
            n.to_le_bytes()
        };
        buf[..8].copy_from_slice(&bytes);
    }
}

/// Byte order that is selectable at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunTimeEndian {
    /// Little endian byte order.
    Little,
    /// Big endian byte order.
    Big,
}

impl Default for RunTimeEndian {
    #[cfg(target_endian = "little")]
    #[inline]
    fn default() -> RunTimeEndian {
        RunTimeEndian::Little
    }

    #[cfg(target_endian = "big")]
    #[inline]
    fn default() -> RunTimeEndian {
        RunTimeEndian::Big
    }
}

impl Endianity for RunTimeEndian {
    #[inline]
    fn is_big_endian(self) -> bool {
        self != RunTimeEndian::Little
    }
}

/// Little endian byte order.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LittleEndian;

impl Endianity for LittleEndian {
    #[inline]
    fn is_big_endian(self) -> bool {
        false
    }
}

/// Big endian byte order.
///
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BigEndian;

impl Endianity for BigEndian {
    #[inline]
    fn is_big_endian(self) -> bool {
        true
    }
}

/// The native endianity for the target platform.
#[cfg(target_endian = "little")]
pub type NativeEndian = LittleEndian;

/// The native endianity for the target platform.
#[cfg(target_endian = "big")]
pub type NativeEndian = BigEndian;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write() {
        let mut buf = [0u8; 4];
        LittleEndian.write_u32(&mut buf, 0x1234_5678);
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
        assert_eq!(LittleEndian.read_u32(&buf), 0x1234_5678);
        BigEndian.write_u32(&mut buf, 0x1234_5678);
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(BigEndian.read_u32(&buf), 0x1234_5678);
        assert_eq!(RunTimeEndian::Big.read_u16(&buf), 0x1234);
        assert_eq!(RunTimeEndian::Little.read_u16(&buf), 0x3412);
        let mut buf = [0u8; 8];
        BigEndian.write_u64(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(LittleEndian.read_u64(&buf), 0x0807_0605_0403_0201);
    }
}
