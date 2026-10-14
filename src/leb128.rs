//! LEB128 encoding, as used throughout the LSDA.

/// Decode an unsigned LEB128 value from a byte iterator.
///
/// Returns `None` if the iterator ends before the value does, or if the value
/// does not fit in a `u64`. Redundant high zero groups are accepted.
pub fn read_unsigned<I: Iterator<Item = u8> + ?Sized>(bytes: &mut I) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = bytes.next()?;
        let low = u64::from(byte & 0x7f);
        if shift >= 64 {
            // Only padding (zero groups) may follow the 64th bit.
            if low != 0 {
                return None;
            }
        } else {
            if shift == 63 && low > 1 {
                return None;
            }
            result |= low << shift;
        }
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

/// Decode a signed LEB128 value from a byte iterator.
///
/// Returns `None` if the iterator ends before the value does, or if the value
/// does not fit in an `i64`. Redundant sign groups are accepted.
pub fn read_signed<I: Iterator<Item = u8> + ?Sized>(bytes: &mut I) -> Option<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        let byte = bytes.next()?;
        let low = i64::from(byte & 0x7f);
        if shift >= 64 {
            // Only sign groups may follow the 64th bit.
            let sign = if result < 0 { 0x7f } else { 0 };
            if low != sign {
                return None;
            }
        } else if shift == 63 {
            // Bit 63 is the sign; the remaining group bits must agree.
            if low != 0 && low != 0x7f {
                return None;
            }
            result |= low << shift;
        } else {
            result |= low << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some(result);
        }
    }
}

/// Return the number of bytes in the minimal unsigned LEB128 encoding of
/// `value`.
#[must_use]
pub fn unsigned_len(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}

/// Return the number of bytes in the minimal signed LEB128 encoding of
/// `value`.
#[must_use]
pub fn signed_len(value: i64) -> usize {
    // One sign bit plus the significant bits.
    let bits = 65
        - if value < 0 {
            value.leading_ones()
        } else {
            value.leading_zeros()
        } as usize;
    bits.div_ceil(7).max(1)
}

/// Encode an unsigned LEB128 value, passing each byte to `out`.
pub fn write_unsigned(value: u64, out: impl FnMut(u8)) {
    write_unsigned_padded(value, 0, out);
}

/// Encode an unsigned LEB128 value in at least `len` bytes, passing each byte
/// to `out`. Bytes beyond the minimal encoding are zero groups.
pub fn write_unsigned_padded(mut value: u64, len: usize, mut out: impl FnMut(u8)) {
    let mut written = 0;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        written += 1;
        if value == 0 && written >= len {
            out(byte);
            return;
        }
        out(byte | 0x80);
    }
}

/// Encode a signed LEB128 value, passing each byte to `out`.
pub fn write_signed(value: i64, out: impl FnMut(u8)) {
    write_signed_padded(value, 0, out);
}

/// Encode a signed LEB128 value in at least `len` bytes, passing each byte to
/// `out`. Bytes beyond the minimal encoding are sign groups.
pub fn write_signed_padded(mut value: i64, len: usize, mut out: impl FnMut(u8)) {
    let mut written = 0;
    loop {
        let byte = (value & 0x7f).cast_unsigned() as u8;
        value >>= 7;
        written += 1;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done && written >= len {
            out(byte);
            return;
        }
        out(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn unsigned(value: u64, len: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        write_unsigned_padded(value, len, |b| buf.push(b));
        buf
    }

    fn signed(value: i64, len: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        write_signed_padded(value, len, |b| buf.push(b));
        buf
    }

    #[test]
    fn test_unsigned() {
        for value in [
            0,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let buf = unsigned(value, 0);
            assert_eq!(buf.len(), unsigned_len(value), "{value:#x}");
            assert_eq!(read_unsigned(&mut buf.iter().copied()), Some(value));
            let padded = unsigned(value, 12);
            assert_eq!(padded.len(), 12);
            assert_eq!(read_unsigned(&mut padded.iter().copied()), Some(value));
        }
        assert_eq!(unsigned(0x80, 0), [0x80, 0x01]);
        assert_eq!(unsigned(2, 3), [0x82, 0x80, 0x00]);
    }

    #[test]
    fn test_signed() {
        for value in [
            0,
            1,
            -1,
            0x3f,
            0x40,
            -0x40,
            -0x41,
            0x1fff,
            -0x2000,
            i64::from(i32::MIN),
            i64::MAX,
            i64::MIN,
        ] {
            let buf = signed(value, 0);
            assert_eq!(buf.len(), signed_len(value), "{value:#x}");
            assert_eq!(read_signed(&mut buf.iter().copied()), Some(value));
            let padded = signed(value, 12);
            assert_eq!(padded.len(), 12);
            assert_eq!(read_signed(&mut padded.iter().copied()), Some(value));
        }
        assert_eq!(signed(-1, 0), [0x7f]);
        assert_eq!(signed(0x40, 0), [0xc0, 0x00]);
        assert_eq!(signed(-3, 2), [0xfd, 0x7f]);
    }

    #[test]
    fn test_errors() {
        assert_eq!(read_unsigned(&mut [0x80u8].iter().copied()), None);
        assert_eq!(read_signed(&mut [0xffu8].iter().copied()), None);
        let overflow = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(read_unsigned(&mut overflow.iter().copied()), None);
        let overflow = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        assert_eq!(read_signed(&mut overflow.iter().copied()), None);
    }
}
