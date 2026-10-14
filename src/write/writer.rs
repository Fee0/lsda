use crate::common::{BaseAddresses, Encoding, Format, padding, sign_extend, size_mask};
use crate::constants::*;
use crate::endianity::Endianity;
use crate::leb128;
use crate::write::{Address, Error, Result};

/// A trait for writing the data to a section that holds LSDAs.
///
/// All write operations append to the section unless otherwise specified.
#[allow(clippy::len_without_is_empty)]
pub trait Writer {
    /// The endianity of bytes that are written.
    type Endian: Endianity;

    /// Return the endianity of bytes that are written.
    fn endian(&self) -> Self::Endian;

    /// Return the current section length.
    ///
    /// This is the section offset of the next byte written. It is used for
    /// alignment and to compute `DW_EH_PE_pcrel` pointers.
    fn len(&self) -> usize;

    /// Write a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer cannot store the bytes.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;

    /// Write an encoded pointer to `address`.
    ///
    /// A constant address is converted to the encoding's application by
    /// subtracting the base address from `bases` (for `DW_EH_PE_pcrel`, the
    /// address of the field itself, from `bases.section` and
    /// [`len`](Self::len)). Address 0 is written as 0 whatever the
    /// application, since that is how a null pointer is read. The indirect
    /// flag does not change what is written: `address` is then the address of
    /// the pointer to the real value. A `DW_EH_PE_aligned` pointer is
    /// preceded by zero padding up to the address size.
    ///
    /// If the writer supports relocations, then it must provide its own
    /// implementation of this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEncoding`] for an undefined or omitted
    /// encoding, [`Error::MissingBaseAddress`] if the base for the
    /// application is not set, [`Error::PointerOutOfRange`] if the value does
    /// not fit in the format, and [`Error::InvalidAddress`] for a symbol if the
    /// writer does not support relocations.
    fn write_pointer(
        &mut self,
        encoding: Encoding,
        address: Address,
        format: Format,
        bases: &BaseAddresses,
    ) -> Result<()> {
        match address {
            Address::Constant(value) => {
                write_constant_pointer(self, encoding, value, format, bases)
            }
            Address::Symbol { .. } => Err(Error::InvalidAddress),
        }
    }

    /// Write a reference to a `type_info` object: a type table entry or an
    /// Arm EHABI exception specification entry.
    ///
    /// The default implementation calls
    /// [`write_pointer`](Self::write_pointer). A writer that records
    /// relocations uses this to emit `R_ARM_TARGET2` for the Arm EHABI.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write_pointer`](Self::write_pointer).
    fn write_type_info(
        &mut self,
        encoding: Encoding,
        address: Address,
        format: Format,
        bases: &BaseAddresses,
    ) -> Result<()> {
        self.write_pointer(encoding, address, format, bases)
    }

    /// Write a u8.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(&[val])
    }

    /// Write a u16.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u16(&mut self, val: u16) -> Result<()> {
        let mut bytes = [0; 2];
        self.endian().write_u16(&mut bytes, val);
        self.write(&bytes)
    }

    /// Write a u32.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u32(&mut self, val: u32) -> Result<()> {
        let mut bytes = [0; 4];
        self.endian().write_u32(&mut bytes, val);
        self.write(&bytes)
    }

    /// Write a u64.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u64(&mut self, val: u64) -> Result<()> {
        let mut bytes = [0; 8];
        self.endian().write_u64(&mut bytes, val);
        self.write(&bytes)
    }

    /// Write the low `size` bytes (1, 2, 4 or 8) of `val`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAddressSize`] for any other size, and the
    /// errors of [`write`](Self::write).
    fn write_sized(&mut self, val: u64, size: u8) -> Result<()> {
        match size {
            1 => self.write_u8(val as u8),
            2 => self.write_u16(val as u16),
            4 => self.write_u32(val as u32),
            8 => self.write_u64(val),
            _ => Err(Error::UnsupportedAddressSize(size)),
        }
    }

    /// Write an unsigned LEB128 value in at least `len` bytes; 0 writes the
    /// minimal encoding.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_uleb128(&mut self, val: u64, len: usize) -> Result<()> {
        write_bytes(self, |out| leb128::write_unsigned_padded(val, len, out))
    }

    /// Write a signed LEB128 value in at least `len` bytes; 0 writes the
    /// minimal encoding.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_sleb128(&mut self, val: i64, len: usize) -> Result<()> {
        write_bytes(self, |out| leb128::write_signed_padded(val, len, out))
    }

    /// Write zero bytes until the length is a multiple of `alignment`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAlignment`] if `alignment` is not a power of
    /// two, and the errors of [`write`](Self::write).
    fn align(&mut self, alignment: u32) -> Result<()> {
        let padding = padding(self.len(), check_alignment(alignment)?);
        for _ in 0..padding {
            self.write_u8(0)?;
        }
        Ok(())
    }
}

/// Write the bytes produced by `encode`, stopping at the first error.
fn write_bytes<W: Writer + ?Sized>(
    w: &mut W,
    encode: impl FnOnce(&mut dyn FnMut(u8)),
) -> Result<()> {
    let mut result = Ok(());
    encode(&mut |byte| {
        if result.is_ok() {
            result = w.write_u8(byte);
        }
    });
    result
}

/// Return `alignment` as a `usize`, or an error if it is not a power of two.
pub(crate) fn check_alignment(alignment: u32) -> Result<usize> {
    if alignment.is_power_of_two() {
        Ok(alignment as usize)
    } else {
        Err(Error::InvalidAlignment(alignment))
    }
}

/// Return the field size of a fixed-size encoding, or `None` for LEB128.
pub(crate) fn field_size(encoding: Encoding, format: Format) -> Result<Option<u8>> {
    if !encoding.is_valid() {
        return Err(Error::InvalidEncoding(encoding));
    }
    if !format.has_valid_address_size() {
        return Err(Error::UnsupportedAddressSize(format.address_size));
    }
    Ok(encoding.size(format.address_size))
}

/// Return the value that reading the field of `raw` written in `encoding`
/// (of `size` bytes, or LEB128) gives back.
pub(crate) fn read_back(encoding: Encoding, raw: u64, size: Option<u8>) -> u64 {
    match size {
        Some(size) if encoding.is_signed() => sign_extend(raw & size_mask(size), size),
        Some(size) => raw & size_mask(size),
        None => raw,
    }
}

/// Write a pointer to a constant address.
pub(crate) fn write_constant_pointer<W: Writer + ?Sized>(
    w: &mut W,
    encoding: Encoding,
    value: u64,
    format: Format,
    bases: &BaseAddresses,
) -> Result<()> {
    let size = field_size(encoding, format)?;
    if encoding.application() == DW_EH_PE_ALIGNED {
        w.align(u32::from(format.address_size))?;
    }
    let mask = format.address_mask();
    if value & !mask != 0 {
        return Err(Error::PointerOutOfRange(value));
    }
    if value == 0 {
        return write_raw(w, encoding, 0, size);
    }
    let base = bases
        .relative_base(encoding, w.len())
        .map_err(Error::MissingBaseAddress)?;
    let mut raw = value.wrapping_sub(base) & mask;
    if encoding.format() == DW_EH_PE_SLEB128 {
        // Keep negative offsets short.
        raw = sign_extend(raw, format.address_size);
    }
    // Check that reading the field back gives the same address, and is not
    // mistaken for a null pointer.
    let read_back = read_back(encoding, raw, size);
    if read_back == 0 || read_back.wrapping_add(base) & mask != value {
        return Err(Error::PointerOutOfRange(value));
    }
    write_raw(w, encoding, raw, size)
}

/// Write the raw field value of a pointer.
pub(crate) fn write_raw<W: Writer + ?Sized>(
    w: &mut W,
    encoding: Encoding,
    raw: u64,
    size: Option<u8>,
) -> Result<()> {
    match size {
        Some(size) => w.write_sized(raw, size),
        None if encoding.format() == DW_EH_PE_SLEB128 => w.write_sleb128(raw.cast_signed(), 0),
        None => w.write_uleb128(raw, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Base;
    use crate::endianity::LittleEndian;
    use crate::write::EndianVec;

    fn write(
        encoding: u8,
        address: u64,
        prefix: usize,
        format: Format,
    ) -> Result<alloc::vec::Vec<u8>> {
        let mut w = EndianVec::new(LittleEndian);
        w.write(&alloc::vec![0xaa; prefix])?;
        let bases = BaseAddresses::default().set_section(0x1000).set_text(0x400);
        w.write_pointer(
            Encoding(encoding),
            Address::Constant(address),
            format,
            &bases,
        )?;
        Ok(w.into_vec().split_off(prefix))
    }

    #[test]
    fn test_write_pointer() {
        let f8 = Format::new(8);
        let f4 = Format::new(4);
        assert_eq!(
            write(0x00, 0x1234, 0, f4),
            Ok(alloc::vec![0x34, 0x12, 0, 0])
        );
        assert_eq!(write(0x00, 0x1234, 0, f8).unwrap().len(), 8);
        // pcrel from 0x1004 to 0x1000.
        assert_eq!(
            write(0x1b, 0x1000, 4, f8),
            Ok(alloc::vec![0xfc, 0xff, 0xff, 0xff])
        );
        assert_eq!(
            write(0x9b, 0x2000, 0, f8),
            Ok(alloc::vec![0x00, 0x10, 0, 0])
        );
        // udata4 pcrel backwards only works with 4-byte addresses.
        assert_eq!(
            write(0x13, 0x1000, 4, f4),
            Ok(alloc::vec![0xfc, 0xff, 0xff, 0xff])
        );
        assert_eq!(
            write(0x13, 0x1000, 4, f8),
            Err(Error::PointerOutOfRange(0x1000))
        );
        assert_eq!(
            write(0x02, 0x1_0000, 0, f8),
            Err(Error::PointerOutOfRange(0x1_0000))
        );
        // Addresses wider than the address size are not truncated.
        assert_eq!(
            write(0x00, 0x1_0000_0000, 0, f4),
            Err(Error::PointerOutOfRange(0x1_0000_0000))
        );
        assert_eq!(
            write(0x00, 0x1_0000_1000, 0, f4),
            Err(Error::PointerOutOfRange(0x1_0000_1000))
        );
        assert_eq!(write(0x21, 0x480, 0, f8), Ok(alloc::vec![0x80, 0x01]));
        assert_eq!(write(0x19, 0xff0, 0, f8), Ok(alloc::vec![0x70]));
        assert_eq!(write(0x19, 0xff0, 0, f4), Ok(alloc::vec![0x70]));
        // Null stays null.
        assert_eq!(write(0x1b, 0, 4, f8), Ok(alloc::vec![0, 0, 0, 0]));
        // A non-null pointer that would read back as null.
        assert_eq!(
            write(0x1b, 0x1004, 4, f8),
            Err(Error::PointerOutOfRange(0x1004))
        );
        // Aligned pointers are padded first.
        assert_eq!(
            write(0x50, 0x10, 1, f4),
            Ok(alloc::vec![0, 0, 0, 0x10, 0, 0, 0])
        );
        assert_eq!(
            write(0x33, 0x10, 0, f8),
            Err(Error::MissingBaseAddress(Base::Data))
        );
        assert_eq!(
            write(0xff, 0x10, 0, f8),
            Err(Error::InvalidEncoding(Encoding::OMIT))
        );
        assert_eq!(
            write(0x00, 0x10, 0, Format::new(3)),
            Err(Error::UnsupportedAddressSize(3))
        );
        let mut w = EndianVec::new(LittleEndian);
        assert_eq!(
            w.write_pointer(
                Encoding::ABSPTR,
                Address::Symbol {
                    symbol: 0,
                    addend: 0
                },
                f8,
                &BaseAddresses::default()
            ),
            Err(Error::InvalidAddress)
        );
    }

    #[test]
    fn test_leb128_and_align() {
        let mut w = EndianVec::new(LittleEndian);
        w.write_uleb128(2, 3).unwrap();
        w.write_sleb128(-2, 0).unwrap();
        w.align(4).unwrap();
        w.align(1).unwrap();
        assert_eq!(w.slice(), [0x82, 0x80, 0x00, 0x7e]);
        w.write_u8(1).unwrap();
        w.align(8).unwrap();
        assert_eq!(w.len(), 8);
        assert_eq!(w.align(3), Err(Error::InvalidAlignment(3)));
        w.write_uleb128(1, 20).unwrap();
        assert_eq!(w.len(), 28);
    }
}
