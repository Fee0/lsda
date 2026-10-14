use core::fmt;

use crate::constants::*;

/// A `DW_EH_PE_*` pointer encoding.
///
/// The low 4 bits select the value format, bits 4-6 how the value is applied
/// (absolute, or relative to some base), and bit 7 whether the result is the
/// address of the real value. `0xff` ([`Encoding::OMIT`]) means that no value
/// is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Encoding(pub u8);

impl Encoding {
    /// `DW_EH_PE_omit`: no value is present.
    pub const OMIT: Encoding = Encoding(DW_EH_PE_OMIT);
    /// `DW_EH_PE_absptr`: a pointer-sized absolute value.
    pub const ABSPTR: Encoding = Encoding(DW_EH_PE_ABSPTR);
    /// `DW_EH_PE_uleb128`.
    pub const ULEB128: Encoding = Encoding(DW_EH_PE_ULEB128);
    /// `DW_EH_PE_udata2`.
    pub const UDATA2: Encoding = Encoding(DW_EH_PE_UDATA2);
    /// `DW_EH_PE_udata4`.
    pub const UDATA4: Encoding = Encoding(DW_EH_PE_UDATA4);
    /// `DW_EH_PE_udata8`.
    pub const UDATA8: Encoding = Encoding(DW_EH_PE_UDATA8);
    /// `DW_EH_PE_sleb128`.
    pub const SLEB128: Encoding = Encoding(DW_EH_PE_SLEB128);
    /// `DW_EH_PE_sdata2`.
    pub const SDATA2: Encoding = Encoding(DW_EH_PE_SDATA2);
    /// `DW_EH_PE_sdata4`.
    pub const SDATA4: Encoding = Encoding(DW_EH_PE_SDATA4);
    /// `DW_EH_PE_sdata8`.
    pub const SDATA8: Encoding = Encoding(DW_EH_PE_SDATA8);
    /// `DW_EH_PE_pcrel | DW_EH_PE_sdata4`, common for position-independent
    /// code.
    pub const PCREL_SDATA4: Encoding = Encoding(DW_EH_PE_PCREL | DW_EH_PE_SDATA4);
    /// `DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4` (`0x9b`), the
    /// usual type table encoding of position-independent code.
    pub const INDIRECT_PCREL_SDATA4: Encoding =
        Encoding(DW_EH_PE_INDIRECT | DW_EH_PE_PCREL | DW_EH_PE_SDATA4);

    /// Return true if this is `DW_EH_PE_omit`.
    #[inline]
    #[must_use]
    pub fn is_omit(self) -> bool {
        self.0 == DW_EH_PE_OMIT
    }

    /// Return the value format: the low 4 bits.
    #[inline]
    #[must_use]
    pub fn format(self) -> u8 {
        self.0 & 0x0f
    }

    /// Return the application: bits 4-6.
    #[inline]
    #[must_use]
    pub fn application(self) -> u8 {
        self.0 & 0x70
    }

    /// Return true if the indirect flag is set.
    #[inline]
    #[must_use]
    pub fn is_indirect(self) -> bool {
        self.0 & DW_EH_PE_INDIRECT != 0
    }

    /// Return true if the format is signed.
    #[inline]
    #[must_use]
    pub fn is_signed(self) -> bool {
        self.0 & DW_EH_PE_SIGNED != 0
    }

    /// Return true if this is not `DW_EH_PE_omit` and both the format and
    /// the application are defined.
    #[must_use]
    pub fn is_valid(self) -> bool {
        !self.is_omit()
            && matches!(
                self.format(),
                DW_EH_PE_ABSPTR
                    | DW_EH_PE_ULEB128
                    | DW_EH_PE_UDATA2
                    | DW_EH_PE_UDATA4
                    | DW_EH_PE_UDATA8
                    | DW_EH_PE_SLEB128
                    | DW_EH_PE_SDATA2
                    | DW_EH_PE_SDATA4
                    | DW_EH_PE_SDATA8
            )
            && self.application() <= DW_EH_PE_ALIGNED
    }

    /// Return the size in bytes of a value in this encoding, or `None` if it
    /// is variable (LEB128) or the encoding is invalid.
    ///
    /// `DW_EH_PE_aligned` values are always pointer-sized.
    #[must_use]
    pub fn size(self, address_size: u8) -> Option<u8> {
        if !self.is_valid() {
            return None;
        }
        if self.application() == DW_EH_PE_ALIGNED {
            return Some(address_size);
        }
        match self.format() {
            DW_EH_PE_ABSPTR => Some(address_size),
            DW_EH_PE_UDATA2 | DW_EH_PE_SDATA2 => Some(2),
            DW_EH_PE_UDATA4 | DW_EH_PE_SDATA4 => Some(4),
            DW_EH_PE_UDATA8 | DW_EH_PE_SDATA8 => Some(8),
            _ => None,
        }
    }
}

impl Default for Encoding {
    fn default() -> Self {
        Encoding::OMIT
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_omit() {
            return f.write_str("DW_EH_PE_omit");
        }
        if !self.is_valid() {
            return write!(f, "<invalid encoding 0x{:02x}>", self.0);
        }
        let format = match self.format() {
            DW_EH_PE_ABSPTR => "absptr",
            DW_EH_PE_ULEB128 => "uleb128",
            DW_EH_PE_UDATA2 => "udata2",
            DW_EH_PE_UDATA4 => "udata4",
            DW_EH_PE_UDATA8 => "udata8",
            DW_EH_PE_SLEB128 => "sleb128",
            DW_EH_PE_SDATA2 => "sdata2",
            DW_EH_PE_SDATA4 => "sdata4",
            _ => "sdata8",
        };
        if self.is_indirect() {
            f.write_str("DW_EH_PE_indirect|")?;
        }
        match self.application() {
            DW_EH_PE_PCREL => f.write_str("DW_EH_PE_pcrel|")?,
            DW_EH_PE_TEXTREL => f.write_str("DW_EH_PE_textrel|")?,
            DW_EH_PE_DATAREL => f.write_str("DW_EH_PE_datarel|")?,
            DW_EH_PE_FUNCREL => f.write_str("DW_EH_PE_funcrel|")?,
            DW_EH_PE_ALIGNED => f.write_str("DW_EH_PE_aligned|")?,
            _ => {}
        }
        write!(f, "DW_EH_PE_{format}")
    }
}

/// The unwinder that the tables are used with.
///
/// This selects between variants of the format that the LSDA itself does not
/// record.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unwinder {
    /// The DWARF-based unwinder (the "zero-cost" table-driven model) used on
    /// most platforms.
    ///
    /// Call-site entries hold a code range, a landing pad and an action, and
    /// exception specifications are lists of ULEB128 type indices.
    #[default]
    Dwarf,
    /// The Arm EHABI unwinder (`__ARM_EABI_UNWINDER__`), where the LSDA
    /// follows the unwinding instructions in `.ARM.extab`.
    ///
    /// Call sites are as for [`Unwinder::Dwarf`], but exception
    /// specifications are lists of `type_info` references (written with
    /// `R_ARM_TARGET2` relocations) encoded like the type table entries, each
    /// list terminated by a null entry. A negative filter counts entries
    /// rather than bytes.
    ArmEhabi,
    /// The setjmp/longjmp unwinder (`__USING_SJLJ_EXCEPTIONS__`), also the
    /// layout used for WebAssembly exception handling.
    ///
    /// Call-site entries hold only a landing pad (dispatch) value and an
    /// action, both ULEB128; the call site is identified by its 1-based index
    /// in the table. Exception specifications are as for [`Unwinder::Dwarf`].
    SjLj,
}

/// The target properties needed to parse or write an LSDA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Format {
    /// The size of a pointer in bytes, used by `DW_EH_PE_absptr` and
    /// `DW_EH_PE_aligned`: 4 or 8 (2 is also accepted).
    pub address_size: u8,
    /// The unwinder variant.
    pub unwinder: Unwinder,
}

impl Format {
    /// Return the format for the DWARF unwinder with the given address size.
    #[inline]
    #[must_use]
    pub fn new(address_size: u8) -> Self {
        Format {
            address_size,
            unwinder: Unwinder::Dwarf,
        }
    }

    /// Return the format of the Arm EHABI: 4-byte addresses and
    /// [`Unwinder::ArmEhabi`].
    #[inline]
    #[must_use]
    pub fn arm_ehabi() -> Self {
        Format {
            address_size: 4,
            unwinder: Unwinder::ArmEhabi,
        }
    }

    /// Return a copy with the unwinder set to `unwinder`.
    #[inline]
    #[must_use]
    pub fn with_unwinder(mut self, unwinder: Unwinder) -> Self {
        self.unwinder = unwinder;
        self
    }

    /// Return a mask of the low `address_size * 8` bits.
    #[cfg(any(feature = "read", feature = "write"))]
    #[inline]
    pub(crate) fn address_mask(self) -> u64 {
        if self.address_size >= 8 {
            u64::MAX
        } else {
            (1u64 << (u32::from(self.address_size) * 8)) - 1
        }
    }
}

/// The base addresses that relative pointer encodings are resolved against.
///
/// Reading resolves an encoded pointer to an address by adding the base for
/// its application; writing subtracts it. Only the bases that the encodings
/// in use require must be set.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BaseAddresses {
    /// The address of the section that holds the LSDA, used by
    /// `DW_EH_PE_pcrel`. This is `.gcc_except_table`, or `.ARM.extab` for
    /// the Arm EHABI.
    pub section: Option<u64>,
    /// The text base, used by `DW_EH_PE_textrel`.
    pub text: Option<u64>,
    /// The data base, used by `DW_EH_PE_datarel` (the GOT on i386).
    pub data: Option<u64>,
    /// The start address of the function, used by `DW_EH_PE_funcrel`.
    pub function: Option<u64>,
}

impl BaseAddresses {
    /// Set the address of the section that holds the LSDA.
    #[inline]
    #[must_use]
    pub fn set_section(mut self, address: u64) -> Self {
        self.section = Some(address);
        self
    }

    /// Set the text base.
    #[inline]
    #[must_use]
    pub fn set_text(mut self, address: u64) -> Self {
        self.text = Some(address);
        self
    }

    /// Set the data base.
    #[inline]
    #[must_use]
    pub fn set_data(mut self, address: u64) -> Self {
        self.data = Some(address);
        self
    }

    /// Set the start address of the function.
    #[inline]
    #[must_use]
    pub fn set_function(mut self, address: u64) -> Self {
        self.function = Some(address);
        self
    }

    /// Return the given base, if known.
    #[inline]
    #[must_use]
    pub fn get(&self, base: Base) -> Option<u64> {
        match base {
            Base::Section => self.section,
            Base::Text => self.text,
            Base::Data => self.data,
            Base::Function => self.function,
        }
    }
}

/// One of the base addresses in [`BaseAddresses`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base {
    /// The address of the section holding the LSDA (`DW_EH_PE_pcrel`).
    Section,
    /// The text base (`DW_EH_PE_textrel`).
    Text,
    /// The data base (`DW_EH_PE_datarel`).
    Data,
    /// The function start (`DW_EH_PE_funcrel`).
    Function,
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Base::Section => "section",
            Base::Text => "text",
            Base::Data => "data",
            Base::Function => "function",
        })
    }
}

/// Return the base address that a pointer with the given application is
/// relative to, or `None` for absolute applications.
#[cfg(any(feature = "read", feature = "write"))]
pub(crate) fn application_base(application: u8) -> Option<Base> {
    match application {
        DW_EH_PE_PCREL => Some(Base::Section),
        DW_EH_PE_TEXTREL => Some(Base::Text),
        DW_EH_PE_DATAREL => Some(Base::Data),
        DW_EH_PE_FUNCREL => Some(Base::Function),
        _ => None,
    }
}

/// An offset into the section that holds the LSDAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LsdaOffset<T = usize>(pub T);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_encoding() {
        let e = Encoding::INDIRECT_PCREL_SDATA4;
        assert_eq!(e.0, 0x9b);
        assert_eq!(e.format(), DW_EH_PE_SDATA4);
        assert_eq!(e.application(), DW_EH_PE_PCREL);
        assert!(e.is_indirect() && e.is_signed() && e.is_valid());
        assert_eq!(e.size(8), Some(4));
        assert_eq!(Encoding::ABSPTR.size(8), Some(8));
        assert_eq!(Encoding::ULEB128.size(8), None);
        assert_eq!(Encoding(DW_EH_PE_ALIGNED).size(4), Some(4));
        assert!(!Encoding::OMIT.is_valid());
        assert!(!Encoding(0x05).is_valid());
        assert!(!Encoding(0x60).is_valid());
        assert_eq!(
            e.to_string(),
            "DW_EH_PE_indirect|DW_EH_PE_pcrel|DW_EH_PE_sdata4"
        );
        assert_eq!(Encoding::ULEB128.to_string(), "DW_EH_PE_uleb128");
        assert_eq!(Encoding(0x0d).to_string(), "<invalid encoding 0x0d>");
    }

    #[test]
    #[cfg(any(feature = "read", feature = "write"))]
    fn test_address_mask() {
        assert_eq!(Format::new(4).address_mask(), 0xffff_ffff);
        assert_eq!(Format::new(8).address_mask(), u64::MAX);
    }
}
