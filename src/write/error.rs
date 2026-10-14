use core::fmt;
use core::result;

use crate::common::{Base, Encoding};

/// An error that occurred when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A symbol address was used with a writer that does not support
    /// relocations.
    InvalidAddress,
    /// A base address that a pointer encoding needs was not provided.
    MissingBaseAddress(Base),
    /// The address size is not 2, 4 or 8.
    UnsupportedAddressSize(u8),
    /// A pointer encoding has an undefined format or application, or is
    /// `DW_EH_PE_omit` where a value is required.
    InvalidEncoding(Encoding),
    /// A relocation cannot be expressed in this encoding: it must have a
    /// fixed size and an absolute or pc-relative application.
    UnsupportedRelocationEncoding(Encoding),
    /// Call-site table values must be offsets: the encoding must have the
    /// `DW_EH_PE_absptr` application.
    UnsupportedCallSiteEncoding(Encoding),
    /// The type table encoding has no fixed size.
    VariableSizeTypeEncoding(Encoding),
    /// The address cannot be represented in the pointer encoding.
    PointerOutOfRange(u64),
    /// A call-site value does not fit in the call-site encoding.
    ValueOutOfRange(u64),
    /// The LSDA has types or exception specifications, but its type table
    /// encoding is `DW_EH_PE_omit`.
    MissingTypeTable,
    /// A `TypeId` does not refer to an entry of the type table.
    InvalidTypeId,
    /// An `ActionId` does not refer to an action record.
    InvalidActionId,
    /// A `SpecId` does not refer to an exception specification.
    InvalidSpecId,
    /// An `LsdaId` does not belong to this table.
    InvalidLsdaId,
    /// An exception specification does not match the unwinder: the Arm
    /// EHABI requires [`ExceptionSpec::TypeInfos`](crate::write::ExceptionSpec::TypeInfos),
    /// the others [`ExceptionSpec::Types`](crate::write::ExceptionSpec::Types).
    ExceptionSpecMismatch,
    /// An alignment is not a power of two.
    InvalidAlignment(u32),
    /// A write was attempted beyond the end of the section.
    OffsetOutOfBounds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InvalidAddress => {
                f.write_str("symbol address used with a writer that does not support relocations")
            }
            Error::MissingBaseAddress(base) => write!(f, "the {base} base address is required"),
            Error::UnsupportedAddressSize(size) => write!(f, "unsupported address size {size}"),
            Error::InvalidEncoding(encoding) => {
                write!(f, "invalid pointer encoding 0x{:02x}", encoding.0)
            }
            Error::UnsupportedRelocationEncoding(encoding) => {
                write!(f, "cannot relocate a pointer with encoding {encoding}")
            }
            Error::UnsupportedCallSiteEncoding(encoding) => {
                write!(f, "unsupported call-site encoding {encoding}")
            }
            Error::VariableSizeTypeEncoding(encoding) => {
                write!(f, "type table encoding {encoding} has no fixed size")
            }
            Error::PointerOutOfRange(address) => {
                write!(
                    f,
                    "address 0x{address:x} cannot be represented in the encoding"
                )
            }
            Error::ValueOutOfRange(value) => {
                write!(
                    f,
                    "call-site value 0x{value:x} does not fit in the encoding"
                )
            }
            Error::MissingTypeTable => {
                f.write_str("the LSDA has types but its type table encoding is DW_EH_PE_omit")
            }
            Error::InvalidTypeId => f.write_str("invalid type id"),
            Error::InvalidActionId => f.write_str("invalid action id"),
            Error::InvalidSpecId => f.write_str("invalid exception specification id"),
            Error::InvalidLsdaId => f.write_str("invalid LSDA id"),
            Error::ExceptionSpecMismatch => {
                f.write_str("exception specification does not match the unwinder")
            }
            Error::InvalidAlignment(alignment) => {
                write!(f, "alignment {alignment} is not a power of two")
            }
            Error::OffsetOutOfBounds => f.write_str("offset out of bounds"),
        }
    }
}

impl core::error::Error for Error {}

/// The result of a write.
pub type Result<T> = result::Result<T, Error>;
