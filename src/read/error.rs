use core::fmt;
use core::result;

use crate::common::{Base, Encoding};

/// An error that occurred when parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the expected data.
    UnexpectedEof,
    /// An unsigned LEB128 value was too large.
    BadUnsignedLeb128,
    /// A signed LEB128 value was too large.
    BadSignedLeb128,
    /// A fixed-size field of this size cannot be read.
    UnsupportedSize(u8),
    /// The address size is not 2, 4 or 8.
    UnsupportedAddressSize(u8),
    /// An offset or index was outside the section.
    OffsetOutOfBounds,
    /// A pointer encoding has an undefined format or application.
    InvalidEncoding(Encoding),
    /// The type table entries must have a fixed size, but the encoding is
    /// LEB128.
    VariableSizeTypeEncoding(Encoding),
    /// Call-site table values must be offsets, but the encoding has an
    /// application other than `DW_EH_PE_absptr`.
    UnsupportedCallSiteEncoding(Encoding),
    /// A base address that a pointer encoding needs was not provided.
    MissingBaseAddress(Base),
    /// The type table is used but the LSDA has no type table
    /// (`DW_EH_PE_omit` type table encoding).
    MissingTypeTable,
    /// A type index of zero was used; type table indices start at 1.
    InvalidTypeIndex,
    /// A chain of action records does not terminate.
    ActionCycle,
    /// A referenced action record does not start on a record boundary when
    /// the action table is read in sequence.
    MisalignedAction(usize),
    /// A referenced exception specification does not start on a list
    /// boundary when the exception specification table is read in sequence.
    MisalignedExceptionSpec(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::UnexpectedEof => f.write_str("unexpected end of input"),
            Error::BadUnsignedLeb128 => f.write_str("unsigned LEB128 value too large"),
            Error::BadSignedLeb128 => f.write_str("signed LEB128 value too large"),
            Error::UnsupportedSize(size) => write!(f, "unsupported field size {size}"),
            Error::UnsupportedAddressSize(size) => write!(f, "unsupported address size {size}"),
            Error::OffsetOutOfBounds => f.write_str("offset out of bounds"),
            Error::InvalidEncoding(encoding) => {
                write!(f, "invalid pointer encoding 0x{:02x}", encoding.0)
            }
            Error::VariableSizeTypeEncoding(encoding) => {
                write!(f, "type table encoding {encoding} has no fixed size")
            }
            Error::UnsupportedCallSiteEncoding(encoding) => {
                write!(f, "unsupported call-site encoding {encoding}")
            }
            Error::MissingBaseAddress(base) => write!(f, "the {base} base address is required"),
            Error::MissingTypeTable => f.write_str("the LSDA has no type table"),
            Error::InvalidTypeIndex => f.write_str("type index 0 is invalid"),
            Error::ActionCycle => f.write_str("action record chain does not terminate"),
            Error::MisalignedAction(offset) => {
                write!(
                    f,
                    "action record at offset {offset} is not on a record boundary"
                )
            }
            Error::MisalignedExceptionSpec(offset) => write!(
                f,
                "exception specification at offset {offset} is not on a list boundary"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// The result of a parse.
pub type Result<T> = result::Result<T, Error>;
