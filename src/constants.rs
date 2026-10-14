//! Constant definitions.
//!
//! The `DW_EH_PE_*` pointer encodings are defined by the Linux Standard Base
//! Core Specification 5.0, "Exception Frames", and implemented by libgcc's
//! `unwind-pe.h`, where they are spelled in lower case (`DW_EH_PE_absptr`).
//! An encoding byte combines a value format (low 4 bits), an
//! application (bits 4-6) and the indirect flag (bit 7).

/// The ELF section name of the exception tables.
pub const GCC_EXCEPT_TABLE: &str = ".gcc_except_table";

/// No value is present.
pub const DW_EH_PE_OMIT: u8 = 0xff;

/// Format: a pointer-sized unsigned value.
pub const DW_EH_PE_ABSPTR: u8 = 0x00;
/// Format: an unsigned LEB128 value.
pub const DW_EH_PE_ULEB128: u8 = 0x01;
/// Format: a 2-byte unsigned value.
pub const DW_EH_PE_UDATA2: u8 = 0x02;
/// Format: a 4-byte unsigned value.
pub const DW_EH_PE_UDATA4: u8 = 0x03;
/// Format: an 8-byte unsigned value.
pub const DW_EH_PE_UDATA8: u8 = 0x04;
/// Format: a signed LEB128 value.
pub const DW_EH_PE_SLEB128: u8 = 0x09;
/// Format: a 2-byte signed value.
pub const DW_EH_PE_SDATA2: u8 = 0x0a;
/// Format: a 4-byte signed value.
pub const DW_EH_PE_SDATA4: u8 = 0x0b;
/// Format: an 8-byte signed value.
pub const DW_EH_PE_SDATA8: u8 = 0x0c;
/// Format bit: the value is signed.
pub const DW_EH_PE_SIGNED: u8 = 0x08;

/// Application: the value is relative to the address of the field itself.
pub const DW_EH_PE_PCREL: u8 = 0x10;
/// Application: the value is relative to the start of the text section.
pub const DW_EH_PE_TEXTREL: u8 = 0x20;
/// Application: the value is relative to the data base, such as the GOT on
/// i386.
pub const DW_EH_PE_DATAREL: u8 = 0x30;
/// Application: the value is relative to the start of the function.
pub const DW_EH_PE_FUNCREL: u8 = 0x40;
/// Application: the value is a pointer-sized absolute value at the next
/// pointer-aligned address.
pub const DW_EH_PE_ALIGNED: u8 = 0x50;

/// Flag: the value is the address of a pointer to the real value.
pub const DW_EH_PE_INDIRECT: u8 = 0x80;
