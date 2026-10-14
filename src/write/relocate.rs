use crate::common::{BaseAddresses, Encoding, Format, Unwinder};
use crate::constants::*;
use crate::write::writer::{field_size, write_constant_pointer};
use crate::write::{Address, Error, Result, Writer};

/// A relocation to be applied to a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    /// The offset within the section where the relocation should be applied.
    pub offset: usize,
    /// The size of the relocated field in bytes.
    pub size: u8,
    /// The kind of relocation.
    pub kind: RelocationKind,
    /// The symbol that the relocation refers to.
    ///
    /// The meaning of this value is decided by the writer, but will typically
    /// be an index into a symbol table.
    pub symbol: usize,
    /// The addend to be applied to the relocated value.
    pub addend: i64,
}

/// The kind of a [`Relocation`].
///
/// The writer maps these to the relocation types of the target, for example
/// `R_X86_64_64` and `R_X86_64_PC32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationKind {
    /// The field holds the absolute address `S + A` (`DW_EH_PE_absptr` and
    /// `DW_EH_PE_aligned`).
    Absolute,
    /// The field holds the place-relative offset `S + A - P`
    /// (`DW_EH_PE_pcrel`).
    Relative,
    /// `R_ARM_TARGET2`: a platform-specific reference to a `type_info`
    /// object, used by the Arm EHABI for the type table and exception
    /// specifications.
    Target2,
}

/// A [`Writer`] which also records relocations.
///
/// Symbol addresses are recorded as relocations. The addend is also stored
/// in the relocated field, as REL relocations (used by i386 and Arm)
/// require. Consumers that emit RELA relocations can ignore those bits.
pub trait RelocateWriter {
    /// The type of the writer being used to write the section data.
    type Writer: Writer;

    /// Get the writer being used to write the section data.
    fn writer(&self) -> &Self::Writer;

    /// Get the writer being used to write the section data.
    fn writer_mut(&mut self) -> &mut Self::Writer;

    /// Record a relocation.
    fn relocate(&mut self, relocation: Relocation);
}

impl<T: RelocateWriter> Writer for T {
    type Endian = <<T as RelocateWriter>::Writer as Writer>::Endian;

    fn endian(&self) -> Self::Endian {
        self.writer().endian()
    }

    fn len(&self) -> usize {
        self.writer().len()
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer_mut().write(bytes)
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.writer_mut().write_at(offset, bytes)
    }

    fn write_pointer(
        &mut self,
        encoding: Encoding,
        address: Address,
        format: Format,
        bases: &BaseAddresses,
    ) -> Result<()> {
        let (symbol, addend) = match address {
            Address::Constant(value) => {
                return write_constant_pointer(self.writer_mut(), encoding, value, format, bases);
            }
            Address::Symbol { symbol, addend } => (symbol, addend),
        };
        let kind = match encoding.application() {
            DW_EH_PE_ABSPTR | DW_EH_PE_ALIGNED => RelocationKind::Absolute,
            DW_EH_PE_PCREL => RelocationKind::Relative,
            _ => return Err(Error::UnsupportedRelocationEncoding(encoding)),
        };
        let size =
            field_size(encoding, format)?.ok_or(Error::UnsupportedRelocationEncoding(encoding))?;
        write_relocation(self, size, kind, symbol, addend, encoding, format)
    }

    fn write_type_info(
        &mut self,
        encoding: Encoding,
        address: Address,
        format: Format,
        bases: &BaseAddresses,
    ) -> Result<()> {
        match address {
            Address::Symbol { symbol, addend } if format.unwinder == Unwinder::ArmEhabi => {
                let size = field_size(encoding, format)?
                    .ok_or(Error::UnsupportedRelocationEncoding(encoding))?;
                write_relocation(
                    self,
                    size,
                    RelocationKind::Target2,
                    symbol,
                    addend,
                    encoding,
                    format,
                )
            }
            _ => self.write_pointer(encoding, address, format, bases),
        }
    }
}

fn write_relocation<T: RelocateWriter + ?Sized>(
    w: &mut T,
    size: u8,
    kind: RelocationKind,
    symbol: usize,
    addend: i64,
    encoding: Encoding,
    format: Format,
) -> Result<()> {
    if encoding.application() == DW_EH_PE_ALIGNED {
        w.writer_mut().align(u32::from(format.address_size))?;
    }
    // Record the relocation only once its field has been written.
    let offset = w.writer().len();
    w.writer_mut().write_sized(addend.cast_unsigned(), size)?;
    w.relocate(Relocation {
        offset,
        size,
        kind,
        symbol,
        addend,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::write::EndianVec;
    use alloc::vec::Vec;

    struct Section<W> {
        writer: W,
        relocations: Vec<Relocation>,
    }

    impl<W: Writer> RelocateWriter for Section<W> {
        type Writer = W;

        fn writer(&self) -> &Self::Writer {
            &self.writer
        }

        fn writer_mut(&mut self) -> &mut Self::Writer {
            &mut self.writer
        }

        fn relocate(&mut self, relocation: Relocation) {
            self.relocations.push(relocation);
        }
    }

    #[test]
    fn test_relocate_writer() {
        let mut w = Section {
            writer: EndianVec::new(LittleEndian),
            relocations: Vec::new(),
        };
        let bases = BaseAddresses::default().set_section(0x100);
        let symbol = |symbol| Address::Symbol { symbol, addend: -4 };
        let f8 = Format::new(8);
        w.write_pointer(Encoding::INDIRECT_PCREL_SDATA4, symbol(1), f8, &bases)
            .unwrap();
        w.write_pointer(Encoding::ABSPTR, symbol(2), f8, &bases)
            .unwrap();
        w.write_pointer(Encoding::PCREL_SDATA4, Address::Constant(0x200), f8, &bases)
            .unwrap();
        w.write_type_info(Encoding::ABSPTR, symbol(3), Format::arm_ehabi(), &bases)
            .unwrap();
        assert_eq!(
            w.write_pointer(Encoding(0x21), symbol(4), f8, &bases),
            Err(Error::UnsupportedRelocationEncoding(Encoding(0x21)))
        );
        assert_eq!(
            w.write_pointer(Encoding(0x11), symbol(4), f8, &bases),
            Err(Error::UnsupportedRelocationEncoding(Encoding(0x11)))
        );
        assert_eq!(w.writer.len(), 20);
        assert_eq!(&w.writer.slice()[..4], [0xfc, 0xff, 0xff, 0xff]);
        assert_eq!(&w.writer.slice()[12..16], (0x200u32 - 0x10c).to_le_bytes());
        assert_eq!(
            w.relocations,
            [
                Relocation {
                    offset: 0,
                    size: 4,
                    kind: RelocationKind::Relative,
                    symbol: 1,
                    addend: -4,
                },
                Relocation {
                    offset: 4,
                    size: 8,
                    kind: RelocationKind::Absolute,
                    symbol: 2,
                    addend: -4,
                },
                Relocation {
                    offset: 16,
                    size: 4,
                    kind: RelocationKind::Target2,
                    symbol: 3,
                    addend: -4,
                },
            ]
        );
    }
}
