use alloc::vec::Vec;

use crate::common::{ARM_SPEC_ENTRY_SIZE, padding};
use crate::common::{BaseAddresses, Encoding, Format, LsdaOffset, Unwinder};
use crate::constants::*;
use crate::leb128;
use crate::write::writer::{check_alignment, field_size, read_back, write_raw};
use crate::write::{Address, EndianVec, Error, Result, Writer};

/// A table of LSDAs, which can be written to `.gcc_except_table`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GccExceptTable {
    format: Format,
    entries: Vec<Entry>,
}

/// An identifier for an entry added to a [`GccExceptTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LsdaId(usize);

impl GccExceptTable {
    /// Create a new, empty table for the given format.
    #[must_use]
    pub fn new(format: Format) -> Self {
        GccExceptTable {
            format,
            entries: Vec::new(),
        }
    }

    /// Return the format of the table.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Add an entry, returning its id.
    pub fn add(&mut self, entry: Entry) -> LsdaId {
        self.entries.push(entry);
        LsdaId(self.entries.len() - 1)
    }

    /// Add an LSDA aligned to 4 bytes, as LLVM and (for the common type
    /// table encodings) GCC emit them, returning its id.
    pub fn add_lsda(&mut self, lsda: Lsda) -> LsdaId {
        self.add(Entry {
            alignment: 4,
            data: EntryData::Lsda(lsda),
        })
    }

    /// Get an entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[must_use]
    pub fn get(&self, id: LsdaId) -> &Entry {
        &self.entries[id.0]
    }

    /// Get an entry for modification.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get_mut(&mut self, id: LsdaId) -> &mut Entry {
        &mut self.entries[id.0]
    }

    /// Return the entries, in the order they are written.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Write the table to the given section.
    ///
    /// Each entry is preceded by zero padding up to its alignment. Offsets
    /// and alignment are relative to the start of the writer, which should
    /// be the start of the section. `bases` must contain the base addresses
    /// for the pointer encodings in use, such as `bases.section` for
    /// `DW_EH_PE_pcrel` constants; a writer that records relocations does not
    /// need them for symbol addresses.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Lsda::write`] and of the writer.
    pub fn write<W: Writer>(&self, w: &mut W, bases: &BaseAddresses) -> Result<LsdaOffsets> {
        let mut offsets = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            w.align(entry.alignment)?;
            offsets.push(LsdaOffset(w.len()));
            match &entry.data {
                EntryData::Lsda(lsda) => lsda.write(w, self.format, bases)?,
                EntryData::Raw(data) => w.write(data)?,
            }
        }
        Ok(LsdaOffsets(offsets))
    }
}

/// The offsets of the entries written by [`GccExceptTable::write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsdaOffsets(Vec<LsdaOffset>);

impl LsdaOffsets {
    /// Get the offset of the entry with the given id.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[must_use]
    pub fn get(&self, id: LsdaId) -> LsdaOffset {
        self.0[id.0]
    }
}

/// An entry in a [`GccExceptTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The alignment of the start of the entry, a power of two. GCC aligns
    /// an LSDA with a type table to the size of a type table entry, LLVM
    /// aligns every LSDA to 4.
    pub alignment: u32,
    /// The contents of the entry.
    pub data: EntryData,
}

/// The contents of an [`Entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryData {
    /// An LSDA.
    Lsda(Lsda),
    /// Uninterpreted bytes, written as-is. Any relocations they need are not
    /// recorded.
    Raw(Vec<u8>),
}

/// An identifier for an action record in an [`Lsda`]: its index in
/// [`Lsda::actions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId(pub usize);

/// An identifier for a type table entry in an [`Lsda`]: its index in
/// [`Lsda::types`]. It is written as the 1-based type index `id + 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub usize);

/// An identifier for an exception specification in an [`Lsda`]: its index
/// in [`Lsda::exception_specs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpecId(pub usize);

/// The landing pad base of an [`Lsda`] (`@LPStart`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LpStart {
    /// The encoding of the pointer.
    pub encoding: Encoding,
    /// The address.
    pub address: Address,
}

/// The language-specific data area of one function.
///
/// The tables are written in the order given, so writing a converted LSDA
/// reproduces the original layout. Ids refer to entries by their index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsda {
    /// The landing pad base. `None` (written as `DW_EH_PE_omit`) makes
    /// landing pads relative to the start of the function, which is what GCC
    /// and LLVM emit unless a function is split into several sections.
    pub lpstart: Option<LpStart>,
    /// The encoding of the type table entries, or `DW_EH_PE_omit` if there is
    /// no type table. It must have a fixed size.
    ///
    /// GCC and LLVM use `DW_EH_PE_indirect | DW_EH_PE_pcrel |
    /// DW_EH_PE_sdata4` for position-independent code, and
    /// `DW_EH_PE_absptr` (or `DW_EH_PE_udata4`) otherwise; Arm EHABI uses
    /// `DW_EH_PE_absptr` with `R_ARM_TARGET2` relocations.
    pub ttype_encoding: Encoding,
    /// The encoding of the call-site table values. GCC and LLVM use
    /// `DW_EH_PE_uleb128` (older versions `DW_EH_PE_udata4`). Ignored by the
    /// SJLJ unwinder, which always uses ULEB128.
    pub call_site_encoding: Encoding,
    /// The alignment of the start of the type table, a power of two. GCC
    /// aligns it to the size of a type table entry, LLVM to 4. The type
    /// table base offset is padded if necessary, as assemblers do. With a
    /// `DW_EH_PE_aligned` type table encoding, the table is aligned to at
    /// least the address size.
    pub type_table_alignment: u32,
    /// The call-site table, sorted by start offset for the DWARF and Arm
    /// EHABI unwinders.
    pub call_sites: Vec<CallSite>,
    /// The action table, in table order.
    pub actions: Vec<Action>,
    /// The type table: `types[i]` has the 1-based index `i + 1`. `None` is a
    /// null entry, which catches any exception.
    pub types: Vec<Option<Address>>,
    /// The exception specification table, in table order.
    pub exception_specs: Vec<ExceptionSpec>,
}

impl Default for Lsda {
    fn default() -> Self {
        Lsda::new()
    }
}

/// An entry in the call-site table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallSite {
    /// The start of the code region, as an offset from the start of the
    /// function. Not written for the SJLJ unwinder.
    pub start: u64,
    /// The length of the code region. Not written for the SJLJ unwinder.
    pub length: u64,
    /// The landing pad as an offset from the landing pad base, or 0 for
    /// none. For the SJLJ unwinder, the dispatch value minus one.
    pub landing_pad: u64,
    /// The first action record, or `None` for cleanups only.
    pub action: Option<ActionId>,
}

/// A record in the action table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Action {
    /// The filter.
    pub filter: Filter,
    /// The next record in the chain.
    pub next: Option<ActionId>,
}

/// What an action record does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Filter {
    /// Run cleanups.
    Cleanup,
    /// Catch the type with this type table entry.
    Catch(TypeId),
    /// Check an exception specification.
    ExceptionSpec(SpecId),
}

/// An exception specification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExceptionSpec {
    /// The types that may be thrown, as type table entries (DWARF and SJLJ
    /// unwinders). Empty for `throw()`.
    Types(Vec<TypeId>),
    /// The types that may be thrown, as `type_info` references written like
    /// type table entries, with `R_ARM_TARGET2` relocations (Arm EHABI). They
    /// are not part of the type table. Empty for `throw()`.
    TypeInfos(Vec<Address>),
}

impl Lsda {
    /// Create an LSDA without a type table, with ULEB128 call-site values
    /// and a type table alignment of 4.
    #[must_use]
    pub fn new() -> Self {
        Lsda {
            lpstart: None,
            ttype_encoding: Encoding::OMIT,
            call_site_encoding: Encoding::ULEB128,
            type_table_alignment: 4,
            call_sites: Vec::new(),
            actions: Vec::new(),
            types: Vec::new(),
            exception_specs: Vec::new(),
        }
    }

    /// Add an action record, returning its id.
    pub fn add_action(&mut self, action: Action) -> ActionId {
        self.actions.push(action);
        ActionId(self.actions.len() - 1)
    }

    /// Add a type table entry, returning its id. `None` catches any
    /// exception.
    pub fn add_type(&mut self, type_info: Option<Address>) -> TypeId {
        self.types.push(type_info);
        TypeId(self.types.len() - 1)
    }

    /// Return the id of the type table entry for `type_info`, adding it if
    /// it is not present.
    pub fn find_or_add_type(&mut self, type_info: Option<Address>) -> TypeId {
        match self.types.iter().position(|t| *t == type_info) {
            Some(index) => TypeId(index),
            None => self.add_type(type_info),
        }
    }

    /// Add an exception specification, returning its id.
    pub fn add_exception_spec(&mut self, spec: ExceptionSpec) -> SpecId {
        self.exception_specs.push(spec);
        SpecId(self.exception_specs.len() - 1)
    }

    /// Write the LSDA at the current position of `w`.
    ///
    /// The caller is responsible for aligning the start, which matters
    /// because the type table is aligned relative to the start of the
    /// writer. This can also be used to write the LSDA of an Arm EHABI
    /// `.ARM.extab` entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingTypeTable`] if there are types or exception
    /// specifications without a type table encoding,
    /// [`Error::VariableSizeTypeEncoding`],
    /// [`Error::UnsupportedCallSiteEncoding`], [`Error::ValueOutOfRange`] for a
    /// call-site value that does not fit its encoding,
    /// [`Error::InvalidActionId`], [`Error::InvalidTypeId`] or
    /// [`Error::InvalidSpecId`] for a dangling id,
    /// [`Error::ExceptionSpecMismatch`], [`Error::NullTypeInfo`],
    /// [`Error::InvalidAlignment`], and the errors of
    /// [`Writer::write_pointer`].
    ///
    /// Every error is reported before anything is written, except those that
    /// depend on where a pointer is written (a pc-relative displacement that
    /// does not fit its format) and those of the writer itself (such as a
    /// symbol address for a writer that does not record relocations). After
    /// such an error, `w` may hold part of the LSDA.
    pub fn write<W: Writer>(&self, w: &mut W, format: Format, bases: &BaseAddresses) -> Result<()> {
        let arm = format.unwinder == Unwinder::ArmEhabi;
        let has_type_table = !self.ttype_encoding.is_omit();
        if !has_type_table && (!self.types.is_empty() || !self.exception_specs.is_empty()) {
            return Err(Error::MissingTypeTable);
        }
        let type_size = if has_type_table {
            usize::from(
                field_size(self.ttype_encoding, format)?
                    .ok_or(Error::VariableSizeTypeEncoding(self.ttype_encoding))?,
            )
        } else {
            0
        };
        let mut type_table_alignment = check_alignment(self.type_table_alignment)?;
        if self.ttype_encoding.application() == DW_EH_PE_ALIGNED {
            // Each entry is aligned to the address size, so the table must
            // start aligned for the entries to be where the base implies.
            type_table_alignment = type_table_alignment.max(usize::from(format.address_size));
        }

        let spec_offsets = self.spec_offsets(arm)?;
        let (actions, action_offsets) = self.encode_actions(w, &spec_offsets)?;
        let call_sites = self.encode_call_sites(w, format, &action_offsets)?;
        self.check_pointers(format, bases)?;

        if let Some(lpstart) = self.lpstart {
            w.write_u8(lpstart.encoding.0)?;
            w.write_pointer(lpstart.encoding, lpstart.address, format, bases)?;
        } else {
            w.write_u8(DW_EH_PE_OMIT)?;
        }
        w.write_u8(self.ttype_encoding.0)?;

        // The bytes after the type table base offset, up to the start of the
        // type table (before alignment).
        let body_len =
            1 + leb128::unsigned_len(call_sites.len() as u64) + call_sites.len() + actions.len();
        let mut types_start = 0;
        if has_type_table {
            // The offset's length moves everything after it, which may change
            // the padding and so the offset. As assemblers do, only ever grow
            // the field, padding the encoding if the value shrinks.
            let field = w.len();
            let mut len = 1;
            let value = loop {
                let after = field + len;
                types_start = after + body_len;
                types_start += padding(types_start, type_table_alignment);
                let base = types_start + self.types.len() * type_size;
                let value = (base - after) as u64;
                let needed = leb128::unsigned_len(value);
                if needed <= len {
                    break value;
                }
                len = needed;
            };
            w.write_uleb128(value, len)?;
        }

        w.write_u8(self.call_site_encoding.0)?;
        w.write_uleb128(call_sites.len() as u64, 0)?;
        w.write(&call_sites)?;
        w.write(&actions)?;
        if !has_type_table {
            return Ok(());
        }

        w.align(type_table_alignment as u32)?;
        debug_assert_eq!(w.len(), types_start);
        for type_info in self.types.iter().rev() {
            let address = type_info.unwrap_or(Address::Constant(0));
            w.write_type_info(self.ttype_encoding, address, format, bases)?;
        }
        for spec in &self.exception_specs {
            match spec {
                ExceptionSpec::Types(types) => {
                    for id in types {
                        w.write_uleb128(id.0 as u64 + 1, 0)?;
                    }
                    w.write_u8(0)?;
                }
                ExceptionSpec::TypeInfos(type_infos) => {
                    let encoding = Encoding::UDATA4;
                    debug_assert_eq!(encoding.size(4), Some(ARM_SPEC_ENTRY_SIZE));
                    for address in type_infos {
                        w.write_type_info(encoding, *address, format, bases)?;
                    }
                    w.write_u32(0)?;
                }
            }
        }
        Ok(())
    }

    /// Check the pointers for the errors that do not depend on where they are
    /// written, so that they are reported before anything is written.
    fn check_pointers(&self, format: Format, bases: &BaseAddresses) -> Result<()> {
        let check = |encoding: Encoding, address: Address| -> Result<()> {
            field_size(encoding, format)?;
            if let Address::Constant(value) = address {
                if value & !format.address_mask() != 0 {
                    return Err(Error::PointerOutOfRange(value));
                }
                if value != 0 {
                    bases
                        .relative_base(encoding, 0)
                        .map_err(Error::MissingBaseAddress)?;
                }
            }
            Ok(())
        };
        if let Some(lpstart) = self.lpstart {
            check(lpstart.encoding, lpstart.address)?;
        }
        for address in self.types.iter().flatten() {
            check(self.ttype_encoding, *address)?;
        }
        for spec in &self.exception_specs {
            if let ExceptionSpec::TypeInfos(type_infos) = spec {
                for address in type_infos {
                    check(Encoding::UDATA4, *address)?;
                }
            }
        }
        Ok(())
    }

    /// Return the offset of each exception specification: in bytes, or in
    /// entries for the Arm EHABI.
    fn spec_offsets(&self, arm: bool) -> Result<Vec<usize>> {
        let mut offsets = Vec::with_capacity(self.exception_specs.len());
        let mut offset = 0;
        for spec in &self.exception_specs {
            offsets.push(offset);
            offset += match spec {
                ExceptionSpec::Types(types) if !arm => {
                    for id in types {
                        if id.0 >= self.types.len() {
                            return Err(Error::InvalidTypeId);
                        }
                    }
                    types
                        .iter()
                        .map(|id| leb128::unsigned_len(id.0 as u64 + 1))
                        .sum::<usize>()
                        + 1
                }
                ExceptionSpec::TypeInfos(type_infos) if arm => {
                    // A null entry is the terminator.
                    if type_infos.contains(&Address::Constant(0)) {
                        return Err(Error::NullTypeInfo);
                    }
                    type_infos.len() + 1
                }
                _ => return Err(Error::ExceptionSpecMismatch),
            };
        }
        Ok(offsets)
    }

    /// Encode the action table, returning its bytes and the offset of each
    /// record.
    fn encode_actions<W: Writer>(
        &self,
        w: &W,
        spec_offsets: &[usize],
    ) -> Result<(Vec<u8>, Vec<usize>)> {
        let mut filters = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            let filter = match action.filter {
                Filter::Cleanup => 0,
                Filter::Catch(id) => {
                    if id.0 >= self.types.len() {
                        return Err(Error::InvalidTypeId);
                    }
                    signed(id.0) + 1
                }
                Filter::ExceptionSpec(id) => {
                    let offset = spec_offsets.get(id.0).ok_or(Error::InvalidSpecId)?;
                    -signed(*offset) - 1
                }
            };
            if action.next.is_some_and(|next| next.0 >= self.actions.len()) {
                return Err(Error::InvalidActionId);
            }
            filters.push(filter);
        }

        // The displacement of each record's next field depends on the
        // offsets of the records, which depend on the lengths of the
        // displacements. Grow the fields until they are stable; a field
        // whose value then needs fewer bytes is padded.
        let mut disp_lens = alloc::vec![1; self.actions.len()];
        let mut offsets = Vec::with_capacity(self.actions.len());
        let mut displacements = Vec::with_capacity(self.actions.len());
        loop {
            offsets.clear();
            displacements.clear();
            let mut offset = 0;
            for (filter, disp_len) in filters.iter().zip(&disp_lens) {
                offsets.push(offset);
                offset += leb128::signed_len(*filter) + disp_len;
            }
            let mut changed = false;
            for (i, action) in self.actions.iter().enumerate() {
                let displacement = action.next.map_or(0, |next| {
                    let place = offsets[i] + leb128::signed_len(filters[i]);
                    signed(offsets[next.0]) - signed(place)
                });
                let needed = leb128::signed_len(displacement);
                if needed > disp_lens[i] {
                    disp_lens[i] = needed;
                    changed = true;
                }
                displacements.push(displacement);
            }
            if !changed {
                break;
            }
        }

        let mut bytes = EndianVec::new(w.endian());
        for ((filter, displacement), disp_len) in filters.iter().zip(displacements).zip(disp_lens) {
            bytes.write_sleb128(*filter, 0)?;
            bytes.write_sleb128(displacement, disp_len)?;
        }
        Ok((bytes.into_vec(), offsets))
    }

    /// Encode the call-site table.
    fn encode_call_sites<W: Writer>(
        &self,
        w: &W,
        format: Format,
        action_offsets: &[usize],
    ) -> Result<Vec<u8>> {
        let sjlj = format.unwinder == Unwinder::SjLj;
        // The SJLJ personality reads ULEB128 values whatever the encoding.
        let encoding = if sjlj {
            Encoding::ULEB128
        } else {
            self.call_site_encoding
        };
        if !encoding.is_offset_encoding() {
            return Err(Error::UnsupportedCallSiteEncoding(encoding));
        }
        let size = field_size(encoding, format)?;
        let mut bytes = EndianVec::new(w.endian());
        let value = |bytes: &mut EndianVec<W::Endian>, value: u64| {
            if read_back(encoding, value, size) != value {
                return Err(Error::ValueOutOfRange(value));
            }
            write_raw(bytes, encoding, value, size)
        };
        for call_site in &self.call_sites {
            if !sjlj {
                value(&mut bytes, call_site.start)?;
                value(&mut bytes, call_site.length)?;
            }
            value(&mut bytes, call_site.landing_pad)?;
            let action = match call_site.action {
                Some(id) => *action_offsets.get(id.0).ok_or(Error::InvalidActionId)? as u64 + 1,
                None => 0,
            };
            bytes.write_uleb128(action, 0)?;
        }
        Ok(bytes.into_vec())
    }
}

/// Convert a table offset or index, which is far below `i64::MAX`.
fn signed(value: usize) -> i64 {
    value.cast_signed() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    #[cfg(feature = "read")]
    use crate::read;

    /// The LSDA of the read module's sample, built by hand.
    #[cfg(feature = "read")]
    fn sample() -> Lsda {
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = Encoding::INDIRECT_PCREL_SDATA4;
        let int = lsda.add_type(Some(Address::Constant(0x3020)));
        let any = lsda.add_type(None);
        let spec = lsda.add_exception_spec(ExceptionSpec::Types(alloc::vec![int]));
        let catch_any = ActionId(1);
        let first = lsda.add_action(Action {
            filter: Filter::Catch(int),
            next: Some(catch_any),
        });
        lsda.add_action(Action {
            filter: Filter::Catch(any),
            next: None,
        });
        let cleanup = lsda.add_action(Action {
            filter: Filter::Cleanup,
            next: None,
        });
        let spec = lsda.add_action(Action {
            filter: Filter::ExceptionSpec(spec),
            next: Some(cleanup),
        });
        lsda.call_sites = alloc::vec![
            CallSite {
                start: 4,
                length: 8,
                landing_pad: 0x20,
                action: Some(first),
            },
            CallSite {
                start: 0x10,
                length: 4,
                landing_pad: 0x30,
                action: None,
            },
            CallSite {
                start: 0x14,
                length: 4,
                landing_pad: 0,
                action: Some(spec),
            },
        ];
        lsda
    }

    #[test]
    #[cfg(feature = "read")]
    fn test_write_lsda() {
        let lsda = sample();
        let mut w = EndianVec::new(LittleEndian);
        let bases = BaseAddresses::default().set_section(0x2000);
        lsda.write(&mut w, Format::new(8), &bases).unwrap();
        assert_eq!(
            w.slice(),
            [
                0xff, 0x9b, 0x21, 0x01, 0x0c, //
                0x04, 0x08, 0x20, 0x01, 0x10, 0x04, 0x30, 0x00, 0x14, 0x04, 0x00, 0x07, //
                0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x7f, 0x7d, //
                0x00, 0x00, 0x00, //
                0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, //
                0x01, 0x00,
            ]
        );

        // It reads back the same.
        let table = read::GccExceptTable::new(w.slice(), LittleEndian, Format::new(8));
        let tables = table
            .lsda_at(LsdaOffset(0))
            .unwrap()
            .parse_tables()
            .unwrap();
        assert_eq!(tables.end, w.len());
        assert_eq!(tables.types[0].address(&bases), Ok(0x3020));
    }

    #[test]
    #[cfg(feature = "read")]
    fn test_ttype_offset_padding() {
        // A call-site table long enough that the type table base offset
        // needs two bytes.
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = Encoding::UDATA4;
        let any = lsda.add_type(None);
        let action = lsda.add_action(Action {
            filter: Filter::Catch(any),
            next: None,
        });
        for i in 0..40 {
            lsda.call_sites.push(CallSite {
                start: i * 4,
                length: 4,
                landing_pad: 0x200,
                action: Some(action),
            });
        }
        for start in 0..8 {
            let mut w = EndianVec::new(LittleEndian);
            w.write(&alloc::vec![0; start]).unwrap();
            lsda.write(&mut w, Format::new(4), &BaseAddresses::default())
                .unwrap();
            let table = read::GccExceptTable::new(w.slice(), LittleEndian, Format::new(4));
            let parsed = table.lsda_at(LsdaOffset(start)).unwrap();
            let base = parsed.ttype_base().unwrap();
            assert_eq!(base % 4, 0, "start {start}");
            assert_eq!(base, w.len());
            assert_eq!(parsed.parse_tables().unwrap().call_sites.len(), 40);
        }
    }

    #[test]
    #[cfg(feature = "read")]
    fn test_forward_action() {
        // A record whose next record follows it, far enough away that the
        // displacement needs two bytes.
        let mut lsda = Lsda::new();
        let mut actions = Vec::new();
        for _ in 0..70 {
            actions.push(lsda.add_action(Action {
                filter: Filter::Cleanup,
                next: None,
            }));
        }
        lsda.actions[0].next = Some(actions[69]);
        lsda.actions[69].next = Some(actions[1]);
        lsda.call_sites.push(CallSite {
            start: 0,
            length: 4,
            landing_pad: 8,
            action: Some(actions[0]),
        });
        let mut w = EndianVec::new(LittleEndian);
        lsda.write(&mut w, Format::new(8), &BaseAddresses::default())
            .unwrap();
        let table = read::GccExceptTable::new(w.slice(), LittleEndian, Format::new(8));
        let parsed = table.lsda_at(LsdaOffset(0)).unwrap();
        let chain: Vec<_> = parsed
            .actions(read::ActionOffset(0))
            .map(|a| a.unwrap().offset.0)
            .collect();
        assert_eq!(chain, [0, 3 + 68 * 2, 3]);
    }

    #[test]
    fn test_arm_and_sjlj() {
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = Encoding::ABSPTR;
        let spec =
            lsda.add_exception_spec(ExceptionSpec::TypeInfos(alloc::vec![Address::Constant(
                0x100
            ),]));
        let action = lsda.add_action(Action {
            filter: Filter::ExceptionSpec(spec),
            next: None,
        });
        lsda.call_sites.push(CallSite {
            start: 0,
            length: 4,
            landing_pad: 8,
            action: Some(action),
        });
        let mut w = EndianVec::new(LittleEndian);
        lsda.write(&mut w, Format::arm_ehabi(), &BaseAddresses::default())
            .unwrap();
        assert_eq!(
            w.slice(),
            [
                0xff, 0x00, 0x09, 0x01, 0x04, 0x00, 0x04, 0x08, 0x01, 0x7f, 0x00, 0x00, //
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            lsda.write(&mut w, Format::new(4), &BaseAddresses::default()),
            Err(Error::ExceptionSpecMismatch)
        );

        let mut lsda = Lsda::new();
        lsda.call_sites.push(CallSite {
            start: 0,
            length: 0,
            landing_pad: 300,
            action: None,
        });
        let mut w = EndianVec::new(LittleEndian);
        let format = Format::new(4).with_unwinder(Unwinder::SjLj);
        lsda.write(&mut w, format, &BaseAddresses::default())
            .unwrap();
        assert_eq!(w.slice(), [0xff, 0xff, 0x01, 0x03, 0xac, 0x02, 0x00]);
    }

    #[test]
    #[cfg(feature = "read")]
    fn test_aligned_type_table() {
        // DW_EH_PE_aligned entries are aligned to the address size, so the
        // table is too, whatever the start offset.
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = Encoding(DW_EH_PE_ALIGNED);
        let ty = lsda.add_type(Some(Address::Constant(0x1234)));
        let spec = lsda.add_exception_spec(ExceptionSpec::Types(alloc::vec![ty]));
        let action = lsda.add_action(Action {
            filter: Filter::ExceptionSpec(spec),
            next: None,
        });
        lsda.call_sites.push(CallSite {
            start: 0,
            length: 4,
            landing_pad: 8,
            action: Some(action),
        });
        for start in 0..8 {
            let mut w = EndianVec::new(LittleEndian);
            w.write(&alloc::vec![0; start]).unwrap();
            lsda.write(&mut w, Format::new(8), &BaseAddresses::default())
                .unwrap();
            let table = read::GccExceptTable::new(w.slice(), LittleEndian, Format::new(8));
            let parsed = table.lsda_at(LsdaOffset(start)).unwrap();
            assert_eq!(
                parsed.type_entry(1).unwrap().value(),
                0x1234,
                "start {start}"
            );
            let tables = parsed.parse_tables().unwrap();
            assert_eq!(
                tables.exception_specs[0].entries,
                [read::SpecEntry::Type(1)],
                "start {start}"
            );
            assert_eq!(tables.end, w.len());
        }
    }

    #[test]
    fn test_errors_before_writing() {
        let bases = BaseAddresses::default();
        let mut w = EndianVec::new(LittleEndian);

        // A missing base address for @LPStart.
        let mut lsda = Lsda::new();
        lsda.lpstart = Some(LpStart {
            encoding: Encoding::PCREL_SDATA4,
            address: Address::Constant(0x10),
        });
        assert_eq!(
            lsda.write(&mut w, Format::new(8), &bases),
            Err(Error::MissingBaseAddress(crate::Base::Section))
        );

        // A null Arm EHABI type_info would terminate the list.
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = Encoding::ABSPTR;
        lsda.add_exception_spec(ExceptionSpec::TypeInfos(alloc::vec![
            Address::Constant(0),
            Address::Constant(0x100),
        ]));
        assert_eq!(
            lsda.write(&mut w, Format::arm_ehabi(), &bases),
            Err(Error::NullTypeInfo)
        );

        // An address wider than the address size.
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = Encoding::UDATA4;
        lsda.add_type(Some(Address::Constant(0x1_0000_0000)));
        assert_eq!(
            lsda.write(&mut w, Format::new(4), &bases),
            Err(Error::PointerOutOfRange(0x1_0000_0000))
        );

        // An indirect call-site encoding, and an unsupported address size.
        let mut lsda = Lsda::new();
        lsda.call_site_encoding = Encoding(0x83);
        assert_eq!(
            lsda.write(&mut w, Format::new(8), &bases),
            Err(Error::UnsupportedCallSiteEncoding(Encoding(0x83)))
        );
        assert_eq!(
            Lsda::new().write(&mut w, Format::new(3), &bases),
            Err(Error::UnsupportedAddressSize(3))
        );
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn test_errors() {
        let bases = BaseAddresses::default();
        let f = Format::new(8);
        let mut w = EndianVec::new(LittleEndian);
        let mut lsda = Lsda::new();
        lsda.add_type(None);
        assert_eq!(lsda.write(&mut w, f, &bases), Err(Error::MissingTypeTable));
        lsda.ttype_encoding = Encoding::ULEB128;
        assert_eq!(
            lsda.write(&mut w, f, &bases),
            Err(Error::VariableSizeTypeEncoding(Encoding::ULEB128))
        );
        lsda.ttype_encoding = Encoding::UDATA4;
        lsda.add_action(Action {
            filter: Filter::Catch(TypeId(1)),
            next: None,
        });
        assert_eq!(lsda.write(&mut w, f, &bases), Err(Error::InvalidTypeId));
        lsda.actions[0].filter = Filter::ExceptionSpec(SpecId(0));
        assert_eq!(lsda.write(&mut w, f, &bases), Err(Error::InvalidSpecId));
        lsda.actions[0].filter = Filter::Cleanup;
        lsda.actions[0].next = Some(ActionId(1));
        assert_eq!(lsda.write(&mut w, f, &bases), Err(Error::InvalidActionId));
        lsda.actions[0].next = None;
        lsda.call_site_encoding = Encoding::UDATA2;
        lsda.call_sites.push(CallSite {
            start: 0x1_0000,
            length: 4,
            landing_pad: 0,
            action: None,
        });
        assert_eq!(
            lsda.write(&mut w, f, &bases),
            Err(Error::ValueOutOfRange(0x1_0000))
        );
        lsda.call_site_encoding = Encoding::PCREL_SDATA4;
        assert_eq!(
            lsda.write(&mut w, f, &bases),
            Err(Error::UnsupportedCallSiteEncoding(Encoding::PCREL_SDATA4))
        );
        lsda.call_site_encoding = Encoding::ULEB128;
        lsda.type_table_alignment = 3;
        assert_eq!(
            lsda.write(&mut w, f, &bases),
            Err(Error::InvalidAlignment(3))
        );
        assert_eq!(w.len(), 0);
    }
}
