use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use crate::common::{BaseAddresses, LsdaOffset, Unwinder, padding};
use crate::endianity::Endianity;
use crate::read::{self, Reader};
use crate::write::{
    Action, ActionId, Address, CallSite, Entry, EntryData, Error, ExceptionSpec, Filter,
    GccExceptTable, LpStart, Lsda, LsdaId, Result, SpecId, TypeId, Writer,
};

/// An error that occurred when converting a read value into a write value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertError {
    /// An error occurred when reading.
    Read(read::Error),
    /// An error occurred when writing.
    Write(Error),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConvertError::Read(e) => write!(f, "read error: {e}"),
            ConvertError::Write(e) => write!(f, "write error: {e}"),
        }
    }
}

impl core::error::Error for ConvertError {}

impl From<read::Error> for ConvertError {
    fn from(e: read::Error) -> Self {
        ConvertError::Read(e)
    }
}

impl From<Error> for ConvertError {
    fn from(e: Error) -> Self {
        ConvertError::Write(e)
    }
}

/// The result of a conversion.
pub type ConvertResult<T> = core::result::Result<T, ConvertError>;

/// The alignments tried, in order of preference, when inferring the
/// alignment of an LSDA or a type table from the padding before it.
const ALIGNMENTS: [u32; 5] = [4, 8, 16, 2, 1];

impl GccExceptTable {
    /// Create a table from a parsed section and the offsets of its LSDAs.
    ///
    /// The offsets normally come from the FDEs in `.eh_frame` (or the
    /// `.ARM.extab` entries); they may be given in any order and may repeat.
    /// The table covers the whole section: bytes before the first LSDA, and
    /// gaps between LSDAs that are not zero alignment padding, become
    /// [`EntryData::Raw`] entries. The returned map gives the id of the entry
    /// for each offset.
    ///
    /// All pointers are resolved to constant addresses using `bases`, so
    /// writing the table with the same base addresses reproduces the
    /// section. Each LSDA is converted to [`EntryData::Lsda`] only if writing
    /// it reproduces its bytes exactly; otherwise it is kept as
    /// [`EntryData::Raw`]. This is the case for non-minimal LEB128 values
    /// other than the type table base offset, unreferenced data, layouts that
    /// the producers do not emit (see [`read::Lsda::parse_tables`]), and, when
    /// reading a relocatable object through a
    /// [`RelocateReader`](read::RelocateReader), relocated fields whose
    /// value changes.
    ///
    /// # Errors
    ///
    /// Returns [`ConvertError::Read`] if an offset is outside the section, an
    /// LSDA header cannot be parsed, or a base address is missing.
    pub fn from_read<R: Reader>(
        section: &read::GccExceptTable<R>,
        offsets: &[LsdaOffset],
        bases: &BaseAddresses,
    ) -> ConvertResult<(GccExceptTable, BTreeMap<LsdaOffset, LsdaId>)> {
        let format = section.format();
        let data = section.reader().to_slice()?;
        let mut offsets: Vec<LsdaOffset> = offsets.to_vec();
        offsets.sort_unstable();
        offsets.dedup();
        if offsets.last().is_some_and(|last| last.0 >= data.len()) {
            return Err(read::Error::OffsetOutOfBounds.into());
        }

        let mut table = GccExceptTable::new(format);
        let mut ids = BTreeMap::new();
        let endian = section.reader().endian();
        let mut cursor = 0;
        for (i, &offset) in offsets.iter().enumerate() {
            let region_end = offsets.get(i + 1).map_or(data.len(), |next| next.0);
            let start = offset.0;

            // Explain the gap before the LSDA as alignment padding, or keep it.
            let gap = &data[cursor..start];
            let padded = gap.iter().all(|&b| b == 0);
            let alignment = ALIGNMENTS
                .into_iter()
                .find(|&a| padded && cursor + padding(cursor, a as usize) == start);
            if alignment.is_none() {
                table.add(Entry {
                    alignment: 1,
                    data: EntryData::Raw(gap.to_vec()),
                });
            }
            let alignment = alignment.unwrap_or(1);

            let lsda = section.lsda_at(offset)?;
            let mut converted = None;
            if let Some((mut model, end, layouts)) = convert_lsda(&lsda, bases)?
                && end <= region_end
            {
                // Use the first layout of the type table that reproduces the
                // bytes. Layouts are in decreasing order of entries, so the
                // model can be truncated in place.
                for (count, alignment) in layouts {
                    model.types.truncate(count);
                    model.type_table_alignment = alignment;
                    let mut check = Check::new(endian, start, &data[start..end]);
                    if model.write(&mut check, format, bases).is_ok() && check.is_complete() {
                        converted = Some((model, end));
                        break;
                    }
                }
            }
            let (entry_data, end) = match converted {
                Some((lsda, end)) => (EntryData::Lsda(lsda), end),
                // Keep the whole region, since its extent is not known.
                None => (EntryData::Raw(data[start..region_end].to_vec()), region_end),
            };
            ids.insert(
                offset,
                table.add(Entry {
                    alignment,
                    data: entry_data,
                }),
            );
            cursor = end;
        }
        if cursor < data.len() {
            table.add(Entry {
                alignment: 1,
                data: EntryData::Raw(data[cursor..].to_vec()),
            });
        }
        Ok((table, ids))
    }
}

/// A converted LSDA, the section offset of its end, and the possible
/// layouts of its type table: the number of entries to keep and the
/// alignment, in order of preference and of decreasing number of entries.
type Converted = (Lsda, usize, Vec<(usize, u32)>);

/// Convert an LSDA, or return `None` if its tables cannot be represented.
#[allow(clippy::too_many_lines)]
fn convert_lsda<R: Reader>(
    lsda: &read::Lsda<R>,
    bases: &BaseAddresses,
) -> ConvertResult<Option<Converted>> {
    let tables = match lsda.parse_tables() {
        Ok(tables) => tables,
        Err(e @ read::Error::MissingBaseAddress(_)) => return Err(e.into()),
        Err(_) => return Ok(None),
    };
    let constant = |pointer: read::Pointer| -> ConvertResult<Address> {
        Ok(Address::Constant(pointer.address(bases)?))
    };

    let lpstart = match lsda.lpstart() {
        Some(pointer) => Some(LpStart {
            encoding: pointer.encoding(),
            address: constant(pointer)?,
        }),
        None => None,
    };

    // The tables are in offset order, so an id is found by binary search.
    let action_id = |offset: read::ActionOffset| {
        tables
            .actions
            .binary_search_by_key(&offset, |action| action.offset)
            .ok()
            .map(ActionId)
    };
    let spec_id = |offset: read::SpecOffset| {
        tables
            .exception_specs
            .binary_search_by_key(&offset, |spec| spec.offset)
            .ok()
            .map(SpecId)
    };
    let type_id = |index: u64| TypeId(index as usize - 1);

    // `parse_tables` found every referenced record and list.
    let mut actions = Vec::with_capacity(tables.actions.len());
    let mut referenced_types = 0;
    for action in &tables.actions {
        let filter = match action.filter {
            read::Filter::Cleanup => Filter::Cleanup,
            read::Filter::Catch(index) => {
                referenced_types = referenced_types.max(index as usize);
                Filter::Catch(type_id(index))
            }
            read::Filter::ExceptionSpec(offset) => {
                Filter::ExceptionSpec(spec_id(offset).ok_or(Error::InvalidSpecId)?)
            }
        };
        let next = match action.next {
            Some(offset) => match action_id(offset) {
                Some(id) => Some(id),
                // The next record is outside the parsed table.
                None => return Ok(None),
            },
            None => None,
        };
        actions.push(Action { filter, next });
    }

    let mut call_sites = Vec::with_capacity(tables.call_sites.len());
    for call_site in &tables.call_sites {
        let action = match call_site.action {
            Some(offset) => Some(action_id(offset).ok_or(Error::InvalidActionId)?),
            None => None,
        };
        call_sites.push(CallSite {
            start: call_site.start,
            length: call_site.length,
            landing_pad: call_site.landing_pad,
            action,
        });
    }

    let mut types = Vec::with_capacity(tables.types.len());
    for pointer in &tables.types {
        types.push(if pointer.is_null() {
            None
        } else {
            Some(constant(*pointer)?)
        });
    }

    let arm = lsda.format().unwinder == Unwinder::ArmEhabi;
    let mut exception_specs = Vec::with_capacity(tables.exception_specs.len());
    for spec in &tables.exception_specs {
        let entries = spec.entries.iter();
        exception_specs.push(if arm {
            ExceptionSpec::TypeInfos(
                entries
                    .filter_map(|entry| match entry {
                        read::SpecEntry::TypeInfo(pointer) => {
                            Some(Address::Constant(pointer.value()))
                        }
                        read::SpecEntry::Type(_) => None,
                    })
                    .collect(),
            )
        } else {
            ExceptionSpec::Types(
                entries
                    .filter_map(|entry| match *entry {
                        read::SpecEntry::Type(index) => {
                            referenced_types = referenced_types.max(index as usize);
                            Some(type_id(index))
                        }
                        read::SpecEntry::TypeInfo(_) => None,
                    })
                    .collect(),
            )
        });
    }

    // The type table may have unreferenced entries, and the padding before
    // it depends on its alignment. The entries beyond the highest referenced
    // index may be padding instead, if they are zero; list the layouts that
    // place the table where it is.
    let mut layouts = Vec::new();
    if let Some(base) = lsda.ttype_base() {
        let Ok(size) = lsda.ttype_entry_size() else {
            return Ok(None);
        };
        let action_end = tables.action_table_end;
        for count in (referenced_types..=types.len()).rev() {
            if types[count..].iter().any(Option::is_some) {
                break;
            }
            let Some(types_start) = base.checked_sub(count * size) else {
                continue;
            };
            // Prefer the entry size, as GCC aligns to it.
            let entry_alignment = size as u32;
            for alignment in [entry_alignment]
                .into_iter()
                .chain(ALIGNMENTS.into_iter().filter(|&a| a != entry_alignment))
            {
                if action_end + padding(action_end, alignment as usize) == types_start {
                    layouts.push((count, alignment));
                }
            }
        }
    } else {
        layouts.push((0, 4));
    }

    let converted = Lsda {
        lpstart,
        ttype_encoding: lsda.ttype_encoding(),
        call_site_encoding: lsda.call_site_encoding(),
        type_table_alignment: 4,
        call_sites,
        actions,
        types,
        exception_specs,
    };
    Ok(Some((converted, tables.end, layouts)))
}

/// A writer that checks that what is written at a section offset matches the
/// expected bytes, stopping at the first difference.
#[derive(Debug)]
struct Check<'a, E: Endianity> {
    endian: E,
    start: usize,
    expected: &'a [u8],
    written: usize,
}

impl<'a, E: Endianity> Check<'a, E> {
    fn new(endian: E, start: usize, expected: &'a [u8]) -> Self {
        Check {
            endian,
            start,
            expected,
            written: 0,
        }
    }

    /// Return true if every expected byte was written.
    fn is_complete(&self) -> bool {
        self.written == self.expected.len()
    }
}

impl<E: Endianity> Writer for Check<'_, E> {
    type Endian = E;

    fn endian(&self) -> Self::Endian {
        self.endian
    }

    fn len(&self) -> usize {
        self.start + self.written
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.written + bytes.len();
        if self.expected.get(self.written..end) != Some(bytes) {
            return Err(Error::OffsetOutOfBounds);
        }
        self.written = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Format;
    use crate::endianity::LittleEndian;
    use crate::write::EndianVec;

    fn roundtrip(data: &[u8], offsets: &[usize], format: Format) -> GccExceptTable {
        let bases = BaseAddresses::default().set_section(0x4000);
        let section = read::GccExceptTable::new(data, LittleEndian, format);
        let offsets: Vec<_> = offsets.iter().map(|&o| LsdaOffset(o)).collect();
        let (table, ids) = GccExceptTable::from_read(&section, &offsets, &bases).unwrap();
        assert!(offsets.iter().all(|offset| ids.contains_key(offset)));
        let mut w = EndianVec::new(LittleEndian);
        let written = table.write(&mut w, &bases).unwrap();
        assert_eq!(w.slice(), data);
        for (offset, id) in ids {
            assert_eq!(written.get(id), offset);
        }
        table
    }

    #[test]
    fn test_roundtrip() {
        let mut data = Vec::new();
        // A GCC-style LSDA without a type table.
        data.extend([0xff, 0xff, 0x01, 0x04, 0x00, 0x04, 0x08, 0x00]);
        // Aligned to 4: one LSDA with a type table (from the write tests).
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = crate::Encoding::PCREL_SDATA4;
        let int = lsda.add_type(Some(Address::Constant(0x5000)));
        let action = lsda.add_action(Action {
            filter: Filter::Catch(int),
            next: None,
        });
        lsda.call_sites.push(CallSite {
            start: 0,
            length: 4,
            landing_pad: 8,
            action: Some(action),
        });
        let mut w = EndianVec::new(LittleEndian);
        w.write(&data).unwrap();
        let second = w.len();
        lsda.write(
            &mut w,
            Format::new(8),
            &BaseAddresses::default().set_section(0x4000),
        )
        .unwrap();
        let data = w.into_vec();

        let table = roundtrip(&data, &[second, 0, second], Format::new(8));
        assert_eq!(table.entries().len(), 2);
        assert!(matches!(table.entries()[0].data, EntryData::Lsda(_)));
        let EntryData::Lsda(converted) = &table.entries()[1].data else {
            panic!("expected an LSDA");
        };
        assert_eq!(converted, &lsda);
    }

    #[test]
    fn test_raw_fallback() {
        let mut data = alloc::vec![0xaa, 0xbb];
        // A non-minimal call-site table length (0x84 0x00 = 4).
        let start = data.len();
        data.extend([0xff, 0xff, 0x01, 0x84, 0x00, 0x00, 0x04, 0x08, 0x00]);
        // Non-zero bytes after the LSDA.
        data.extend([0x01, 0x02]);
        let table = roundtrip(&data, &[start], Format::new(4));
        assert_eq!(table.entries().len(), 2);
        assert!(matches!(&table.entries()[0].data, EntryData::Raw(raw) if raw == &[0xaa, 0xbb]));
        assert!(matches!(&table.entries()[1].data, EntryData::Raw(raw) if raw.len() == 11));
    }

    #[test]
    fn test_trailing_data() {
        // An LSDA, then unreferenced bytes kept as raw.
        let data = [0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09];
        let table = roundtrip(&data, &[0], Format::new(8).with_unwinder(Unwinder::SjLj));
        assert_eq!(table.entries().len(), 2);
    }
}
