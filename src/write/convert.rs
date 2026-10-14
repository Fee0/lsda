use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use crate::common::{ARM_TARGET2_SIZE, BaseAddresses, Encoding, LsdaOffset, Unwinder, padding};
use crate::constants::{DW_EH_PE_SLEB128, DW_EH_PE_ULEB128};
use crate::endianity::Endianity;
use crate::leb128;
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

/// The most unreferenced action records, and exception specifications, that
/// a conversion considers. Producers leave a few; the limit bounds the work
/// on arbitrary data.
const MAX_UNREFERENCED: usize = 256;

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
    /// [`EntryData::Raw`].
    ///
    /// The conversion keeps what producers emit beyond the referenced tables
    /// that [`read::Lsda::parse_tables`] decodes: unreferenced action records
    /// after the referenced ones, with the exception specifications that
    /// they use (GCC keeps those of call sites that optimization removed),
    /// unreferenced type table entries (LLVM lists the types of Arm EHABI
    /// exception specifications), padded `@TType` base offsets, and padded
    /// LEB128 call-site values (RISC-V linkers leave them). LSDAs are kept
    /// raw for other non-minimal LEB128 values, other unreferenced data, and,
    /// when reading a relocatable object through a
    /// [`RelocateReader`](read::RelocateReader), relocated fields whose value
    /// changes.
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
            if let Some(candidate) = convert_lsda(&lsda, section.reader(), bases, region_end)? {
                // Use the first layout that reproduces the bytes.
                for layout in &candidate.layouts {
                    if layout.end > region_end {
                        continue;
                    }
                    let model = candidate.with_layout(*layout);
                    let mut check = Check::new(endian, start, &data[start..layout.end]);
                    if model.write(&mut check, format, bases).is_ok() && check.is_complete() {
                        converted = Some((model, layout.end));
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

/// A layout of the tables whose extent is not recorded: the number of
/// action records, type table entries and exception specifications, the
/// alignment of the type table, and the section offset of the end of the
/// LSDA.
#[derive(Debug, Clone, Copy)]
struct Layout {
    actions: usize,
    types: usize,
    exception_specs: usize,
    alignment: u32,
    end: usize,
}

/// A converted LSDA with every candidate action record, type table entry and
/// exception specification, and the layouts that place the tables where
/// they are, in order of preference.
struct Candidate {
    lsda: Lsda,
    layouts: Vec<Layout>,
}

impl Candidate {
    fn with_layout(&self, layout: Layout) -> Lsda {
        let mut lsda = self.lsda.clone();
        lsda.actions.truncate(layout.actions);
        lsda.types.truncate(layout.types);
        lsda.exception_specs.truncate(layout.exception_specs);
        lsda.type_table_alignment = layout.alignment;
        lsda
    }
}

/// Return the highest value of `f` over each prefix of `items`, starting
/// with `initial` for the empty prefix.
fn prefix_max<T>(items: &[T], initial: usize, f: impl Fn(&T) -> usize) -> Vec<usize> {
    let mut max = Vec::with_capacity(items.len() + 1);
    max.push(initial);
    for (i, item) in items.iter().enumerate() {
        max.push(max[i].max(f(item)));
    }
    max
}

/// Convert an LSDA that must end by `region_end`, or return `None` if its
/// tables cannot be represented.
///
/// The extent of the tables is inferred by `parse_tables`, from the
/// references to them. But GCC keeps the action records and exception
/// specifications of call sites that optimization removed: unreferenced
/// records may follow the referenced ones, with the exception
/// specifications that they use. And the type table may have entries that
/// nothing refers to, or be preceded by padding that looks like entries.
/// The candidate holds every record, entry and list that may be part of the
/// tables, and its layouts are the ways of dividing the bytes between them:
/// the referenced records first, then more and more of those that follow.
#[allow(clippy::too_many_lines)]
fn convert_lsda<R: Reader>(
    lsda: &read::Lsda<R>,
    section: &R,
    bases: &BaseAddresses,
    region_end: usize,
) -> ConvertResult<Option<Candidate>> {
    let tables = match lsda.parse_tables() {
        Ok(tables) => tables,
        Err(e @ read::Error::MissingBaseAddress(_)) => return Err(e.into()),
        Err(_) => return Ok(None),
    };
    let constant = |pointer: read::Pointer| -> ConvertResult<Address> {
        Ok(Address::Constant(pointer.address(bases)?))
    };
    let arm = lsda.format().unwinder == Unwinder::ArmEhabi;

    let lpstart = match lsda.lpstart() {
        Some(pointer) => Some(LpStart {
            encoding: pointer.encoding(),
            address: constant(pointer)?,
        }),
        None => None,
    };

    // The records that `parse_tables` found, then those that follow them
    // before the type table base, in sequence. Likewise for the exception
    // specifications, up to the end of the region. Unreferenced records and
    // lists are only possible with a type table.
    let referenced_actions = tables.actions.len();
    let referenced_specs = tables.exception_specs.len();
    let mut records = tables.actions.clone();
    let mut specs = tables.exception_specs.clone();
    let mut spec_ends = Vec::new();
    let action_table = lsda.action_table_offset();
    if let Some(base) = lsda.ttype_base() {
        let mut offset = tables.action_table_end;
        while offset < base && records.len() < referenced_actions + MAX_UNREFERENCED {
            let Ok(action) = lsda.action_at(read::ActionOffset(offset - action_table)) else {
                break;
            };
            offset += action.len();
            records.push(action);
        }

        // Exception specification offsets count entries for the Arm EHABI.
        let unit = if arm { ARM_TARGET2_SIZE as usize } else { 1 };
        let mut offset = if specs.is_empty() { base } else { tables.end };
        while offset < region_end && specs.len() < referenced_specs + MAX_UNREFERENCED {
            let spec = read::SpecOffset((offset - base) / unit);
            let Ok(mut iter) = lsda.exception_spec(spec) else {
                break;
            };
            let mut entries = Vec::new();
            let terminated = loop {
                match iter.next() {
                    Ok(Some(entry)) => entries.push(entry),
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            };
            offset = iter.offset();
            if !terminated || offset > region_end {
                break;
            }
            specs.push(read::ExceptionSpec {
                offset: spec,
                entries,
            });
            spec_ends.push(offset);
        }
    }

    // The tables are in offset order, so an id is found by binary search.
    let action_id = |offset: read::ActionOffset| {
        records
            .binary_search_by_key(&offset, |action| action.offset)
            .ok()
            .map(ActionId)
    };
    let spec_id = |offset: read::SpecOffset| {
        specs
            .binary_search_by_key(&offset, |spec| spec.offset)
            .ok()
            .map(SpecId)
    };
    let type_id = |index: u64| TypeId(index as usize - 1);

    // Convert the records, as far as they can be represented.
    let mut actions = Vec::with_capacity(records.len());
    for (i, action) in records.iter().enumerate() {
        let filter = match action.filter {
            read::Filter::Cleanup => Some(Filter::Cleanup),
            read::Filter::Catch(index) => Some(Filter::Catch(type_id(index))),
            read::Filter::ExceptionSpec(offset) => spec_id(offset).map(Filter::ExceptionSpec),
        };
        let next = match action.next {
            Some(offset) => action_id(offset).map(Some),
            None => Some(None),
        };
        let (Some(filter), Some(next)) = (filter, next) else {
            // The referenced records must be representable; the following
            // ones are candidates only up to here.
            if i < referenced_actions {
                return Ok(None);
            }
            break;
        };
        actions.push(Action { filter, next });
    }
    // What the first n records refer to, which the layout must include.
    let referenced_records = prefix_max(&actions, 0, |action| action.next.map_or(0, |id| id.0 + 1));
    let action_types = prefix_max(&actions, 0, |action| match action.filter {
        Filter::Catch(id) => id.0 + 1,
        _ => 0,
    });
    let action_specs = prefix_max(&actions, referenced_specs, |action| match action.filter {
        Filter::ExceptionSpec(id) => id.0 + 1,
        _ => 0,
    });

    let mut call_sites = Vec::with_capacity(tables.call_sites.len());
    for call_site in &tables.call_sites {
        let action = match call_site.action {
            Some(offset) => match action_id(offset) {
                Some(id) => Some(id),
                None => return Ok(None),
            },
            None => None,
        };
        let Ok(leb128_lengths) = leb128_lengths(lsda, section, call_site) else {
            return Ok(None);
        };
        call_sites.push(CallSite {
            start: call_site.start,
            length: call_site.length,
            landing_pad: call_site.landing_pad,
            action,
            leb128_lengths,
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

    let mut exception_specs = Vec::with_capacity(specs.len());
    for spec in &specs {
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
                        read::SpecEntry::Type(index) => Some(type_id(index)),
                        read::SpecEntry::TypeInfo(_) => None,
                    })
                    .collect(),
            )
        });
    }
    let spec_types = prefix_max(&exception_specs, 0, |spec| match spec {
        ExceptionSpec::Types(types) => types.iter().map(|id| id.0 + 1).max().unwrap_or(0),
        ExceptionSpec::TypeInfos(_) => 0,
    });

    let mut layouts = Vec::new();
    let Some(base) = lsda.ttype_base() else {
        layouts.push(Layout {
            actions: referenced_actions,
            types: 0,
            exception_specs: 0,
            alignment: 4,
            end: tables.end,
        });
        return Ok(Some(Candidate {
            lsda: Lsda {
                lpstart,
                ttype_encoding: lsda.ttype_encoding(),
                call_site_encoding: lsda.call_site_encoding(),
                type_table_alignment: 4,
                call_sites,
                actions,
                types,
                exception_specs,
            },
            layouts,
        }));
    };
    let Ok(size) = lsda.ttype_entry_size() else {
        return Ok(None);
    };
    // Every entry between the referenced records and the base.
    let available = base.saturating_sub(tables.action_table_end) / size;
    for index in types.len() + 1..=available {
        let Ok(pointer) = lsda.type_entry(index as u64) else {
            return Ok(None);
        };
        types.push(if pointer.is_null() {
            None
        } else {
            Some(constant(pointer)?)
        });
    }

    // The number of entries up to the last non-null one, for each number of
    // entries.
    let mut non_null = Vec::with_capacity(types.len() + 1);
    non_null.push(0);
    for (i, entry) in types.iter().enumerate() {
        non_null.push(if entry.is_some() { i + 1 } else { non_null[i] });
    }
    // Prefer the entry size, as GCC aligns to it.
    let entry_alignment = size as u32;
    let alignments = [entry_alignment]
        .into_iter()
        .chain(ALIGNMENTS.into_iter().filter(|&a| a != entry_alignment));
    for count in referenced_actions..=actions.len() {
        let spec_count = action_specs[count];
        if referenced_records[count] > count || spec_count > exception_specs.len() {
            // A record refers to one beyond the tables.
            continue;
        }
        let end = match spec_count.checked_sub(referenced_specs + 1) {
            Some(extra) => spec_ends[extra],
            None => tables.end,
        };
        let action_end = match count.checked_sub(1) {
            Some(last) => action_table + records[last].offset.0 + records[last].len(),
            None => action_table,
        };
        let referenced = action_types[count].max(spec_types[spec_count]);
        // The entries that do not overlap the records.
        let entries = if count == referenced_actions {
            types.len()
        } else {
            types.len().min(base.saturating_sub(action_end) / size)
        };
        // The alignment places the type table after the padding. The entries
        // beyond the highest referenced index may be padding instead, if they
        // are zero.
        let fewest = referenced.max(non_null[entries]);
        for alignment in alignments.clone() {
            let types_start = action_end + padding(action_end, alignment as usize);
            let Some(table_size) = base.checked_sub(types_start) else {
                continue;
            };
            let type_count = table_size / size;
            if table_size % size == 0 && (fewest..=entries).contains(&type_count) {
                layouts.push(Layout {
                    actions: count,
                    types: type_count,
                    exception_specs: spec_count,
                    alignment,
                    end,
                });
            }
        }
    }

    Ok(Some(Candidate {
        lsda: Lsda {
            lpstart,
            ttype_encoding: lsda.ttype_encoding(),
            call_site_encoding: lsda.call_site_encoding(),
            type_table_alignment: 4,
            call_sites,
            actions,
            types,
            exception_specs,
        },
        layouts,
    }))
}

/// Return the lengths of the LEB128-encoded values of a call site that are
/// longer than the shortest encoding, as [`CallSite::leb128_lengths`].
fn leb128_lengths<R: Reader>(
    lsda: &read::Lsda<R>,
    section: &R,
    call_site: &read::CallSite,
) -> read::Result<[u8; 3]> {
    let sjlj = lsda.format().unwinder == Unwinder::SjLj;
    let encoding = if sjlj {
        Encoding::ULEB128
    } else {
        lsda.call_site_encoding()
    };
    let signed = encoding.format() == DW_EH_PE_SLEB128;
    if encoding.format() != DW_EH_PE_ULEB128 && !signed {
        return Ok([0; 3]);
    }
    let mut input = section.range_from(call_site.offset)?;
    let mut lengths = [0; 3];
    let fields = if sjlj { 2..3 } else { 0..3 };
    for field in fields {
        let before = input.len();
        let shortest = if signed {
            leb128::signed_len(input.read_sleb128()?)
        } else {
            leb128::unsigned_len(input.read_uleb128()?)
        };
        let len = before - input.len();
        if len > shortest {
            lengths[field] = u8::try_from(len).map_err(|_| read::Error::BadUnsignedLeb128)?;
        }
    }
    Ok(lengths)
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
    fn test_unreferenced_records() {
        // From libstdc++ for x86-64: a function whose call sites were all
        // removed keeps the action record of its `throw()` specification,
        // and the specification, which follows the type table base.
        let data = [
            0xff, 0x9b, 0x05, 0x01, 0x00, // header, base at 0x08
            0x7f, 0x00, // action: exception specification 0
            0x00, // padding
            0x00, // exception specification: throw()
            0x00, 0x00, 0x00, // padding before the next LSDA
            0xff, 0xff, 0x01, 0x00, // the next LSDA
        ];
        let table = roundtrip(&data, &[0, 12], Format::new(8));
        let EntryData::Lsda(lsda) = &table.entries()[0].data else {
            panic!("expected an LSDA");
        };
        assert_eq!(lsda.call_sites, []);
        assert_eq!(
            lsda.actions,
            [Action {
                filter: Filter::ExceptionSpec(SpecId(0)),
                next: None
            }]
        );
        assert_eq!(lsda.exception_specs, [ExceptionSpec::Types(Vec::new())]);
    }

    #[test]
    fn test_padded_leb128() {
        // From libc for RISC-V: the linker rewrote a call-site length of 0x70
        // in the two bytes that the assembler reserved.
        let data = [
            0xff, 0xff, 0x01, 0x05, // header
            0x10, 0xf0, 0x00, 0x00, 0x00, // call site
        ];
        let table = roundtrip(&data, &[0], Format::new(8));
        let EntryData::Lsda(lsda) = &table.entries()[0].data else {
            panic!("expected an LSDA");
        };
        assert_eq!(lsda.call_sites[0].length, 0x70);
        assert_eq!(lsda.call_sites[0].leb128_lengths, [0, 2, 0]);
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
            ..Default::default()
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
    fn test_malformed_lsda_is_raw() {
        // An exception specification without a type table.
        let data = [0xff, 0xff, 0x01, 0x04, 0x00, 0x04, 0x00, 0x01, 0x7f, 0x00];
        let table = roundtrip(&data, &[0], Format::new(8));
        assert!(matches!(&table.entries()[0].data, EntryData::Raw(raw) if raw == &data));
    }

    #[test]
    fn test_unreferenced_types() {
        // A type table entry that no action refers to is kept.
        let mut lsda = Lsda::new();
        lsda.ttype_encoding = crate::Encoding::UDATA4;
        let used = lsda.add_type(Some(Address::Constant(0x100)));
        lsda.add_type(Some(Address::Constant(0x200)));
        let action = lsda.add_action(Action {
            filter: Filter::Catch(used),
            next: None,
        });
        lsda.call_sites.push(CallSite {
            start: 0,
            length: 4,
            landing_pad: 8,
            action: Some(action),
            ..Default::default()
        });
        let mut w = EndianVec::new(LittleEndian);
        lsda.write(&mut w, Format::new(4), &BaseAddresses::default())
            .unwrap();
        let table = roundtrip(w.slice(), &[0], Format::new(4));
        let EntryData::Lsda(converted) = &table.entries()[0].data else {
            panic!("expected an LSDA");
        };
        assert_eq!(converted, &lsda);
    }

    #[test]
    fn test_trailing_data() {
        // An LSDA, then unreferenced bytes kept as raw.
        let data = [0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09];
        let table = roundtrip(&data, &[0], Format::new(8).with_unwinder(Unwinder::SjLj));
        assert_eq!(table.entries().len(), 2);
    }
}
