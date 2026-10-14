use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::common::{ARM_TARGET2_SIZE, Encoding, Format, LsdaOffset, Unwinder, size_mask};
use crate::constants::DW_EH_PE_ALIGNED;
use crate::endianity::Endianity;
use crate::read::{EndianSlice, Error, Pointer, Reader, Result, read_pointer, target2_pointer};

/// A section that holds LSDAs: `.gcc_except_table`, or `.ARM.extab` for the
/// Arm EHABI.
///
/// LSDAs are not self-delimiting (the type table grows backwards from its
/// base, and its length is not recorded), so they are accessed by offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GccExceptTable<R> {
    section: R,
    format: Format,
}

impl<'input, Endian> GccExceptTable<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `GccExceptTable` from the data in the section.
    ///
    /// ```
    /// use lsda::read::GccExceptTable;
    /// use lsda::{Format, LittleEndian};
    ///
    /// # let buf = [0xff, 0xff, 0x01, 0x00];
    /// # let read_section_somehow = || &buf;
    /// let table = GccExceptTable::new(read_section_somehow(), LittleEndian, Format::new(8));
    /// ```
    pub fn new(section: &'input [u8], endian: Endian, format: Format) -> Self {
        Self::from_reader(EndianSlice::new(section, endian), format)
    }
}

impl<R> GccExceptTable<R> {
    /// Construct a new `GccExceptTable` from a reader for the section.
    pub fn from_reader(section: R, format: Format) -> Self {
        GccExceptTable { section, format }
    }

    /// Return the reader for the section.
    #[inline]
    pub fn reader(&self) -> &R {
        &self.section
    }

    /// Return the format used to parse the section.
    #[inline]
    pub fn format(&self) -> Format {
        self.format
    }
}

impl<R: Reader> GccExceptTable<R> {
    /// Parse the header of the LSDA at the given offset.
    ///
    /// The tables are parsed on demand by the methods of [`Lsda`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedAddressSize`] if the format's address size
    /// is not 2, 4 or 8 (4 for the Arm EHABI), [`Error::OffsetOutOfBounds`]
    /// if `offset` is outside the section or the type table base is beyond
    /// its end, [`Error::InvalidEncoding`] for an undefined pointer encoding,
    /// [`Error::UnsupportedCallSiteEncoding`] for a call-site encoding that
    /// is not a plain offset (it has an application or is indirect), and
    /// [`Error::UnexpectedEof`] if the header or the call-site table is
    /// truncated.
    pub fn lsda_at(&self, offset: LsdaOffset) -> Result<Lsda<R>> {
        Lsda::parse(&self.section, offset, self.format)
    }
}

/// The language-specific data area of one function.
///
/// The LSDA consists of a header, a call-site table, an action table, and,
/// if the type table encoding is not `DW_EH_PE_omit`, a type table that ends
/// at the type table base followed by the exception specification table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsda<R: Reader> {
    offset: LsdaOffset,
    format: Format,
    lpstart: Option<Pointer>,
    ttype_encoding: Encoding,
    ttype_base: Option<usize>,
    call_site_encoding: Encoding,
    call_sites: R,
    /// Whether the call-site table was cut short by
    /// [`Lsda::with_call_site_table_end`], and may end with padding.
    call_sites_cut: bool,
    actions: R,
    section: R,
}

impl<R: Reader> Lsda<R> {
    fn parse(section: &R, offset: LsdaOffset, format: Format) -> Result<Self> {
        if !format.has_valid_address_size() {
            return Err(Error::UnsupportedAddressSize(format.address_size));
        }
        if offset.0 >= section.len() {
            return Err(Error::OffsetOutOfBounds);
        }
        let mut input = section.range_from(offset.0)?;

        let lpstart_encoding = Encoding(input.read_u8()?);
        let lpstart = if lpstart_encoding.is_omit() {
            None
        } else {
            Some(read_pointer(
                &mut input,
                section,
                lpstart_encoding,
                format.address_size,
            )?)
        };

        let ttype_encoding = Encoding(input.read_u8()?);
        let ttype_base = if ttype_encoding.is_omit() {
            None
        } else {
            if !ttype_encoding.is_valid() {
                return Err(Error::InvalidEncoding(ttype_encoding));
            }
            let delta = input.read_uleb128()?;
            let base = usize::try_from(delta)
                .ok()
                .and_then(|delta| input.offset_from(section).checked_add(delta))
                .filter(|&base| base <= section.len())
                .ok_or(Error::OffsetOutOfBounds)?;
            Some(base)
        };

        let call_site_encoding = Encoding(input.read_u8()?);
        // The SJLJ personality reads its call-site table as ULEB128 values
        // whatever the encoding byte says.
        if format.unwinder != Unwinder::SjLj && !call_site_encoding.is_offset_encoding() {
            return Err(Error::UnsupportedCallSiteEncoding(call_site_encoding));
        }
        let len = input.read_uleb128()?;
        let len = usize::try_from(len).map_err(|_| Error::UnexpectedEof)?;
        let call_sites = input.split(len)?;

        Ok(Lsda {
            offset,
            format,
            lpstart,
            ttype_encoding,
            ttype_base,
            call_site_encoding,
            call_sites,
            call_sites_cut: false,
            actions: input,
            section: section.clone(),
        })
    }

    /// Return the LSDA with its call-site table ending at the section offset
    /// `end`, if that is before the action table.
    ///
    /// With `-fbasic-block-sections`, LLVM splits the call-site table of a
    /// function into ranges, one for each section of the function. Each range
    /// has its own LSDA header, which the FDE of that section refers to,
    /// followed by the call sites in that section, and the ranges share the
    /// action and type tables that follow the last one. So that they find
    /// the action table, the call-site table length of each range extends to
    /// the end of the last range, over the ranges that follow it. The
    /// personality routine still finds the call sites of a range, since it
    /// stops at the first call site past the location.
    ///
    /// To read the call sites of a range alone, end its call-site table where
    /// the next range starts. Up to 3 zero bytes at the end are taken as the
    /// padding that aligns the next range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OffsetOutOfBounds`] if `end` is before the call-site
    /// table.
    pub fn with_call_site_table_end(mut self, end: usize) -> Result<Self> {
        let start = self.call_site_table_offset();
        if end < start {
            return Err(Error::OffsetOutOfBounds);
        }
        if end < self.action_table_offset() {
            self.call_sites = self.section.range_from(start)?.split(end - start)?;
            self.call_sites_cut = true;
        }
        Ok(self)
    }

    /// Return the offset of the LSDA within its section.
    #[inline]
    pub fn offset(&self) -> LsdaOffset {
        self.offset
    }

    /// Return the format used to parse the LSDA.
    #[inline]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Return the encoding of the landing pad base (`@LPStart`).
    #[inline]
    pub fn lpstart_encoding(&self) -> Encoding {
        self.lpstart
            .map_or(Encoding::OMIT, |lpstart| lpstart.encoding())
    }

    /// Return the landing pad base, or `None` if it is omitted, in which case
    /// landing pads are relative to the start of the function.
    #[inline]
    pub fn lpstart(&self) -> Option<Pointer> {
        self.lpstart
    }

    /// Return the encoding of the type table entries, which is
    /// `DW_EH_PE_omit` if there is no type table.
    #[inline]
    pub fn ttype_encoding(&self) -> Encoding {
        self.ttype_encoding
    }

    /// Return the section offset of the type table base (`@TType`), the end
    /// of the type table and the start of the exception specification
    /// table, or `None` if there is no type table.
    #[inline]
    pub fn ttype_base(&self) -> Option<usize> {
        self.ttype_base
    }

    /// Return the encoding of the call-site table values.
    #[inline]
    pub fn call_site_encoding(&self) -> Encoding {
        self.call_site_encoding
    }

    /// Return the section offset of the call-site table.
    #[inline]
    pub fn call_site_table_offset(&self) -> usize {
        self.call_sites.offset_from(&self.section)
    }

    /// Return the section offset of the action table, which immediately
    /// follows the call-site table.
    #[inline]
    pub fn action_table_offset(&self) -> usize {
        self.actions.offset_from(&self.section)
    }

    /// Return the size of a type table entry, as used to index the table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingTypeTable`] if there is no type table,
    /// [`Error::VariableSizeTypeEncoding`] if the encoding has no fixed size,
    /// and [`Error::InvalidEncoding`] for the Arm EHABI if the size is not 4
    /// or the encoding is `DW_EH_PE_aligned`: its personality routines read
    /// 4-byte `R_ARM_TARGET2` words in place.
    pub fn ttype_entry_size(&self) -> Result<usize> {
        self.type_table().map(|(_, size)| size)
    }

    /// Return the type table base and entry size.
    fn type_table(&self) -> Result<(usize, usize)> {
        let base = self.ttype_base.ok_or(Error::MissingTypeTable)?;
        let size = self
            .ttype_encoding
            .size(self.format.address_size)
            .ok_or(Error::VariableSizeTypeEncoding(self.ttype_encoding))?;
        // The Arm EHABI personality routines read `R_ARM_TARGET2` words in
        // place, whatever the encoding says.
        if self.format.unwinder == Unwinder::ArmEhabi
            && (size != ARM_TARGET2_SIZE || self.ttype_encoding.0 == DW_EH_PE_ALIGNED)
        {
            return Err(Error::InvalidEncoding(self.ttype_encoding));
        }
        Ok((base, usize::from(size)))
    }

    /// Return an iterator over the call-site table.
    pub fn call_sites(&self) -> CallSiteIter<R> {
        CallSiteIter {
            input: self.call_sites.clone(),
            section: self.section.clone(),
            encoding: self.call_site_encoding,
            format: self.format,
            index: 0,
            padded: self.call_sites_cut,
        }
    }

    /// Find the call site that covers a code location, as the personality
    /// routine does.
    ///
    /// For the DWARF and Arm EHABI unwinders, `location` is an offset from
    /// the start of the function. The table is sorted by start offset, so the
    /// search stops at the first call site that starts after `location`.
    /// `None` means that no call site covers it, which makes the personality
    /// routine call `std::terminate`.
    ///
    /// For the SJLJ unwinder, `location` is the 1-based call-site index
    /// recorded by the function; 0 returns `None`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`CallSiteIter::next`].
    pub fn find_call_site(&self, location: u64) -> Result<Option<CallSite>> {
        let mut call_sites = self.call_sites();
        while let Some(call_site) = call_sites.next()? {
            if self.format.unwinder == Unwinder::SjLj {
                if call_site.index + 1 == location {
                    return Ok(Some(call_site));
                }
            } else if location < call_site.start {
                break;
            } else if call_site.contains(location) {
                return Ok(Some(call_site));
            }
        }
        Ok(None)
    }

    /// Parse the action record at the given offset in the action table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the record is truncated,
    /// [`Error::BadSignedLeb128`] for an oversized value, and
    /// [`Error::OffsetOutOfBounds`] if the record's next displacement points
    /// before the action table.
    pub fn action_at(&self, offset: ActionOffset) -> Result<Action> {
        parse_action(&self.actions, offset)
    }

    /// Return an iterator over the chain of action records starting at
    /// `first`.
    pub fn actions(&self, first: ActionOffset) -> ActionIter<R> {
        ActionIter {
            actions: self.actions.clone(),
            next: Some(first),
            // A chain that does not terminate must revisit a record, and each
            // record is at least 2 bytes.
            remaining: self.actions.len() / 2 + 1,
        }
    }

    /// Return the type table entry with the given 1-based index, as used by
    /// a [`Filter::Catch`] filter.
    ///
    /// Entry `index` is at `ttype_base - index * size`. A null entry
    /// ([`Pointer::is_null`]) catches any exception. For the Arm EHABI, the
    /// entries are `R_ARM_TARGET2` values whose interpretation is
    /// platform-specific.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTypeIndex`] for index 0,
    /// [`Error::MissingTypeTable`] if there is no type table,
    /// [`Error::VariableSizeTypeEncoding`] if the encoding has no fixed size,
    /// [`Error::InvalidEncoding`] for an Arm EHABI encoding whose size is not
    /// 4 or that is `DW_EH_PE_aligned`, and [`Error::OffsetOutOfBounds`] if
    /// the entry is before the section.
    pub fn type_entry(&self, index: u64) -> Result<Pointer> {
        if index == 0 {
            return Err(Error::InvalidTypeIndex);
        }
        let (base, size) = self.type_table()?;
        let offset = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(size))
            .and_then(|delta| base.checked_sub(delta))
            .ok_or(Error::OffsetOutOfBounds)?;
        let mut input = self.section.range_from(offset)?;
        read_pointer(
            &mut input,
            &self.section,
            self.ttype_encoding,
            self.format.address_size,
        )
    }

    /// Return an iterator over the exception specification at the given
    /// offset, as used by a [`Filter::ExceptionSpec`] filter.
    ///
    /// For the DWARF and SJLJ unwinders the specification is a list of
    /// ULEB128 type table indices; for the Arm EHABI it is a list of
    /// `R_ARM_TARGET2` words. Either way the list ends with a zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingTypeTable`] if there is no type table, and
    /// [`Error::OffsetOutOfBounds`] if the offset is outside the section.
    pub fn exception_spec(&self, offset: SpecOffset) -> Result<ExceptionSpecIter<R>> {
        let base = self.ttype_base.ok_or(Error::MissingTypeTable)?;
        let arm = self.format.unwinder == Unwinder::ArmEhabi;
        let delta = if arm {
            offset.0.checked_mul(usize::from(ARM_TARGET2_SIZE))
        } else {
            Some(offset.0)
        };
        let start = delta
            .and_then(|delta| base.checked_add(delta))
            .ok_or(Error::OffsetOutOfBounds)?;
        Ok(ExceptionSpecIter {
            input: self.section.range_from(start)?,
            section: self.section.clone(),
            arm,
            done: false,
        })
    }

    /// Decode all of the tables, and find the extent of the LSDA.
    ///
    /// The extent of the action, type and exception specification tables is
    /// not recorded, so it is inferred from the references to them, as the
    /// producers emit them:
    ///
    /// * the action table holds the records reachable from the call sites,
    ///   read in sequence from its start (unreferenced records between them
    ///   are included);
    /// * the type table holds as many entries as the highest index referenced
    ///   by an action or exception specification;
    /// * the exception specification table holds the lists referenced by
    ///   the actions, read in sequence from the type table base.
    ///
    /// Data that nothing refers to is not decoded: GCC keeps the action
    /// records and exception specifications of call sites that optimization
    /// removed, after the referenced ones, and LLVM also lists the types of
    /// Arm EHABI exception specifications in the type table.
    /// [`write::GccExceptTable::from_read`](crate::write::GccExceptTable::from_read)
    /// keeps them.
    ///
    /// # Errors
    ///
    /// Returns the errors of the individual table accessors,
    /// [`Error::MissingTypeTable`] if an action refers to a type or an
    /// exception specification but there is no type table,
    /// [`Error::ActionCycle`] for a chain of actions that does not end, and
    /// [`Error::MisalignedAction`] or [`Error::MisalignedExceptionSpec`] if
    /// a referenced record or list is not where reading the table in
    /// sequence finds one.
    pub fn parse_tables(&self) -> Result<LsdaTables> {
        let mut call_sites = Vec::new();
        let mut iter = self.call_sites();
        while let Some(call_site) = iter.next()? {
            call_sites.push(call_site);
        }

        let (actions, action_table_end) = self.parse_action_table(&call_sites)?;

        let mut type_count = 0;
        let mut spec_offsets = BTreeSet::new();
        for action in &actions {
            match action.filter {
                Filter::Cleanup => {}
                Filter::Catch(index) => type_count = type_count.max(index),
                Filter::ExceptionSpec(offset) => {
                    spec_offsets.insert(offset);
                }
            }
        }

        if !spec_offsets.is_empty() && self.ttype_base.is_none() {
            return Err(Error::MissingTypeTable);
        }

        // Read the exception specification table in sequence up to the last
        // referenced list.
        let mut exception_specs = Vec::new();
        let mut spec_end = self.ttype_base;
        if let (Some(last), Some(base)) = (spec_offsets.last(), self.ttype_base) {
            let mut starts = BTreeSet::new();
            let mut offset = SpecOffset(0);
            while offset <= *last {
                let mut iter = self.exception_spec(offset)?;
                let mut entries = Vec::new();
                while let Some(entry) = iter.next()? {
                    if let SpecEntry::Type(index) = entry {
                        type_count = type_count.max(index);
                    }
                    entries.push(entry);
                }
                starts.insert(offset);
                exception_specs.push(ExceptionSpec { offset, entries });
                let end = iter.offset();
                spec_end = Some(end);
                let len = end - base;
                offset = SpecOffset(if iter.arm {
                    len / usize::from(ARM_TARGET2_SIZE)
                } else {
                    len
                });
            }
            if let Some(missing) = spec_offsets.difference(&starts).next() {
                return Err(Error::MisalignedExceptionSpec(missing.0));
            }
        }

        let mut types = Vec::new();
        if type_count > 0 {
            // Check the extent first, so that a huge index fails without
            // reading every entry.
            self.type_entry(type_count)?;
            for index in 1..=type_count {
                types.push(self.type_entry(index)?);
            }
        }

        let end = action_table_end.max(spec_end.unwrap_or(0));
        Ok(LsdaTables {
            call_sites,
            actions,
            action_table_end,
            types,
            exception_specs,
            end,
        })
    }

    /// Read the action table: the records reachable from `call_sites`, in
    /// sequence from the start of the table. Return them and the section
    /// offset of the end of the table.
    fn parse_action_table(&self, call_sites: &[CallSite]) -> Result<(Vec<Action>, usize)> {
        // Every record reachable from a call site.
        let mut reachable = BTreeSet::new();
        for call_site in call_sites {
            let Some(first) = call_site.action else {
                continue;
            };
            if reachable.contains(&first) {
                continue;
            }
            // A record seen earlier in this chain is a cycle; one seen in
            // another chain is a shared tail, which is already visited.
            let mut chain = self.actions(first);
            let mut visited = BTreeSet::new();
            while let Some(action) = chain.next()? {
                if !visited.insert(action.offset) {
                    return Err(Error::ActionCycle);
                }
                if !reachable.insert(action.offset) {
                    break;
                }
            }
        }

        // Read the action table in sequence up to the last reachable record.
        let mut actions = Vec::new();
        let mut starts = BTreeSet::new();
        let mut offset = 0;
        if let Some(last) = reachable.last() {
            while offset <= last.0 {
                let action = self.action_at(ActionOffset(offset))?;
                offset += action.len;
                starts.insert(action.offset);
                actions.push(action);
            }
        }
        if let Some(missing) = reachable.difference(&starts).next() {
            return Err(Error::MisalignedAction(missing.0));
        }
        Ok((actions, self.action_table_offset() + offset))
    }
}

/// The decoded tables of an [`Lsda`], returned by [`Lsda::parse_tables`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsdaTables {
    /// The call-site table.
    pub call_sites: Vec<CallSite>,
    /// The action table, in table order.
    pub actions: Vec<Action>,
    /// The section offset of the end of the action table.
    pub action_table_end: usize,
    /// The type table: entry `i` has the 1-based index `i + 1`, and is
    /// stored before the entries with lower indices.
    pub types: Vec<Pointer>,
    /// The exception specification table, in table order.
    pub exception_specs: Vec<ExceptionSpec>,
    /// The section offset of the end of the LSDA.
    pub end: usize,
}

/// An iterator over the call-site table of an [`Lsda`].
#[derive(Debug, Clone)]
pub struct CallSiteIter<R: Reader> {
    input: R,
    section: R,
    encoding: Encoding,
    format: Format,
    index: u64,
    /// Whether the table may end with alignment padding.
    padded: bool,
}

impl<R: Reader> CallSiteIter<R> {
    /// Advance the iterator and return the next call site.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the table ends within an entry,
    /// [`Error::CallSiteOutOfRange`] if the end of the region is beyond the
    /// address space (the personality routine's address arithmetic would
    /// wrap around, and never match it), and [`Error::OffsetOutOfBounds`] if
    /// the action does not fit in a `usize`. After an error, the iterator
    /// returns `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<CallSite>> {
        if self.input.is_empty() || self.at_padding() {
            return Ok(None);
        }
        match self.parse() {
            Ok(call_site) => {
                self.index += 1;
                Ok(Some(call_site))
            }
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }

    /// Return true if the rest of a cut call-site table is padding: zero
    /// bytes, fewer than the smallest entry.
    fn at_padding(&self) -> bool {
        self.padded
            && self.input.len() < 4
            && self
                .input
                .to_slice()
                .is_ok_and(|bytes| bytes.iter().all(|&b| b == 0))
    }

    fn parse(&mut self) -> Result<CallSite> {
        let offset = self.input.offset_from(&self.section);
        // The personality routine holds the values in address-sized words.
        let mask = size_mask(self.format.address_size);
        let (start, length, landing_pad) = if self.format.unwinder == Unwinder::SjLj {
            (0, 0, self.input.read_uleb128()? & mask)
        } else {
            let mut value = || {
                read_pointer(
                    &mut self.input,
                    &self.section,
                    self.encoding,
                    self.format.address_size,
                )
                .map(|pointer| pointer.value() & mask)
            };
            (value()?, value()?, value()?)
        };
        if length > mask - start {
            return Err(Error::CallSiteOutOfRange(offset));
        }
        let action = match self.input.read_uleb128()? {
            0 => None,
            action => Some(ActionOffset(
                usize::try_from(action - 1).map_err(|_| Error::OffsetOutOfBounds)?,
            )),
        };
        Ok(CallSite {
            offset,
            index: self.index,
            start,
            length,
            landing_pad,
            action,
        })
    }
}

impl_iterators!(CallSiteIter, CallSite);

/// An entry in the call-site table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallSite {
    /// The offset of the entry within the section.
    pub offset: usize,
    /// The 0-based index of the entry in the call-site table.
    pub index: u64,
    /// The start of the code region, as an offset from the start of the
    /// function. Always 0 for the SJLJ unwinder.
    ///
    /// Call-site values are truncated to the address size, as the
    /// personality routine reads them, and the region ends within the
    /// address space.
    pub start: u64,
    /// The length of the code region. Always 0 for the SJLJ unwinder.
    pub length: u64,
    /// The landing pad as an offset from the landing pad base (`@LPStart`),
    /// or 0 if there is none: an exception propagates through the region
    /// without stopping.
    ///
    /// For the SJLJ unwinder this is the dispatch value minus one, and every
    /// entry has a landing pad.
    pub landing_pad: u64,
    /// The first action record, or `None` if the landing pad only runs
    /// cleanups.
    pub action: Option<ActionOffset>,
}

impl CallSite {
    /// Return true if the region contains the given function offset.
    #[inline]
    #[must_use]
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset - self.start < self.length
    }
}

/// An offset within the action table, as recorded by a call site (minus 1)
/// or by the next displacement of an action record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionOffset(pub usize);

/// An offset within the exception specification table, which starts at the
/// type table base.
///
/// This is in bytes for the DWARF and SJLJ unwinders, and in 4-byte entries
/// for the Arm EHABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpecOffset(pub usize);

/// What an action record does when its landing pad is considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Filter {
    /// Filter 0: run cleanups. The landing pad is entered in the cleanup
    /// phase only.
    Cleanup,
    /// A positive filter: catch the type with this 1-based type table index.
    /// A null type entry catches any exception.
    Catch(u64),
    /// A negative filter: an exception specification. The landing pad is
    /// entered if the exception matches none of the listed types.
    ExceptionSpec(SpecOffset),
}

impl Filter {
    /// Decode a filter value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OffsetOutOfBounds`] if an exception specification
    /// offset does not fit in a `usize`.
    pub fn from_value(value: i64) -> Result<Self> {
        Ok(match value {
            0 => Filter::Cleanup,
            1.. => Filter::Catch(value.cast_unsigned()),
            _ => {
                let offset = (-(value + 1)).cast_unsigned();
                Filter::ExceptionSpec(SpecOffset(
                    usize::try_from(offset).map_err(|_| Error::OffsetOutOfBounds)?,
                ))
            }
        })
    }

    /// Return the encoded filter value.
    #[must_use]
    pub fn value(self) -> i64 {
        match self {
            Filter::Cleanup => 0,
            Filter::Catch(index) => index.cast_signed(),
            Filter::ExceptionSpec(offset) => {
                i64::try_from(offset.0).map_or(i64::MIN, |offset| -offset - 1)
            }
        }
    }
}

/// A record in the action table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Action {
    /// The offset of the record within the action table.
    pub offset: ActionOffset,
    /// The filter.
    pub filter: Filter,
    /// The next record in the chain, or `None` if this is the last.
    pub next: Option<ActionOffset>,
    len: usize,
}

impl Action {
    /// Return the length of the record in bytes.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }
}

/// An iterator over a chain of action records, returned by
/// [`Lsda::actions`].
#[derive(Debug, Clone)]
pub struct ActionIter<R: Reader> {
    actions: R,
    next: Option<ActionOffset>,
    remaining: usize,
}

impl<R: Reader> ActionIter<R> {
    /// Advance the iterator and return the next action record.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Lsda::action_at`], and [`Error::ActionCycle`]
    /// if the chain does not end. After an error, the iterator returns
    /// `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<Action>> {
        let Some(offset) = self.next.take() else {
            return Ok(None);
        };
        if self.remaining == 0 {
            return Err(Error::ActionCycle);
        }
        self.remaining -= 1;
        let action = parse_action(&self.actions, offset)?;
        self.next = action.next;
        Ok(Some(action))
    }
}

/// Parse the action record at `offset` in the action table `actions`.
fn parse_action<R: Reader>(actions: &R, offset: ActionOffset) -> Result<Action> {
    let mut input = actions.range_from(offset.0)?;
    let filter = Filter::from_value(input.read_sleb128()?)?;
    let place = input.offset_from(actions);
    let displacement = input.read_sleb128()?;
    let next = if displacement == 0 {
        None
    } else {
        let next = i64::try_from(place)
            .ok()
            .and_then(|place| place.checked_add(displacement))
            .and_then(|next| usize::try_from(next).ok())
            .ok_or(Error::OffsetOutOfBounds)?;
        Some(ActionOffset(next))
    };
    Ok(Action {
        offset,
        filter,
        next,
        len: input.offset_from(actions) - offset.0,
    })
}

impl_iterators!(ActionIter, Action);

/// An exception specification decoded by [`Lsda::parse_tables`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionSpec {
    /// The offset of the list within the exception specification table.
    pub offset: SpecOffset,
    /// The types that may be thrown, without the terminator. Empty for
    /// `throw()`.
    pub entries: Vec<SpecEntry>,
}

/// An entry in an exception specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecEntry {
    /// A 1-based type table index (DWARF and SJLJ unwinders).
    Type(u64),
    /// An `R_ARM_TARGET2` reference to a `type_info` object (Arm EHABI).
    TypeInfo(Pointer),
}

/// An iterator over an exception specification, returned by
/// [`Lsda::exception_spec`].
#[derive(Debug, Clone)]
pub struct ExceptionSpecIter<R: Reader> {
    input: R,
    section: R,
    arm: bool,
    done: bool,
}

impl<R: Reader> ExceptionSpecIter<R> {
    /// Return the section offset of the next entry, which is after the
    /// terminator once the iterator has returned `Ok(None)`.
    #[inline]
    pub fn offset(&self) -> usize {
        self.input.offset_from(&self.section)
    }

    /// Advance the iterator and return the next entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the list is not terminated within
    /// the section. After an error, the iterator returns `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<SpecEntry>> {
        if self.done {
            return Ok(None);
        }
        let result = self.parse();
        if !matches!(result, Ok(Some(_))) {
            self.done = true;
        }
        result
    }

    fn parse(&mut self) -> Result<Option<SpecEntry>> {
        let offset = self.offset();
        if self.arm {
            match self.input.read_relocatable(ARM_TARGET2_SIZE)? {
                0 => Ok(None),
                value => Ok(Some(SpecEntry::TypeInfo(target2_pointer(offset, value)))),
            }
        } else {
            match self.input.read_uleb128()? {
                0 => Ok(None),
                index => Ok(Some(SpecEntry::Type(index))),
            }
        }
    }
}

impl_iterators!(ExceptionSpecIter, SpecEntry);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BaseAddresses;
    use crate::endianity::{BigEndian, LittleEndian};

    /// A GCC-style LSDA for:
    ///
    /// ```c++
    /// void f() throw(int) {
    ///   try { g(); } catch (int) {} catch (...) {}
    ///   h(); // cleanup only
    /// }
    /// ```
    fn sample() -> alloc::vec::Vec<u8> {
        alloc::vec![
            0xff, // @LPStart omitted
            0x9b, // @TType: indirect pcrel sdata4
            0x21, // @TType base offset: 3 + 0x21 = 0x24
            0x01, // call sites: uleb128
            0x0c, // call-site table length
            // [0x04, 0x0c) -> 0x20, action 1 (offset 0)
            0x04, 0x08, 0x20, 0x01, //
            // [0x10, 0x14) -> 0x30, cleanup
            0x10, 0x04, 0x30, 0x00, //
            // [0x14, 0x18) -> no landing pad, action 7 (offset 6)
            0x14, 0x04, 0x00, 0x07, //
            // 0x11 actions: catch 1, next at +1 (offset 2)
            0x01, 0x01, //
            // offset 2: catch 2, end
            0x02, 0x00, //
            // offset 4: unreferenced cleanup
            0x00, 0x00, //
            // offset 6: exception spec at 0, then offset 4
            0x7f, 0x7d, //
            // 0x19: padding
            0x00, 0x00, 0x00, //
            // 0x1c: type 2 = null (catch all), type 1 = DW.ref._ZTIi
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x10, 0x00, 0x00, //
            // 0x24: exception spec: type 1, terminator
            0x01, 0x00,
        ]
    }

    #[test]
    fn test_lsda() {
        let data = sample();
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(8));
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.lpstart(), None);
        assert_eq!(lsda.ttype_encoding(), Encoding::INDIRECT_PCREL_SDATA4);
        assert_eq!(lsda.ttype_base(), Some(0x24));
        assert_eq!(lsda.call_site_table_offset(), 5);
        assert_eq!(lsda.action_table_offset(), 0x11);

        let call_sites: Vec<_> = lsda.call_sites().collect::<Result<_>>().unwrap();
        assert_eq!(call_sites.len(), 3);
        assert_eq!(
            call_sites[0],
            CallSite {
                offset: 5,
                index: 0,
                start: 4,
                length: 8,
                landing_pad: 0x20,
                action: Some(ActionOffset(0)),
            }
        );
        assert_eq!(call_sites[1].action, None);
        assert_eq!(call_sites[2].action, Some(ActionOffset(6)));

        assert_eq!(lsda.find_call_site(3).unwrap(), None);
        assert_eq!(lsda.find_call_site(4).unwrap(), Some(call_sites[0]));
        assert_eq!(lsda.find_call_site(0x13).unwrap(), Some(call_sites[1]));
        assert_eq!(lsda.find_call_site(0x18).unwrap(), None);

        let chain: Vec<_> = lsda
            .actions(ActionOffset(0))
            .map(|a| a.unwrap().filter)
            .collect();
        assert_eq!(chain, [Filter::Catch(1), Filter::Catch(2)]);
        let chain: Vec<_> = lsda
            .actions(ActionOffset(6))
            .map(|a| a.unwrap().filter)
            .collect();
        assert_eq!(
            chain,
            [Filter::ExceptionSpec(SpecOffset(0)), Filter::Cleanup]
        );

        let bases = BaseAddresses::default().set_section(0x2000);
        let type1 = lsda.type_entry(1).unwrap();
        assert_eq!(type1.offset(), 0x20);
        assert_eq!(type1.address(&bases), Ok(0x3020));
        assert!(lsda.type_entry(2).unwrap().is_null());
        assert_eq!(lsda.type_entry(0), Err(Error::InvalidTypeIndex));
        assert_eq!(lsda.type_entry(10), Err(Error::OffsetOutOfBounds));

        let spec: Vec<_> = lsda
            .exception_spec(SpecOffset(0))
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(spec, [SpecEntry::Type(1)]);

        let tables = lsda.parse_tables().unwrap();
        assert_eq!(tables.call_sites, call_sites);
        assert_eq!(tables.actions.len(), 4);
        assert_eq!(tables.actions[2].filter, Filter::Cleanup);
        assert_eq!(tables.action_table_end, 0x19);
        assert_eq!(tables.types.len(), 2);
        assert_eq!(
            tables.exception_specs,
            [ExceptionSpec {
                offset: SpecOffset(0),
                entries: alloc::vec![SpecEntry::Type(1)],
            }]
        );
        assert_eq!(tables.end, data.len());
    }

    #[test]
    fn test_arm_ehabi() {
        // Big-endian, exception spec of two TARGET2 words.
        let data = [
            0xff, 0x00, 0x0d, 0x01, 0x04, // header, base at 0x10
            0x00, 0x04, 0x08, 0x01, // call site
            0x7f, 0x00, // action: spec at entry 0
            0x00, // padding
            0x00, 0x00, 0x00, 0x00, // an unreferenced type entry
            0x00, 0x00, 0x01, 0x00, // spec: two words, terminator
            0x00, 0x00, 0x02, 0x00, //
            0x00, 0x00, 0x00, 0x00,
        ];
        let table = GccExceptTable::new(&data, BigEndian, Format::arm_ehabi());
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.ttype_base(), Some(0x10));
        let tables = lsda.parse_tables().unwrap();
        // The word before the base is not referenced.
        assert_eq!(tables.types.len(), 0);
        let entries: Vec<_> = tables.exception_specs[0]
            .entries
            .iter()
            .map(|entry| match entry {
                SpecEntry::TypeInfo(pointer) => (pointer.offset(), pointer.value()),
                SpecEntry::Type(_) => panic!("expected a type_info"),
            })
            .collect();
        assert_eq!(entries, [(0x10, 0x100), (0x14, 0x200)]);
        assert_eq!(tables.end, data.len());
    }

    #[test]
    fn test_unreferenced_bytes_before_types() {
        // Unreferenced bytes after the last action record are not types.
        let data = [
            0xff, 0x03, 0x14, 0x01, 0x04, // header, base at 0x17
            0x00, 0x04, 0x00, 0x01, // call site
            0x01, 0x00, // action: catch type 1
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // unreferenced
            0x00, 0x10, 0x00, 0x00, // type 1
        ];
        for format in [Format::new(4), Format::arm_ehabi()] {
            let table = GccExceptTable::new(&data, LittleEndian, format);
            let tables = table
                .lsda_at(LsdaOffset(0))
                .unwrap()
                .parse_tables()
                .unwrap();
            assert_eq!(tables.types.len(), 1);
            assert_eq!(tables.types[0].value(), 0x1000);
            assert_eq!(tables.end, data.len());
        }
    }

    #[test]
    fn test_call_site_ranges() {
        // Two LLVM call-site ranges that share the action table.
        let data = [
            0xff, 0xff, 0x01, 0x10, // range 1: call sites up to 0x14
            0x00, 0x84, 0x01, 0x00, 0x00, // call site
            0x00, 0x00, 0x00, // padding
            0xff, 0xff, 0x01, 0x04, // range 2 at 0x0c
            0x00, 0x08, 0x02, 0x01, // call site
            0x00, 0x00, // action table at 0x14
        ];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(8));
        let first = table.lsda_at(LsdaOffset(0)).unwrap();
        // Read as one table, the call sites run into the second range.
        assert!(first.parse_tables().is_err());
        let first = first.with_call_site_table_end(0x0c).unwrap();
        let tables = first.parse_tables().unwrap();
        assert_eq!(tables.call_sites.len(), 1);
        assert_eq!(tables.call_sites[0].length, 0x84);
        assert_eq!(first.action_table_offset(), 0x14);
        assert_eq!(first.find_call_site(0x90).unwrap(), None);

        let second = table.lsda_at(LsdaOffset(0x0c)).unwrap();
        let tables = second.parse_tables().unwrap();
        assert_eq!(tables.call_sites[0].action, Some(ActionOffset(0)));
        assert_eq!(tables.end, data.len());
        // An end at or after the action table changes nothing.
        let same = second.clone().with_call_site_table_end(0x20).unwrap();
        assert_eq!(same.parse_tables().unwrap(), tables);
        assert_eq!(
            second.with_call_site_table_end(0x0f).err(),
            Some(Error::OffsetOutOfBounds)
        );
    }

    #[test]
    fn test_sjlj() {
        let data = [
            0xff, 0xff, 0x01, 0x04, // header without a type table
            0x00, 0x00, 0x05, 0x01, // two call sites
            0x00, 0x00, // action: cleanup
        ];
        let format = Format::new(4).with_unwinder(Unwinder::SjLj);
        let table = GccExceptTable::new(&data, LittleEndian, format);
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.find_call_site(0).unwrap(), None);
        let call_site = lsda.find_call_site(2).unwrap().unwrap();
        assert_eq!(
            (call_site.landing_pad, call_site.action),
            (5, Some(ActionOffset(0)))
        );
        assert_eq!(lsda.parse_tables().unwrap().end, data.len());
    }

    #[test]
    fn test_lpstart() {
        let data = [
            0x03, 0x00, 0x10, 0x00, 0x00, // @LPStart: udata4 0x1000
            0xff, 0x03, 0x00, // no type table, empty udata4 call-site table
        ];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(4));
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.lpstart().map(|p| p.value()), Some(0x1000));
        assert_eq!(lsda.call_site_encoding(), Encoding::UDATA4);
        let tables = lsda.parse_tables().unwrap();
        assert_eq!(tables.end, data.len());
        assert_eq!(lsda.ttype_entry_size(), Err(Error::MissingTypeTable));
    }

    #[test]
    fn test_errors() {
        let parse = |data: &[u8]| {
            GccExceptTable::new(data, LittleEndian, Format::new(8))
                .lsda_at(LsdaOffset(0))
                .map(|_| ())
        };
        assert_eq!(parse(&[]), Err(Error::OffsetOutOfBounds));
        assert_eq!(parse(&[0xff]), Err(Error::UnexpectedEof));
        assert_eq!(parse(&[0x0d]), Err(Error::InvalidEncoding(Encoding(0x0d))));
        assert_eq!(
            parse(&[0xff, 0x9b, 0x10, 0x01, 0x00]),
            Err(Error::OffsetOutOfBounds)
        );
        assert_eq!(
            parse(&[0xff, 0xff, 0x13, 0x00]),
            Err(Error::UnsupportedCallSiteEncoding(Encoding(0x13)))
        );
        assert_eq!(
            parse(&[0xff, 0xff, 0x01, 0x04, 0x00]),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(
            GccExceptTable::new(&[0xff], LittleEndian, Format::new(3)).lsda_at(LsdaOffset(0)),
            Err(Error::UnsupportedAddressSize(3))
        );

        // An indirect call-site encoding: libgcc would dereference offsets.
        assert_eq!(
            parse(&[0xff, 0xff, 0x83, 0x00]),
            Err(Error::UnsupportedCallSiteEncoding(Encoding(0x83)))
        );

        // An exception specification without a type table.
        let data = [0xff, 0xff, 0x01, 0x04, 0x00, 0x04, 0x00, 0x01, 0x7f, 0x00];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(8));
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.parse_tables(), Err(Error::MissingTypeTable));

        // An action that points to itself.
        let data = [0xff, 0xff, 0x01, 0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x7f];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(8));
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.parse_tables(), Err(Error::ActionCycle));

        // A call site that points into the middle of a record.
        let data = [
            0xff, 0xff, 0x01, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x80, 0x01,
            0x00,
        ];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(8));
        let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
        assert_eq!(lsda.parse_tables(), Err(Error::MisalignedAction(1)));

        // The Arm EHABI is 32-bit.
        let arm8 = Format::new(8).with_unwinder(Unwinder::ArmEhabi);
        assert_eq!(
            GccExceptTable::new(&[0xff], LittleEndian, arm8).lsda_at(LsdaOffset(0)),
            Err(Error::UnsupportedAddressSize(8))
        );

        // Arm EHABI type table entries are 4-byte words read in place.
        for encoding in [0x04, 0x02, 0x50] {
            let data = [0xff, encoding, 0x08, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
            let table = GccExceptTable::new(&data, LittleEndian, Format::arm_ehabi());
            let lsda = table.lsda_at(LsdaOffset(0)).unwrap();
            assert_eq!(
                lsda.type_entry(1),
                Err(Error::InvalidEncoding(Encoding(encoding)))
            );
        }

        // Call-site values are truncated to the address size, and a region
        // must end within the address space.
        let data = [
            0xff, 0xff, 0x0b, 0x0d, 0xf0, 0xff, 0xff, 0xff, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0x00,
        ];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(4));
        let call_site = table
            .lsda_at(LsdaOffset(0))
            .unwrap()
            .find_call_site(0xffff_fff8);
        assert_eq!(call_site.unwrap().unwrap().start, 0xffff_fff0);
        let data = [
            0xff, 0xff, 0x0b, 0x0d, 0xf0, 0xff, 0xff, 0xff, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x00,
        ];
        let table = GccExceptTable::new(&data, LittleEndian, Format::new(4));
        assert_eq!(
            table.lsda_at(LsdaOffset(0)).unwrap().find_call_site(0),
            Err(Error::CallSiteOutOfRange(4))
        );
    }
}
