//! Glue for loading the LSDAs of an ELF file with the `object` and `gimli`
//! crates.
//!
//! Shared by the `lsdadump` example and the integration tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::rc::Rc;

use lsda::read::{EndianSlice, GccExceptTable, Relocate, RelocateReader};
use lsda::{BaseAddresses, Format, LsdaOffset, RunTimeEndian};
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationKind, RelocationTarget,
    SectionIndex,
};

/// A reader that applies the relocations of a relocatable object.
pub type Reader<'data> = RelocateReader<EndianSlice<'data, RunTimeEndian>, Relocations>;

/// The section that holds the LSDAs of an ELF file, and where they are.
pub struct LsdaSection<'data> {
    pub name: String,
    pub endian: RunTimeEndian,
    pub format: Format,
    /// The section contents as stored in the file.
    pub data: &'data [u8],
    /// The section contents with relocations applied: what a linker would
    /// produce for the layout of `address`. Equal to `data` for linked files.
    pub relocated: Vec<u8>,
    /// The address of the section (synthetic for relocatable objects).
    pub address: u64,
    pub relocatable: bool,
    pub relocations: Relocations,
    /// Each LSDA, with the start address of its function, sorted by offset.
    pub lsdas: Vec<FunctionLsda>,
    /// Symbol addresses (in the layout of `address`) and names, sorted.
    pub symbols: Vec<(u64, String)>,
    /// For relocatable objects: the name of the symbol that the pointer at
    /// each address refers to, from the relocations of every section.
    pub pointer_targets: HashMap<u64, String>,
}

/// An LSDA and the function it belongs to.
#[derive(Debug, Clone)]
pub struct FunctionLsda {
    pub offset: LsdaOffset,
    pub function: u64,
    pub name: Option<String>,
}

impl<'data> LsdaSection<'data> {
    /// Return the section through the relocation layer.
    pub fn table(&self) -> GccExceptTable<Reader<'data>> {
        GccExceptTable::from_reader(
            RelocateReader::new(
                EndianSlice::new(self.data, self.endian),
                self.relocations.clone(),
            ),
            self.format,
        )
    }

    /// Return the relocated section as a plain slice.
    pub fn relocated_table(&self) -> GccExceptTable<EndianSlice<'_, RunTimeEndian>> {
        GccExceptTable::new(&self.relocated, self.endian, self.format)
    }

    /// Return the base addresses for resolving pointers.
    pub fn bases(&self) -> BaseAddresses {
        BaseAddresses::default().set_section(self.address)
    }

    /// Return the offsets of all LSDAs.
    pub fn offsets(&self) -> Vec<LsdaOffset> {
        self.lsdas.iter().map(|lsda| lsda.offset).collect()
    }

    /// Return the offset of the first LSDA after `offset`, or the section
    /// length.
    pub fn next_offset(&self, offset: LsdaOffset) -> usize {
        self.lsdas
            .iter()
            .map(|lsda| lsda.offset.0)
            .filter(|&next| next > offset.0)
            .min()
            .unwrap_or(self.data.len())
    }
}

/// Parse the LSDA at `offset`. If its call-site table extends over the next
/// LSDA at `next`, it is an LLVM call-site range (`-fbasic-block-sections`):
/// end its call-site table there, and return true.
pub fn parse_lsda<R: lsda::read::Reader>(
    table: &GccExceptTable<R>,
    offset: LsdaOffset,
    next: usize,
) -> lsda::read::Result<(lsda::read::Lsda<R>, bool)> {
    let lsda = table.lsda_at(offset)?;
    if lsda.call_site_table_offset() <= next && next < lsda.action_table_offset() {
        Ok((lsda.with_call_site_table_end(next)?, true))
    } else {
        Ok((lsda, false))
    }
}

impl LsdaSection<'_> {
    /// Return the LSDA of the named function.
    pub fn lsda_of(&self, name: &str) -> Option<&FunctionLsda> {
        self.lsdas
            .iter()
            .find(|lsda| lsda.name.as_deref() == Some(name))
    }

    /// Return the name of the symbol at `address`, if any.
    pub fn symbol_name(&self, address: u64) -> Option<&str> {
        symbol_at(&self.symbols, address)
    }

    /// Name the `type_info` object that a type table entry refers to, if
    /// the relocations make that possible (relocatable objects only).
    ///
    /// An indirect pointer refers to a slot that holds the address; its name
    /// is taken from the relocation of the slot, or from a `DW.ref.` symbol.
    pub fn type_name(&self, address: u64, indirect: bool) -> Option<String> {
        if !indirect {
            return self.symbol_name(address).map(str::to_string);
        }
        if let Some(name) = self.pointer_targets.get(&address) {
            return Some(name.clone());
        }
        self.symbol_name(address)
            .and_then(|name| name.strip_prefix("DW.ref."))
            .map(str::to_string)
    }

    /// Format an address, followed by the name of the symbol there, if any.
    pub fn describe(&self, address: u64) -> String {
        match self.symbol_name(address) {
            Some(name) => format!("0x{address:x} ({name})"),
            None => format!("0x{address:x}"),
        }
    }
}

/// Return the name of the symbol at `address` in a sorted symbol list.
fn symbol_at(symbols: &[(u64, String)], address: u64) -> Option<&str> {
    let index = symbols.partition_point(|(a, _)| *a < address);
    symbols
        .get(index)
        .filter(|(a, _)| *a == address)
        .map(|(_, name)| name.as_str())
}

/// Applies relocations, using a synthetic layout in which every section of
/// a relocatable object has its own address.
#[derive(Debug, Clone, Default)]
pub struct Relocations {
    /// Section offset -> relocated value.
    values: Rc<HashMap<usize, u64>>,
}

impl Relocate for Relocations {
    fn relocate(&self, offset: usize, _size: u8, value: u64) -> lsda::read::Result<u64> {
        Ok(self.values.get(&offset).copied().unwrap_or(value))
    }
}

/// The synthetic layout of a relocatable object: the address of each
/// section, and of each symbol.
struct Layout {
    sections: HashMap<SectionIndex, u64>,
    symbols: HashMap<object::SymbolIndex, u64>,
}

impl Layout {
    fn new(file: &object::File<'_>) -> Self {
        let mut sections = HashMap::new();
        let mut next = 0x10000u64;
        for section in file.sections() {
            if file.kind() == object::ObjectKind::Relocatable {
                sections.insert(section.index(), next);
                next += (section.size() + 0xfff) & !0xfff;
                next += 0x1000;
            } else {
                sections.insert(section.index(), section.address());
            }
        }
        let mut symbols = HashMap::new();
        let mut undefined = 0x0100_0000u64;
        for symbol in file.symbols() {
            let address = match symbol.section_index() {
                Some(index) if file.kind() == object::ObjectKind::Relocatable => {
                    sections[&index] + symbol.address()
                }
                None if symbol.is_undefined() => {
                    undefined += 0x10;
                    undefined
                }
                _ => symbol.address(),
            };
            symbols.insert(symbol.index(), address);
        }
        Layout { sections, symbols }
    }

    fn target(&self, target: RelocationTarget) -> Option<u64> {
        match target {
            RelocationTarget::Symbol(index) => self.symbols.get(&index).copied(),
            RelocationTarget::Section(index) => self.sections.get(&index).copied(),
            _ => None,
        }
    }
}

/// Apply the relocations of `section`, returning the relocated contents and
/// the value of every relocated field.
fn relocate_section(
    file: &object::File<'_>,
    section: &object::Section<'_, '_>,
    layout: &Layout,
    endian: RunTimeEndian,
) -> (Vec<u8>, HashMap<usize, u64>) {
    let mut data = section.data().unwrap().to_vec();
    let mut values = HashMap::new();
    let address = layout.sections[&section.index()];
    for (offset, relocation) in section.relocations() {
        let offset = offset as usize;
        let Some((kind, size)) = kind_and_size(file, &relocation) else {
            continue;
        };
        let field = &mut data[offset..offset + size];
        let addend = if relocation.has_implicit_addend() {
            let raw = read_sized(field, endian);
            let shift = 64 - size * 8;
            ((raw << shift).cast_signed() >> shift) + relocation.addend()
        } else {
            relocation.addend()
        };
        let symbol = layout
            .target(relocation.target())
            .unwrap_or_else(|| panic!("unsupported relocation target {relocation:?}"));
        let value = match kind {
            RelocationKind::Absolute => symbol.wrapping_add_signed(addend),
            RelocationKind::Relative => symbol
                .wrapping_add_signed(addend)
                .wrapping_sub(address + offset as u64),
            kind => panic!(
                "{:?}: unsupported relocation kind {kind:?} in {}",
                file.architecture(),
                section.name().unwrap_or("?")
            ),
        };
        write_sized(field, value, endian);
        values.insert(offset, value);
    }
    (data, values)
}

/// Return the kind and size in bytes of a relocation, or `None` for
/// relocations that change nothing (`R_*_NONE`).
fn kind_and_size(
    file: &object::File<'_>,
    relocation: &object::Relocation,
) -> Option<(RelocationKind, usize)> {
    let size = usize::from(relocation.size() / 8);
    if size != 0 {
        return Some((relocation.kind(), size));
    }
    // `object` does not classify these 64-bit PowerPC relocations.
    if let (object::Architecture::PowerPc64, RelocationFlags::Elf { r_type }) =
        (file.architecture(), relocation.flags())
    {
        match r_type {
            object::elf::R_PPC64_ADDR64 => return Some((RelocationKind::Absolute, 8)),
            object::elf::R_PPC64_REL64 => return Some((RelocationKind::Relative, 8)),
            _ => {}
        }
    }
    None
}

fn read_sized(field: &[u8], endian: RunTimeEndian) -> u64 {
    let mut bytes = [0u8; 8];
    if endian == RunTimeEndian::Big {
        bytes[8 - field.len()..].copy_from_slice(field);
        u64::from_be_bytes(bytes)
    } else {
        bytes[..field.len()].copy_from_slice(field);
        u64::from_le_bytes(bytes)
    }
}

fn write_sized(field: &mut [u8], value: u64, endian: RunTimeEndian) {
    let len = field.len();
    if endian == RunTimeEndian::Big {
        field.copy_from_slice(&value.to_be_bytes()[8 - len..]);
    } else {
        field.copy_from_slice(&value.to_le_bytes()[..len]);
    }
}

/// Load the LSDA section of an ELF file: `.gcc_except_table`, or
/// `.ARM.extab` for Arm. Returns `None` if there is none.
pub fn load<'data>(file: &object::File<'data>) -> Option<LsdaSection<'data>> {
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let arm = file.architecture() == object::Architecture::Arm;
    let format = if arm {
        Format::arm_ehabi()
    } else {
        Format::new(if file.is_64() { 8 } else { 4 })
    };
    let name = if arm {
        ".ARM.extab"
    } else {
        ".gcc_except_table"
    };
    let section = file.section_by_name(name)?;
    let relocatable = file.kind() == object::ObjectKind::Relocatable;
    let layout = Layout::new(file);
    let address = layout.sections[&section.index()];
    let (relocated, values) = relocate_section(file, &section, &layout, endian);

    // Undefined symbols have synthetic addresses in relocatable objects.
    // Arm mapping symbols (`$a`, `$d`, ...) are not names.
    let mut symbols: Vec<(u64, String)> = file
        .symbols()
        .filter(|symbol| relocatable || !symbol.is_undefined())
        .filter_map(|symbol| {
            let name = symbol
                .name()
                .ok()
                .filter(|name| !name.is_empty() && !name.starts_with('$'))?;
            Some((layout.symbols[&symbol.index()], name.to_string()))
        })
        .collect();
    symbols.sort();

    // In a relocatable object, record the target of every relocated
    // pointer-sized field, to name indirect type_info references.
    let mut pointer_targets = HashMap::new();
    if relocatable {
        for other in file.sections() {
            for (offset, relocation) in other.relocations() {
                if let RelocationTarget::Symbol(index) = relocation.target()
                    && let Ok(symbol) = file.symbol_by_index(index)
                    && let Ok(name) = symbol.name()
                {
                    let address = layout.sections[&other.index()] + offset;
                    pointer_targets.insert(address, name.to_string());
                }
            }
        }
    }

    let mut lsdas = if arm {
        arm_lsdas(file, &layout, address, endian)
    } else {
        eh_frame_lsdas(file, &layout, address, endian, format)
    };
    for lsda in &mut lsdas {
        // Ignore the Thumb bit.
        let function = if arm {
            lsda.function & !1
        } else {
            lsda.function
        };
        lsda.name = symbol_at(&symbols, function).map(str::to_string);
    }
    lsdas.sort_by_key(|lsda| lsda.offset);

    Some(LsdaSection {
        name: name.to_string(),
        endian,
        format,
        data: section.data().ok()?,
        relocated,
        address,
        relocatable,
        relocations: Relocations {
            values: Rc::new(values),
        },
        lsdas,
        symbols,
        pointer_targets,
    })
}

/// Find the LSDAs through the FDEs in `.eh_frame`.
fn eh_frame_lsdas(
    file: &object::File<'_>,
    layout: &Layout,
    section_address: u64,
    endian: RunTimeEndian,
    format: Format,
) -> Vec<FunctionLsda> {
    use gimli::UnwindSection;

    let Some(eh_frame) = file.section_by_name(".eh_frame") else {
        return Vec::new();
    };
    let (data, _) = relocate_section(file, &eh_frame, layout, endian);
    let gimli_endian = if endian == RunTimeEndian::Big {
        gimli::RunTimeEndian::Big
    } else {
        gimli::RunTimeEndian::Little
    };
    let mut section = gimli::EhFrame::new(&data, gimli_endian);
    section.set_address_size(format.address_size);
    let mut bases =
        gimli::BaseAddresses::default().set_eh_frame(layout.sections[&eh_frame.index()]);
    if let Some(text) = file.section_by_name(".text") {
        bases = bases.set_text(layout.sections[&text.index()]);
    }

    let mut lsdas = Vec::new();
    let mut entries = section.entries(&bases);
    while let Some(entry) = entries.next().expect(".eh_frame entry") {
        let gimli::CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let fde = partial
            .parse(gimli::EhFrame::cie_from_offset)
            .expect(".eh_frame FDE");
        let Some(lsda) = fde.lsda() else {
            continue;
        };
        let address = match lsda {
            gimli::Pointer::Direct(address) | gimli::Pointer::Indirect(address) => address,
        };
        lsdas.push(FunctionLsda {
            offset: LsdaOffset((address - section_address) as usize),
            function: fde.initial_address(),
            name: None,
        });
    }
    lsdas
}

/// Find the LSDAs of the generic-model entries in `.ARM.extab` of a linked
/// Arm file, through `.ARM.exidx`.
fn arm_lsdas(
    file: &object::File<'_>,
    layout: &Layout,
    extab_address: u64,
    endian: RunTimeEndian,
) -> Vec<FunctionLsda> {
    let Some(exidx) = file.section_by_name(".ARM.exidx") else {
        return Vec::new();
    };
    let extab = file.section_by_name(".ARM.extab").unwrap();
    let extab_data = extab.data().unwrap();
    let exidx_address = layout.sections[&exidx.index()];
    let word = |data: &[u8], offset: usize| read_sized(&data[offset..offset + 4], endian) as u32;
    let prel31 = |word: u32, place: u64| {
        place.wrapping_add_signed(i64::from((word << 1).cast_signed() >> 1)) & 0xffff_ffff
    };

    let data = exidx.data().unwrap();
    let mut lsdas = Vec::new();
    for offset in (0..data.len()).step_by(8) {
        let function = prel31(word(data, offset), exidx_address + offset as u64);
        let second = word(data, offset + 4);
        if second == 1 || second & 0x8000_0000 != 0 {
            continue;
        }
        let entry = prel31(second, exidx_address + offset as u64 + 4) - extab_address;
        let entry = entry as usize;
        if word(extab_data, entry) & 0x8000_0000 != 0 {
            // Compact model: no LSDA in the GCC format.
            continue;
        }
        let count = (word(extab_data, entry + 4) >> 24) as usize;
        lsdas.push(FunctionLsda {
            offset: LsdaOffset(entry + 8 + 4 * count),
            function,
            name: None,
        });
    }
    lsdas
}
