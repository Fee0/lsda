//! Interoperability with the `ehabi` crate, which reads and writes the Arm
//! EHABI `.ARM.exidx` and `.ARM.extab` sections. A generic-model
//! `.ARM.extab` entry for `__gxx_personality_v0` ends with an LSDA: `ehabi`
//! finds it (`GenericEntry::gnu_lsda_offset`) and carries its bytes
//! (`GenericData::Gnu`), and this crate decodes and encodes them.
//!
//! The tests use the Arm fixture, and every linked Arm file in the directory
//! named by `LSDA_CORPUS` if it is set (see `tests/corpus.rs`).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use ehabi::read::UnwindEntry;
use ehabi::write::{GenericData, IndexEntryData, Sections, UnwindTable};
use lsda::read::GccExceptTable;
use lsda::write::{self, Action, Address, CallSite, EntryData, ExceptionSpec, Filter, Lsda};
use lsda::{BaseAddresses, Encoding, Format, LsdaOffset, RunTimeEndian};
use object::{Object, ObjectSection, ObjectSymbol};

/// Personality routines whose generic-model entries use the GCC/LLVM layout,
/// with an LSDA in the `.gcc_except_table` format.
const GNU_PERSONALITIES: [&str; 5] = [
    "__gxx_personality_v0",
    "__gcc_personality_v0",
    "__gnu_objc_personality_v0",
    "__gccgo_personality_v0",
    "rust_eh_personality",
];

/// The `.ARM.exidx` and `.ARM.extab` sections of a linked Arm file.
struct ArmSections {
    name: String,
    endian: RunTimeEndian,
    exidx: Vec<u8>,
    extab: Vec<u8>,
    bases: ehabi::BaseAddresses,
    extab_address: u64,
    /// Defined symbols by address, to name personality routines.
    symbols: HashMap<u32, String>,
}

impl ArmSections {
    fn load(path: &Path) -> Option<ArmSections> {
        let data = std::fs::read(path).ok()?;
        let file = object::File::parse(&*data).ok()?;
        if file.architecture() != object::Architecture::Arm
            || file.kind() == object::ObjectKind::Relocatable
        {
            return None;
        }
        let exidx = file.section_by_name(".ARM.exidx")?;
        let extab = file.section_by_name(".ARM.extab")?;
        let bases = ehabi::BaseAddresses::default()
            .set_exidx(exidx.address() as u32)
            .set_extab(extab.address() as u32);
        let symbols = file
            .symbols()
            .chain(file.dynamic_symbols())
            .filter(|symbol| !symbol.is_undefined())
            .filter_map(|symbol| {
                // Arm mapping symbols (`$a`, `$d`, ...) are not names.
                let name = symbol.name().ok().filter(|name| !name.starts_with('$'))?;
                // Ignore the Thumb bit.
                Some((symbol.address() as u32 & !1, name.to_string()))
            })
            .collect();
        Some(ArmSections {
            name: path.display().to_string(),
            endian: if file.is_little_endian() {
                RunTimeEndian::Little
            } else {
                RunTimeEndian::Big
            },
            exidx: exidx.data().ok()?.to_vec(),
            extab: extab.data().ok()?.to_vec(),
            bases,
            extab_address: extab.address(),
            symbols,
        })
    }

    fn ehabi_endian(&self) -> ehabi::RunTimeEndian {
        match self.endian {
            RunTimeEndian::Little => ehabi::RunTimeEndian::Little,
            RunTimeEndian::Big => ehabi::RunTimeEndian::Big,
        }
    }

    /// The offsets in `.ARM.extab` of the generic entries that use the
    /// GCC/LLVM layout and of their LSDAs, as `ehabi` finds them.
    ///
    /// Entries whose personality routine is named and not one of
    /// [`GNU_PERSONALITIES`] are left out. A routine without a name (one
    /// called through the PLT of a stripped library) is taken to use the
    /// GCC/LLVM layout, as every compiler for Arm Linux does.
    fn lsdas(&self) -> Vec<(usize, LsdaOffset)> {
        let endian = self.ehabi_endian();
        let exidx = ehabi::read::ExIdx::new(&self.exidx, endian);
        let extab = ehabi::read::ExTab::new(&self.extab, endian);
        let mut lsdas = Vec::new();
        let mut entries = exidx.entries();
        while let Some(entry) = entries.next().unwrap() {
            let UnwindEntry::Generic(generic) = entry.resolve(&extab, &self.bases).unwrap() else {
                continue;
            };
            let personality = generic.personality_address(&self.bases).unwrap() & !1;
            if let Some(name) = self.symbols.get(&personality)
                && !GNU_PERSONALITIES.contains(&name.as_str())
            {
                continue;
            }
            let lsda = generic.gnu_lsda_offset().unwrap();
            lsdas.push((generic.offset().0, LsdaOffset(lsda.0)));
        }
        lsdas.sort_unstable();
        lsdas.dedup();
        lsdas
    }
}

/// The Arm fixture, and the linked Arm files of the corpus.
fn arm_files() -> Vec<ArmSections> {
    let mut paths = vec![PathBuf::from(format!(
        "{}/tests/data/clang-armv7a.so",
        env!("CARGO_MANIFEST_DIR")
    ))];
    if let Ok(dir) = std::env::var("LSDA_CORPUS") {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        walk(Path::new(&dir), &mut paths);
    }
    paths
        .iter()
        .filter_map(|path| ArmSections::load(path))
        .collect()
}

/// Every LSDA that `ehabi` finds parses completely, and ends before the next
/// `.ARM.extab` entry.
#[test]
fn test_read_lsdas_found_by_ehabi() {
    let mut count = 0;
    for s in arm_files() {
        let table = GccExceptTable::new(&s.extab, s.endian, Format::arm_ehabi());
        let lsdas = s.lsdas();
        for (i, (entry, offset)) in lsdas.iter().enumerate() {
            let context = format!("{}: entry at {entry:#x}", s.name);
            let lsda = table.lsda_at(*offset).expect(&context);
            let tables = lsda.parse_tables().expect(&context);
            let next = lsdas.get(i + 1).map_or(s.extab.len(), |next| next.0);
            assert!(
                tables.end <= next,
                "{context}: LSDA overlaps the next entry"
            );
            for call_site in tables.call_sites.iter().filter(|c| c.length != 0) {
                assert_eq!(
                    lsda.find_call_site(call_site.start).unwrap(),
                    Some(*call_site),
                    "{context}"
                );
            }
            count += 1;
        }
    }
    assert_ne!(count, 0);
    eprintln!("{count} LSDAs found by ehabi parsed");
}

/// `ehabi` converts the tables, this crate converts and rewrites the LSDA of
/// every generic entry, and `ehabi` writes the sections back identically:
/// the workflow for editing the LSDAs of an Arm file.
#[test]
fn test_edit_lsdas_through_ehabi() {
    for s in arm_files() {
        let endian = s.ehabi_endian();
        let exidx = ehabi::read::ExIdx::new(&s.exidx, endian);
        let extab = ehabi::read::ExTab::new(&s.extab, endian);
        let mut table = UnwindTable::from_read(&exidx, &extab, &s.bases).unwrap();

        // Where each entry is, and so where its LSDA is: pc-relative values
        // in an LSDA depend on its address.
        let mut sections = Sections::new(ehabi::write::EndianVec::new(endian));
        let entry_offsets = table.write(&mut sections, &s.bases).unwrap();
        let lsdas = s.lsdas();

        // The entry of each offset; entries may be shared by functions.
        let ids: BTreeMap<usize, _> = table
            .index_entries()
            .iter()
            .filter_map(|entry| match entry.data {
                IndexEntryData::ExTab(id) => Some((entry_offsets.get(id).0, id)),
                _ => None,
            })
            .collect();
        for (entry_offset, lsda_offset) in &lsdas {
            let context = format!("{}: entry at {entry_offset:#x}", s.name);
            let id = ids[entry_offset];
            let ehabi::write::ExTabEntry::Generic(generic) = table.extab_entry_mut(id) else {
                panic!("{context}: not a generic entry");
            };
            let GenericData::Gnu { lsda: bytes, .. } = &mut generic.data else {
                panic!("{context}: ehabi did not convert the GCC/LLVM layout");
            };
            let bases =
                BaseAddresses::default().set_section(s.extab_address + lsda_offset.0 as u64);

            // The bytes run to the next entry, so they may end with padding.
            let read = GccExceptTable::new(bytes, s.endian, Format::arm_ehabi());
            let (model, ids) =
                write::GccExceptTable::from_read(&read, &[LsdaOffset(0)], &bases).expect(&context);
            assert!(
                matches!(model.get(ids[&LsdaOffset(0)]).data, EntryData::Lsda(_)),
                "{context}: not converted"
            );
            let mut w = write::EndianVec::new(s.endian);
            model.write(&mut w, &bases).expect(&context);
            assert_eq!(w.slice(), bytes.as_slice(), "{context}");
            *bytes = w.into_vec();
        }

        let mut sections = Sections::new(ehabi::write::EndianVec::new(endian));
        table.write(&mut sections, &s.bases).unwrap();
        assert!(
            sections.exidx.slice() == s.exidx,
            "{}: .ARM.exidx differs",
            s.name
        );
        assert!(
            sections.extab.slice() == s.extab,
            "{}: .ARM.extab differs",
            s.name
        );
        eprintln!("{}: {} LSDAs rewritten", s.name, lsdas.len());
    }
}

/// An LSDA written by this crate, in an `.ARM.extab` entry written by
/// `ehabi`, reads back as written.
#[test]
fn test_write_lsda_into_ehabi_entry() {
    // void f() throw(E) { try { g(); } catch (int) {} }
    let mut lsda = Lsda::new();
    // clang's encoding: the type table holds raw R_ARM_TARGET2 words.
    lsda.ttype_encoding = Encoding::ABSPTR;
    let int = lsda.add_type(Some(Address::Constant(0x1_2340)));
    let spec = lsda.add_exception_spec(ExceptionSpec::TypeInfos(vec![Address::Constant(0x1_2350)]));
    let spec_action = lsda.add_action(Action {
        filter: Filter::ExceptionSpec(spec),
        next: None,
    });
    let catch = lsda.add_action(Action {
        filter: Filter::Catch(int),
        next: Some(spec_action),
    });
    lsda.call_sites
        .push(CallSite::new(0x8, 0x4, 0x20, Some(catch)));
    let mut bytes = write::EndianVec::new(RunTimeEndian::Little);
    lsda.write(&mut bytes, Format::arm_ehabi(), &BaseAddresses::default())
        .unwrap();

    let mut table = UnwindTable::new();
    let entry = table.add_extab_entry(ehabi::write::ExTabEntry::Generic(
        ehabi::write::GenericEntry {
            personality: ehabi::write::Address::Constant(0x9000),
            data: GenericData::Gnu {
                // push {r4, lr}
                instructions: ehabi::UnwindInstruction::pop_core(0x4010),
                lsda: bytes.into_vec(),
            },
        },
    ));
    table.add_index_entry(ehabi::write::IndexEntry {
        function: ehabi::write::Address::Constant(0x8000),
        data: IndexEntryData::ExTab(entry),
    });
    let mut sections = Sections::new(ehabi::write::EndianVec::new(ehabi::LittleEndian));
    let bases = ehabi::BaseAddresses::default()
        .set_exidx(0xa000)
        .set_extab(0xa100);
    table.write(&mut sections, &bases).unwrap();

    let s = ArmSections {
        name: "written".to_string(),
        endian: RunTimeEndian::Little,
        exidx: sections.exidx.slice().to_vec(),
        extab: sections.extab.slice().to_vec(),
        bases,
        extab_address: 0xa100,
        symbols: HashMap::new(),
    };
    let [(_, offset)] = s.lsdas()[..] else {
        panic!("expected one LSDA");
    };
    let read = GccExceptTable::new(&s.extab, s.endian, Format::arm_ehabi());
    let (model, ids) =
        write::GccExceptTable::from_read(&read, &[offset], &BaseAddresses::default()).unwrap();
    let EntryData::Lsda(read_back) = &model.get(ids[&offset]).data else {
        panic!("not converted");
    };
    assert_eq!(read_back, &lsda);
}
