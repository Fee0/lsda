//! Tests against the ELF fixtures built from `tests/data/src/eh.cpp` by GCC
//! and clang (see `tests/data/build.sh`).

use lsda::read::{self, Filter, SpecEntry};
use lsda::write::{self, EndianVec, EntryData};
use lsda::{Encoding, Unwinder};

mod elf;

/// Every fixture, and whether its function symbols name the code (on
/// ppc64 with ELF ABI v1 they name function descriptors).
const FIXTURES: [(&str, bool); 10] = [
    ("gcc-x86_64.o", true),
    ("gcc-x86_64-pic.o", true),
    ("gcc-i386.o", true),
    ("gcc-x86_64.so", true),
    ("clang-x86_64.o", true),
    ("clang-i686.o", true),
    ("clang-aarch64.o", true),
    ("clang-powerpc64.o", false),
    ("clang-x86_64.so", true),
    ("clang-armv7a.so", true),
];

/// The functions of `eh.cpp` that have an LSDA.
const FUNCTIONS: [&str; 11] = [
    "cleanup_only",
    "catch_int",
    "catch_many",
    "nested",
    "spec_one",
    "spec_two",
    "spec_none",
    "no_except",
    "rethrow",
    "spec_and_catch",
    "many_handlers",
];

fn for_each_fixture(f: impl Fn(&str, bool, &elf::LsdaSection<'_>)) {
    for (name, named) in FIXTURES {
        let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
        let data = std::fs::read(&path).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let section = elf::load(&file).unwrap_or_else(|| panic!("{name}: no LSDA section"));
        f(name, named, &section);
    }
}

/// Every LSDA parses, both through the relocation layer and from the
/// relocated section, with the same result, and LSDAs do not overlap.
#[test]
fn test_parse_all() {
    for_each_fixture(|name, named, s| {
        assert_eq!(s.lsdas.len(), FUNCTIONS.len(), "{name}");
        if named {
            for function in FUNCTIONS {
                assert!(
                    s.lsda_of(function).is_some(),
                    "{name}: no LSDA for {function}"
                );
            }
        }
        let table = s.table();
        let relocated = s.relocated_table();
        let bases = s.bases();
        for (i, function) in s.lsdas.iter().enumerate() {
            let context = format!("{name} 0x{:x}", function.offset.0);
            let lsda = table.lsda_at(function.offset).expect(&context);
            let tables = lsda.parse_tables().expect(&context);
            let plain = relocated.lsda_at(function.offset).unwrap();
            assert_eq!(plain.parse_tables().unwrap(), tables, "{context}");

            let next = s
                .lsdas
                .get(i + 1)
                .map_or(s.data.len(), |next| next.offset.0);
            assert!(tables.end <= next, "{context}: overlaps the next LSDA");
            for pointer in &tables.types {
                pointer.address(&bases).expect(&context);
            }
            // The lookup finds every call site by its start.
            for call_site in tables.call_sites.iter().filter(|c| c.length != 0) {
                assert_eq!(
                    lsda.find_call_site(call_site.start).unwrap(),
                    Some(*call_site),
                    "{context}"
                );
            }
        }
    });
}

/// Converting the relocated section and writing it back reproduces it byte
/// for byte, with every LSDA converted.
#[test]
fn test_roundtrip() {
    for_each_fixture(|name, _, s| {
        let bases = s.bases();
        let (table, ids) =
            write::GccExceptTable::from_read(&s.relocated_table(), &s.offsets(), &bases)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        for (offset, id) in &ids {
            assert!(
                matches!(table.get(*id).data, EntryData::Lsda(_)),
                "{name}: LSDA at 0x{:x} was not converted",
                offset.0
            );
        }
        let mut w = EndianVec::new(s.endian);
        let offsets = table.write(&mut w, &bases).unwrap();
        assert!(
            w.slice() == s.relocated.as_slice(),
            "{name}: written section differs"
        );
        for (offset, id) in ids {
            assert_eq!(offsets.get(id), offset, "{name}");
        }
    });
}

/// A summary of one LSDA, with type table entries named where the
/// relocations allow it.
struct Summary {
    unwinder: Unwinder,
    ttype_encoding: Encoding,
    /// The filters of each call site's action chain.
    chains: Vec<Vec<Filter>>,
    types: Vec<Option<String>>,
    /// Exception specifications as type names (`None` when unknown).
    specs: Vec<Vec<Option<String>>>,
    call_site_table_len: usize,
    ttype_offset: Option<usize>,
}

fn summarize(s: &elf::LsdaSection<'_>, function: &str) -> Summary {
    let offset = s.lsda_of(function).unwrap().offset;
    let lsda = s.table().lsda_at(offset).unwrap();
    let tables = lsda.parse_tables().unwrap();
    let bases = s.bases();
    let name = |pointer: &read::Pointer| {
        if pointer.is_null() {
            return Some("...".to_string());
        }
        s.type_name(pointer.address(&bases).unwrap(), pointer.is_indirect())
    };
    let types: Vec<Option<String>> = tables.types.iter().map(name).collect();
    let chains = tables
        .call_sites
        .iter()
        .filter_map(|call_site| call_site.action)
        .map(|first| {
            lsda.actions(first)
                .map(|action| action.unwrap().filter)
                .collect()
        })
        .collect();
    let specs = tables
        .exception_specs
        .iter()
        .map(|spec| {
            spec.entries
                .iter()
                .map(|entry| match entry {
                    SpecEntry::Type(index) => types[*index as usize - 1].clone(),
                    SpecEntry::TypeInfo(_) => None,
                })
                .collect()
        })
        .collect();
    Summary {
        unwinder: lsda.format().unwinder,
        ttype_encoding: lsda.ttype_encoding(),
        chains,
        types,
        specs,
        call_site_table_len: lsda.action_table_offset() - lsda.call_site_table_offset(),
        ttype_offset: lsda.ttype_base().map(|base| base - offset.0),
    }
}

impl Summary {
    /// Return the type names caught by each chain, in order.
    fn catches(&self) -> Vec<Vec<Option<String>>> {
        self.chains
            .iter()
            .map(|chain| {
                chain
                    .iter()
                    .filter_map(|filter| match filter {
                        Filter::Catch(index) => Some(self.types[*index as usize - 1].clone()),
                        _ => None,
                    })
                    .collect()
            })
            .collect()
    }

    fn has_spec(&self) -> bool {
        self.chains
            .iter()
            .flatten()
            .any(|filter| matches!(filter, Filter::ExceptionSpec(_)))
    }
}

#[allow(clippy::unnecessary_wraps)]
fn name(name: &str) -> Option<String> {
    Some(name.to_string())
}

/// Each function decodes to what its source says.
#[test]
#[allow(clippy::too_many_lines)]
fn test_expected_contents() {
    for_each_fixture(|fixture, named, s| {
        if !named {
            return;
        }
        // Type names are known from the relocations of relocatable objects.
        let names = s.relocatable;
        let arm = s.format.unwinder == Unwinder::ArmEhabi;
        let check = |function: &str, f: &dyn Fn(&Summary)| {
            let summary = summarize(s, function);
            assert_eq!(summary.unwinder, s.format.unwinder);
            f(&summary);
        };
        let context = |function: &str| format!("{fixture}: {function}");

        check("cleanup_only", &|l| {
            assert!(l.ttype_encoding.is_omit(), "{}", context("cleanup_only"));
            assert!(l.chains.is_empty(), "{}", context("cleanup_only"));
        });

        check("catch_int", &|l| {
            let catches = l.catches();
            assert_eq!(catches.len(), 1, "{}", context("catch_int"));
            if names {
                assert_eq!(catches[0], [name("_ZTIi")], "{}", context("catch_int"));
            }
        });

        check("catch_many", &|l| {
            let catches = l.catches();
            assert_eq!(catches.len(), 1, "{}", context("catch_many"));
            assert_eq!(catches[0].len(), 4, "{}", context("catch_many"));
            assert_eq!(catches[0][3], name("..."), "{}", context("catch_many"));
            if names {
                assert_eq!(
                    catches[0],
                    [
                        name("_ZTI2E2"),
                        name("_ZTI2E1"),
                        name("_ZTIPKc"),
                        name("...")
                    ],
                    "{}",
                    context("catch_many")
                );
            }
        });

        check("nested", &|l| {
            // The inner handler, the cleanup, and the outer handler.
            assert!(
                l.chains
                    .iter()
                    .any(|chain| chain.contains(&Filter::Cleanup)),
                "{}",
                context("nested")
            );
            let catches: Vec<_> = l.catches().into_iter().flatten().collect();
            if names {
                assert!(catches.contains(&name("_ZTI2E1")), "{}", context("nested"));
                assert!(catches.contains(&name("_ZTIi")), "{}", context("nested"));
            }
        });

        for (function, expected) in [
            ("spec_one", vec![name("_ZTIi")]),
            ("spec_two", vec![name("_ZTIi"), name("_ZTI2E1")]),
            ("spec_none", vec![]),
        ] {
            check(function, &|l| {
                assert!(l.has_spec(), "{}", context(function));
                assert_eq!(l.specs.len(), 1, "{}", context(function));
                assert_eq!(l.specs[0].len(), expected.len(), "{}", context(function));
                if names && !arm {
                    let mut actual = l.specs[0].clone();
                    actual.sort();
                    let mut expected = expected.clone();
                    expected.sort();
                    assert_eq!(actual, expected, "{}", context(function));
                }
            });
        }

        check("no_except", &|l| {
            assert!(!l.has_spec(), "{}", context("no_except"));
        });

        check("rethrow", &|l| {
            assert!(
                l.catches().iter().flatten().any(|t| *t == name("...")),
                "{}",
                context("rethrow")
            );
        });

        check("spec_and_catch", &|l| {
            assert!(l.has_spec(), "{}", context("spec_and_catch"));
            if names {
                assert!(
                    l.catches().iter().flatten().any(|t| *t == name("_ZTIi")),
                    "{}",
                    context("spec_and_catch")
                );
            }
        });

        check("many_handlers", &|l| {
            // Multi-byte ULEB128 call-site table length and type base offset.
            assert!(l.call_site_table_len > 0x7f, "{}", context("many_handlers"));
            assert!(
                l.ttype_offset.is_some_and(|offset| offset > 0x7f),
                "{}",
                context("many_handlers")
            );
        });
    });
}

/// The Arm EHABI fixture stores exception specifications as `R_ARM_TARGET2`
/// words.
#[test]
fn test_arm_exception_specs() {
    let path = format!("{}/tests/data/clang-armv7a.so", env!("CARGO_MANIFEST_DIR"));
    let data = std::fs::read(path).unwrap();
    let file = object::File::parse(&*data).unwrap();
    let s = elf::load(&file).unwrap();
    let offset = s.lsda_of("spec_two").unwrap().offset;
    let tables = s.table().lsda_at(offset).unwrap().parse_tables().unwrap();
    let spec = &tables.exception_specs[0];
    assert_eq!(spec.entries.len(), 2);
    for entry in &spec.entries {
        let SpecEntry::TypeInfo(pointer) = entry else {
            panic!("expected a TARGET2 word");
        };
        assert_eq!(pointer.offset() % 4, 0);
        assert!(!pointer.is_null());
    }
}

/// Functions split into several parts, with an LSDA for each: GCC's hot and
/// cold partitions, and LLVM's call-site ranges for basic block sections.
#[test]
fn test_split_functions() {
    for (name, has_ranges) in [
        ("gcc14-x86_64-split.so", false),
        ("clang19-x86_64-bbsections.so", true),
    ] {
        let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
        let data = std::fs::read(&path).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let s = elf::load(&file).unwrap();
        for function in FUNCTIONS {
            assert!(
                s.lsda_of(function).is_some(),
                "{name}: no LSDA for {function}"
            );
        }
        let table = s.table();
        let bases = s.bases();
        let mut ranges = Vec::new();
        let mut explicit_lpstart = 0;
        // The @LPStart of the call-site ranges of the current function.
        let mut function_lpstart = None;
        for function in &s.lsdas {
            let context = format!("{name} 0x{:x}", function.offset.0);
            let next = s.next_offset(function.offset);
            let (lsda, range) = elf::parse_lsda(&table, function.offset, next).expect(&context);
            if range {
                ranges.push(function.offset);
            }
            if let Some(lpstart) = lsda.lpstart() {
                // The start of the section with the landing pads, the same
                // for every range of a function.
                assert_eq!(lpstart.encoding(), Encoding(0x10), "{context}");
                let address = lpstart.address(&bases).unwrap();
                assert_eq!(
                    *function_lpstart.get_or_insert(address),
                    address,
                    "{context}"
                );
                explicit_lpstart += 1;
            }
            if !range {
                // The last range of the function.
                function_lpstart = None;
            }
            let tables = lsda.parse_tables().expect(&context);
            for call_site in tables.call_sites.iter().filter(|c| c.length != 0) {
                assert_eq!(
                    lsda.find_call_site(call_site.start).unwrap(),
                    Some(*call_site),
                    "{context}"
                );
            }
        }
        // GCC keeps the landing pads of each part in that part, and LLVM
        // gives the call-site ranges an explicit @LPStart.
        assert_eq!(explicit_lpstart != 0, has_ranges, "{name}");
        assert_eq!(!ranges.is_empty(), has_ranges, "{name}");

        // Every LSDA converts, except the call-site ranges before the last
        // of each function, and the section is written back identically.
        let (converted, ids) =
            write::GccExceptTable::from_read(&s.relocated_table(), &s.offsets(), &bases).unwrap();
        for (offset, id) in &ids {
            let raw = matches!(converted.get(*id).data, EntryData::Raw(_));
            assert_eq!(raw, ranges.contains(offset), "{name} 0x{:x}", offset.0);
        }
        let mut w = EndianVec::new(s.endian);
        converted.write(&mut w, &bases).unwrap();
        assert!(
            w.slice() == s.relocated.as_slice(),
            "{name}: written section differs"
        );
    }
}
