//! Robustness and consistency.
//!
//! * Every read path must return `Ok` or `Err` on arbitrary input, never
//!   panic or loop forever. Inputs are random sections and mutations of the
//!   fixture sections, read in both byte orders, with every unwinder variant
//!   and address size.
//! * Whenever `GccExceptTable::from_read` succeeds, writing the table must
//!   reproduce the section byte for byte.
//! * Randomly generated LSDAs must read back as written, and convert back to
//!   LSDAs that write the same bytes.
//!
//! Set `LSDA_FUZZ_ITERATIONS` to run longer than the default.

use lsda::read::{ActionOffset, GccExceptTable, Reader, SpecOffset};
use lsda::write::{self, Action, ActionId, Address, CallSite, EndianVec, EntryData, Filter};
use lsda::write::{ExceptionSpec, LpStart, Lsda, SpecId, TypeId, Writer};
use lsda::{BaseAddresses, Encoding, Format, LsdaOffset, RunTimeEndian, Unwinder};

mod rng;
use rng::{Rng, iterations};

const SECTION: u64 = 0x10_0000;

fn bases() -> BaseAddresses {
    BaseAddresses::default()
        .set_section(SECTION)
        .set_text(0x1000)
        .set_data(0x20_0000)
        .set_function(0x2000)
}

fn random_format(rng: &mut Rng) -> Format {
    let unwinder = match rng.below(3) {
        0 => Unwinder::Dwarf,
        1 => Unwinder::ArmEhabi,
        _ => Unwinder::SjLj,
    };
    let address_size = if rng.chance(50) { 4 } else { 8 };
    Format {
        address_size,
        unwinder,
    }
}

fn random_endian(rng: &mut Rng) -> RunTimeEndian {
    if rng.chance(50) {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    }
}

/// Exercise every read path on the LSDA at `offset`.
fn read_everything<R: Reader>(table: &GccExceptTable<R>, offset: usize, rng: &mut Rng) {
    let Ok(lsda) = table.lsda_at(LsdaOffset(offset)) else {
        return;
    };
    let bases = bases();
    if let Some(lpstart) = lsda.lpstart() {
        let _ = lpstart.address(&bases);
    }
    let _ = lsda.ttype_entry_size();
    let mut call_sites = lsda.call_sites();
    while let Ok(Some(call_site)) = call_sites.next() {
        if let Some(action) = call_site.action
            && let Ok(mut actions) = lsda.actions(action)
        {
            while let Ok(Some(_)) = actions.next() {}
        }
    }
    let _ = lsda.find_call_site(rng.below(0x200));
    if let Ok(mut actions) = lsda.actions(ActionOffset(rng.below(64) as usize)) {
        while let Ok(Some(_)) = actions.next() {}
    }
    if let Ok(pointer) = lsda.type_entry(rng.below(8)) {
        let _ = pointer.address(&bases);
    }
    if let Ok(mut spec) = lsda.exception_spec(SpecOffset(rng.below(16) as usize)) {
        while let Ok(Some(_)) = spec.next() {}
    }
    if let Ok(tables) = lsda.parse_tables() {
        assert!(tables.end <= table.reader().len() + 8);
        for pointer in &tables.types {
            let _ = pointer.address(&bases);
        }
    }
}

/// Read a section in every way, and check that a successful conversion
/// writes it back unchanged.
fn check_section(
    data: &[u8],
    offsets: &[usize],
    format: Format,
    endian: RunTimeEndian,
    rng: &mut Rng,
) {
    let table = GccExceptTable::new(data, endian, format);
    for &offset in offsets {
        read_everything(&table, offset, rng);
    }
    let offsets: Vec<_> = offsets.iter().map(|&o| LsdaOffset(o)).collect();
    let bases = bases();
    if let Ok((converted, _)) = write::GccExceptTable::from_read(&table, &offsets, &bases) {
        let mut w = EndianVec::new(endian);
        converted
            .write(&mut w, &bases)
            .expect("a converted table must be writable");
        assert_eq!(w.slice(), data, "{format:?} {endian:?} {offsets:?}");
    }
}

#[test]
fn test_random_sections() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..iterations("LSDA_FUZZ_ITERATIONS", 20_000) {
        let len = rng.below(96) as usize + 1;
        let mut data = rng.bytes(len);
        // Make plausible headers likely.
        if rng.chance(70) {
            data[0] = 0xff;
        }
        if len > 2 && rng.chance(50) {
            data[2] = 0x01;
        }
        let offsets: Vec<usize> = (0..=rng.below(3))
            .map(|_| rng.below(len as u64) as usize)
            .collect();
        let format = random_format(&mut rng);
        let endian = random_endian(&mut rng);
        check_section(&data, &offsets, format, endian, &mut rng);
    }
}

#[test]
fn test_mutated_fixtures() {
    let mut rng = Rng(0x0fed_cba9_8765_4321);
    let iterations = iterations("LSDA_FUZZ_ITERATIONS", 20_000);
    let fixtures = load_fixtures();
    for i in 0..iterations {
        let (data, offsets, format, endian) = &fixtures[i as usize % fixtures.len()];
        let mut data = data.clone();
        for _ in 0..=rng.below(4) {
            let index = rng.below(data.len() as u64) as usize;
            data[index] = if rng.chance(50) {
                rng.byte()
            } else {
                data[index] ^ (1 << rng.below(8))
            };
        }
        let mut offsets = offsets.clone();
        if rng.chance(20) {
            offsets.push(rng.below(data.len() as u64) as usize);
        }
        let (format, endian) = if rng.chance(80) {
            (*format, *endian)
        } else {
            (random_format(&mut rng), random_endian(&mut rng))
        };
        check_section(&data, &offsets, format, endian, &mut rng);
    }
}

/// The relocated LSDA sections of the fixtures, with their offsets.
fn load_fixtures() -> Vec<(Vec<u8>, Vec<usize>, Format, RunTimeEndian)> {
    let dir = format!("{}/tests/data", env!("CARGO_MANIFEST_DIR"));
    let mut fixtures = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !matches!(path.extension().and_then(|e| e.to_str()), Some("o" | "so")) {
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let section = elf::load(&file).unwrap();
        fixtures.push((
            section.relocated.clone(),
            section.offsets().iter().map(|o| o.0).collect(),
            section.format,
            section.endian,
        ));
    }
    assert_ne!(fixtures.len(), 0, "no fixtures");
    fixtures
}

mod elf;

/// Pick a valid encoding for pointers of the given kind.
fn random_encoding(rng: &mut Rng, fixed_size: bool) -> Encoding {
    let formats: &[u8] = if fixed_size {
        &[0x00, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c]
    } else {
        &[0x00, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0a, 0x0b, 0x0c]
    };
    let format = formats[rng.below(formats.len() as u64) as usize];
    let application = [0x00, 0x10, 0x20, 0x30, 0x40][rng.below(5) as usize];
    let indirect = if rng.chance(30) { 0x80 } else { 0 };
    Encoding(format | application | indirect)
}

/// An address near one of the bases, or null.
fn random_address(rng: &mut Rng) -> Address {
    let base = [SECTION, 0x1000, 0x20_0000, 0x2000][rng.below(4) as usize];
    Address::Constant(if rng.chance(10) {
        0
    } else {
        base + rng.below(0x400) * 4
    })
}

fn random_lsda(rng: &mut Rng, format: Format) -> Lsda {
    let mut lsda = Lsda::new();
    if rng.chance(20) {
        lsda.lpstart = Some(LpStart {
            encoding: random_encoding(rng, false),
            address: random_address(rng),
        });
    }
    lsda.call_site_encoding = match rng.below(4) {
        0 => Encoding::ULEB128,
        1 => Encoding::UDATA4,
        2 => Encoding::SDATA4,
        _ => Encoding::ABSPTR,
    };
    lsda.type_table_alignment = 1 << rng.below(5);

    let arm = format.unwinder == Unwinder::ArmEhabi;
    let type_count = rng.below(6) as usize;
    let spec_count = rng.below(3) as usize;
    if type_count > 0 || spec_count > 0 || rng.chance(20) {
        lsda.ttype_encoding = random_encoding(rng, true);
    }
    for _ in 0..type_count {
        let address = if rng.chance(20) {
            None
        } else {
            Some(random_address(rng))
        };
        lsda.add_type(address);
    }
    for _ in 0..spec_count {
        let len = rng.below(3) as usize;
        let spec = if arm {
            ExceptionSpec::TypeInfos(
                (0..len)
                    .map(|_| Address::Constant(rng.below(0x1_0000) + 1))
                    .collect(),
            )
        } else if type_count == 0 {
            ExceptionSpec::Types(Vec::new())
        } else {
            ExceptionSpec::Types(
                (0..len)
                    .map(|_| TypeId(rng.below(type_count as u64) as usize))
                    .collect(),
            )
        };
        lsda.add_exception_spec(spec);
    }

    // Actions link only to later actions, so that chains end. Every action
    // is the head of a call site's chain, so that all are reachable, and
    // every exception specification is used by an action, as producers emit
    // only referenced specifications.
    let action_count = rng.below(8) as usize + spec_count;
    for i in 0..action_count {
        let filter = match rng.below(3) {
            _ if i < spec_count => Filter::ExceptionSpec(SpecId(i)),
            1 if type_count > 0 => Filter::Catch(TypeId(rng.below(type_count as u64) as usize)),
            2 if spec_count > 0 => {
                Filter::ExceptionSpec(SpecId(rng.below(spec_count as u64) as usize))
            }
            _ => Filter::Cleanup,
        };
        let next = (i + 1 < action_count && rng.chance(50))
            .then(|| ActionId(i + 1 + rng.below((action_count - i - 1) as u64) as usize));
        lsda.add_action(Action { filter, next });
    }
    let mut start = 0;
    for i in 0..action_count + rng.below(4) as usize {
        let length = rng.below(0x100) + 1;
        lsda.call_sites.push(CallSite {
            start,
            length,
            landing_pad: if rng.chance(20) { 0 } else { rng.below(0x400) },
            action: (i < action_count).then_some(ActionId(i)),
        });
        start += length + rng.below(0x10);
    }
    lsda
}

#[test]
fn test_random_lsdas() {
    let mut rng = Rng(0x5555_aaaa_3333_cccc);
    let iterations = iterations("LSDA_FUZZ_ITERATIONS", 20_000);
    let mut written = 0;
    for _ in 0..iterations {
        let format = random_format(&mut rng);
        let endian = random_endian(&mut rng);
        let lsda = random_lsda(&mut rng, format);
        let prefix = rng.below(8) as usize;
        let bases = bases();
        let mut w = EndianVec::new(endian);
        w.write(&vec![0; prefix]).unwrap();
        // Some random addresses are not representable in their encoding.
        if lsda.write(&mut w, format, &bases).is_err() {
            continue;
        }
        written += 1;
        let data = w.into_vec();

        // It reads back as written.
        let table = GccExceptTable::new(&data, endian, format);
        let parsed = table.lsda_at(LsdaOffset(prefix)).unwrap();
        let tables = parsed
            .parse_tables()
            .unwrap_or_else(|e| panic!("{e}: {lsda:?}"));
        assert_eq!(tables.end, data.len(), "{lsda:?}");
        assert_eq!(tables.call_sites.len(), lsda.call_sites.len());
        assert_eq!(tables.actions.len(), lsda.actions.len());
        assert_eq!(tables.exception_specs.len(), lsda.exception_specs.len());
        assert!(tables.types.len() >= lsda.types.len());
        for (read, written) in tables.call_sites.iter().zip(&lsda.call_sites) {
            if format.unwinder != Unwinder::SjLj {
                assert_eq!((read.start, read.length), (written.start, written.length));
            }
            assert_eq!(read.landing_pad, written.landing_pad);
            assert_eq!(read.action.is_some(), written.action.is_some());
        }
        // The type table entries before the written ones are padding.
        let extra = tables.types.len() - lsda.types.len();
        for (read, written) in tables.types[..lsda.types.len()].iter().zip(&lsda.types) {
            let address = read.address(&bases).unwrap();
            match written {
                Some(Address::Constant(value)) => {
                    assert_eq!(address, value & mask(format));
                }
                _ => assert!(read.is_null()),
            }
        }
        assert!(
            tables.types[lsda.types.len()..]
                .iter()
                .all(lsda::read::Pointer::is_null)
        );
        assert!(extra * 2 < lsda.type_table_alignment as usize);

        // It converts back to an LSDA that writes the same bytes.
        let (converted, ids) =
            write::GccExceptTable::from_read(&table, &[LsdaOffset(prefix)], &bases).unwrap();
        let id = ids[&LsdaOffset(prefix)];
        assert!(
            matches!(converted.get(id).data, EntryData::Lsda(_)),
            "not converted: {format:?} {endian:?} prefix {prefix}: {lsda:?}
{data:02x?}"
        );
        let mut w = EndianVec::new(endian);
        converted.write(&mut w, &bases).unwrap();
        assert_eq!(w.slice(), data);
    }
    assert!(
        written > iterations / 4,
        "only {written} LSDAs were writable"
    );
}

fn mask(format: Format) -> u64 {
    if format.address_size == 8 {
        u64::MAX
    } else {
        (1 << (u32::from(format.address_size) * 8)) - 1
    }
}
