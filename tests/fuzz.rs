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

use lsda::read::{ActionOffset, GccExceptTable, Pointer, Reader, SpecOffset};
use lsda::write::{self, Address, EndianVec, EntryData, Writer};
use lsda::{BaseAddresses, Format, LsdaOffset, RunTimeEndian, Unwinder};

mod random;
mod rng;
use random::{SECTION, random_endian, random_format, random_lsda};
use rng::{Rng, iterations};

fn bases() -> BaseAddresses {
    BaseAddresses::default()
        .set_section(SECTION)
        .set_text(0x1000)
        .set_data(0x20_0000)
        .set_function(0x2000)
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
        if let Some(action) = call_site.action {
            let mut actions = lsda.actions(action);
            while let Ok(Some(_)) = actions.next() {}
        }
    }
    let _ = lsda.find_call_site(rng.below(0x200));
    let mut actions = lsda.actions(ActionOffset(rng.below(64) as usize));
    while let Ok(Some(_)) = actions.next() {}
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
        let offsets = section.offsets().iter().map(|o| o.0).collect();
        fixtures.push((section.relocated, offsets, section.format, section.endian));
    }
    assert_ne!(fixtures.len(), 0, "no fixtures");
    fixtures
}

mod elf;

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
        for (read, written) in tables.call_sites.iter().zip(&lsda.call_sites) {
            if format.unwinder != Unwinder::SjLj {
                assert_eq!((read.start, read.length), (written.start, written.length));
            }
            assert_eq!(read.landing_pad, written.landing_pad);
            assert_eq!(read.action.is_some(), written.action.is_some());
        }
        // The referenced types read back as written. Entries beyond the
        // written ones (read only for the Arm EHABI) are alignment padding.
        let compared = tables.types.len().min(lsda.types.len());
        for (read, written) in tables.types.iter().zip(&lsda.types) {
            let address = read.address(&bases).unwrap();
            match written {
                Some(Address::Constant(value)) => assert_eq!(address, *value),
                _ => assert!(read.is_null()),
            }
        }
        assert!(tables.types[compared..].iter().all(Pointer::is_null));

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
