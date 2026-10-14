//! Differential test against the GNU C++ personality routine.
//!
//! `tests/personality/oracle.c` decodes LSDAs with libgcc's pointer decoding and
//! the LSDA logic of libstdc++'s personality routine (see
//! `tests/personality/mod.rs`). This test compares its decoding with the crate's
//! for the LSDAs of the fixtures, random LSDAs in every encoding, and
//! mutations of both that the crate accepts.
//!
//! The oracle is built by `tests/personality/build.sh`. The test runs the
//! commands in `LSDA_ORACLE64` and `LSDA_ORACLE32` (split at whitespace),
//! for 64- and 32-bit LSDAs, and is skipped without them. Set
//! `LSDA_ORACLE_ITERATIONS` to compare more random LSDAs.

use lsda::write::{EndianVec, Writer as _};
use lsda::{LittleEndian, RunTimeEndian};

mod elf;
mod personality;
mod random;
mod rng;
use personality::Case;
use random::{random_format, random_lsda};
use rng::{Rng, iterations};

/// The LSDAs of the little-endian fixtures.
fn fixture_cases(cases: &mut Vec<Case>) {
    let dir = format!("{}/tests/data", env!("CARGO_MANIFEST_DIR"));
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !matches!(path.extension().and_then(|e| e.to_str()), Some("o" | "so")) {
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let section = elf::load(&file).unwrap();
        if section.endian != RunTimeEndian::Little {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        for offset in section.offsets() {
            // The personality routine reads LLVM call-site ranges past their
            // end (see `Lsda::with_call_site_table_end`).
            let table = section.relocated_table();
            let (_, range) = elf::parse_lsda(&table, offset, section.next_offset(offset)).unwrap();
            if range {
                continue;
            }
            let label = format!("{name} LSDA at {:#x}", offset.0);
            let case = Case::new(label, section.relocated.clone(), offset.0, section.format);
            cases.push(case.unwrap_or_else(|| panic!("{name}: LSDA at {:#x} rejected", offset.0)));
        }
    }
}

/// Random LSDAs, and mutations of them and of the fixtures.
fn random_cases(cases: &mut Vec<Case>, rng: &mut Rng, iterations: u64) {
    let fixtures: Vec<_> = cases
        .iter()
        .map(|case| (case.data.clone(), case.offset, case.format))
        .collect();
    let mut accepted = 0;
    for i in 0..iterations {
        let (mut data, offset, format) = if i % 2 == 0 {
            let format = random_format(rng);
            let lsda = random_lsda(rng, format);
            let prefix = rng.below(8) as usize;
            let mut w = EndianVec::new(LittleEndian);
            w.write(&vec![0; prefix]).unwrap();
            if lsda.write(&mut w, format, &personality::bases()).is_err() {
                continue;
            }
            (w.into_vec(), prefix, format)
        } else {
            fixtures[rng.below(fixtures.len() as u64) as usize].clone()
        };
        // Mutate a third of them, near the LSDA.
        if rng.chance(33) {
            let window = (data.len() - offset).min(64) as u64;
            for _ in 0..=rng.below(2) {
                let index = offset + rng.below(window) as usize;
                data[index] = if rng.chance(50) {
                    rng.byte()
                } else {
                    data[index] ^ (1 << rng.below(8))
                };
            }
        }
        let label = format!("random case {i}");
        if let Some(case) = Case::new(label, data, offset, format) {
            accepted += 1;
            cases.push(case);
        }
    }
    assert!(accepted > iterations / 4, "only {accepted} cases accepted");
}

#[test]
fn test_oracle() {
    if personality::oracles().is_empty() {
        eprintln!("skipped: set LSDA_ORACLE64 and LSDA_ORACLE32 (see tests/personality/build.sh)");
        return;
    }
    let mut cases = Vec::new();
    fixture_cases(&mut cases);
    let fixtures = cases.len();
    let mut rng = Rng(0x0dd5_eed5_1234_5678);
    random_cases(
        &mut cases,
        &mut rng,
        iterations("LSDA_ORACLE_ITERATIONS", 20_000),
    );
    let (compared, failed) = personality::compare(&cases);
    eprintln!("compared {compared} LSDAs ({fixtures} from fixtures), {failed} differ");
    assert_eq!(failed, 0, "{failed} LSDAs differ");
}
