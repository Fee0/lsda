//! Checks the crate against a corpus of real ELF files.
//!
//! Set `LSDA_CORPUS` to a directory of ELF files, for example one created by
//! `scripts/fetch_corpus.py`. Without it, the test prints a notice and passes.
//! For every file with LSDAs (found through `.eh_frame`, or `.ARM.exidx` for
//! the Arm EHABI) it checks that:
//!
//! 1. every LSDA parses completely (`parse_tables`), ends before the next
//!    one, and finds each of its call sites by location;
//! 2. `GccExceptTable::from_read` followed by `write` reproduces the section
//!    byte for byte, and reports how many LSDAs it could not convert;
//! 3. if the oracles are set (see `tests/oracle.rs`), the crate decodes every
//!    little-endian LSDA as libstdc++'s personality routine does.
//!
//! Run it in release mode: `cargo test --release --test corpus -- --nocapture`.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use lsda::read::Filter;
use lsda::write::{EndianVec, EntryData, GccExceptTable};
use lsda::{LsdaOffset, RunTimeEndian, Unwinder};
use object::Object;

mod elf;
mod personality;

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[derive(Default)]
struct Stats {
    files: usize,
    lsdas: usize,
    /// LLVM call-site ranges, other than the last of each function.
    ranges: usize,
    call_sites: usize,
    actions: usize,
    types: usize,
    exception_specs: usize,
    converted: usize,
    identical: usize,
    /// LSDAs per machine.
    machines: BTreeMap<String, usize>,
    /// LSDAs per header encoding (`@LPStart`, `@TType`, call sites).
    encodings: BTreeMap<String, usize>,
    /// Filters per kind.
    filters: BTreeMap<&'static str, usize>,
}

fn count<K: Ord>(map: &mut BTreeMap<K, usize>, key: K) {
    *map.entry(key).or_default() += 1;
}

/// Check one file, returning a description of each failure.
fn check_file(
    name: &str,
    file: &object::File<'_>,
    stats: &mut Stats,
    cases: &mut Vec<personality::Case>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(s) = elf::load(file) else {
        return errors;
    };
    let offsets: BTreeSet<_> = s.offsets().into_iter().collect();
    if offsets.is_empty() {
        return errors;
    }
    stats.files += 1;
    let machine = format!("{:?}", file.architecture());

    let table = s.relocated_table();
    let bases = s.bases();
    let offsets: Vec<_> = offsets.into_iter().collect();
    let mut ranges = Vec::new();
    for (i, &offset) in offsets.iter().enumerate() {
        let context = format!("{name}: LSDA at {:#x}", offset.0);
        let next = offsets.get(i + 1).map_or(s.relocated.len(), |next| next.0);
        let (lsda, range) = match elf::parse_lsda(&table, offset, next) {
            Ok(lsda) => lsda,
            Err(e) => {
                errors.push(format!("{context}: {e}"));
                continue;
            }
        };
        if range {
            stats.ranges += 1;
            ranges.push(offset);
        }
        let tables = match lsda.parse_tables() {
            Ok(tables) => tables,
            Err(e) => {
                errors.push(format!("{context}: {e}"));
                continue;
            }
        };
        stats.lsdas += 1;
        count(&mut stats.machines, machine.clone());
        count(
            &mut stats.encodings,
            format!(
                "@LPStart {:02x}, @TType {:02x}, call sites {:02x}",
                lsda.lpstart_encoding().0,
                lsda.ttype_encoding().0,
                lsda.call_site_encoding().0
            ),
        );
        stats.call_sites += tables.call_sites.len();
        stats.actions += tables.actions.len();
        stats.types += tables.types.len();
        stats.exception_specs += tables.exception_specs.len();
        for action in &tables.actions {
            count(
                &mut stats.filters,
                match action.filter {
                    Filter::Cleanup => "cleanup",
                    Filter::Catch(index) if tables.types[index as usize - 1].is_null() => {
                        "catch (...)"
                    }
                    Filter::Catch(_) => "catch",
                    Filter::ExceptionSpec(_) => "exception specification",
                },
            );
        }

        // Call-site ranges share the tables after the last range.
        if tables.end > next && !range {
            errors.push(format!(
                "{context}: ends at {:#x}, after the next LSDA at {next:#x}",
                tables.end
            ));
        }
        for pointer in &tables.types {
            if let Err(e) = pointer.address(&bases) {
                errors.push(format!("{context}: type at {:#x}: {e}", pointer.offset()));
            }
        }
        if lsda.format().unwinder != Unwinder::SjLj {
            for call_site in tables.call_sites.iter().filter(|c| c.length != 0) {
                match lsda.find_call_site(call_site.start) {
                    Ok(Some(found)) if found == *call_site => {}
                    found => errors.push(format!(
                        "{context}: call site at {:#x} found as {found:?}",
                        call_site.offset
                    )),
                }
            }
        }

        // The personality routine reads a call-site range past its end.
        if s.endian == RunTimeEndian::Little && !range && !personality::oracles().is_empty() {
            // The LSDA's own bytes: pc-relative values are then relative to
            // its start, for the crate and the oracle alike.
            let data = s.relocated[offset.0..next].to_vec();
            match personality::Case::new(context.clone(), data, 0, s.format) {
                Some(case) => cases.push(case),
                None => errors.push(format!("{context}: rejected in isolation")),
            }
        }
    }

    errors.extend(check_roundtrip(name, &s, &offsets, &ranges, stats));
    errors
}

/// Check that the section converts and writes back identically.
fn check_roundtrip(
    name: &str,
    s: &elf::LsdaSection<'_>,
    offsets: &[LsdaOffset],
    ranges: &[LsdaOffset],
    stats: &mut Stats,
) -> Vec<String> {
    let mut errors = Vec::new();
    let table = s.relocated_table();
    let bases = s.bases();
    match GccExceptTable::from_read(&table, offsets, &bases) {
        Ok((converted, ids)) => {
            // The model has a single call-site table, so call-site ranges
            // other than the last of a function are kept raw.
            let raw: Vec<_> = ids
                .iter()
                .filter(|(offset, id)| {
                    matches!(converted.get(**id).data, EntryData::Raw(_))
                        && !ranges.contains(offset)
                })
                .map(|(offset, _)| format!("{:#x}", offset.0))
                .collect();
            stats.converted += ids
                .values()
                .filter(|id| matches!(converted.get(**id).data, EntryData::Lsda(_)))
                .count();
            if !raw.is_empty() {
                errors.push(format!(
                    "{name}: {} of {} LSDAs kept raw, at {}",
                    raw.len(),
                    ids.len(),
                    raw[..raw.len().min(5)].join(", ")
                ));
            }
            let mut w = EndianVec::new(s.endian);
            match converted.write(&mut w, &bases) {
                Ok(_) if w.slice() == s.relocated.as_slice() => stats.identical += 1,
                Ok(_) => errors.push(format!("{name}: written section differs")),
                Err(e) => errors.push(format!("{name}: write: {e}")),
            }
        }
        Err(e) => errors.push(format!("{name}: from_read: {e}")),
    }
    errors
}

#[test]
fn test_corpus() {
    let Ok(dir) = std::env::var("LSDA_CORPUS") else {
        eprintln!("skipped: set LSDA_CORPUS to a directory of ELF files (scripts/fetch_corpus.py)");
        return;
    };
    let mut paths = Vec::new();
    files(Path::new(&dir), &mut paths);
    paths.sort();

    let mut stats = Stats::default();
    let mut errors = Vec::new();
    let mut cases = Vec::new();
    for path in &paths {
        let name = path
            .strip_prefix(&dir)
            .unwrap_or(path)
            .display()
            .to_string();
        let data = std::fs::read(path).unwrap();
        let Ok(file) = object::File::parse(&*data) else {
            continue;
        };
        match catch_unwind(AssertUnwindSafe(|| {
            check_file(&name, &file, &mut stats, &mut cases)
        })) {
            Ok(file_errors) => errors.extend(file_errors),
            Err(_) => errors.push(format!("{name}: panicked")),
        }
    }

    eprintln!(
        "{} files with LSDAs: {} LSDAs ({} converted, {} call-site ranges), {} call sites, {} actions, {} types, {} exception specifications; {} sections written identically",
        stats.files,
        stats.lsdas,
        stats.converted,
        stats.ranges,
        stats.call_sites,
        stats.actions,
        stats.types,
        stats.exception_specs,
        stats.identical
    );
    for (machine, n) in &stats.machines {
        eprintln!("{n:8} LSDAs for {machine}");
    }
    for (encodings, n) in &stats.encodings {
        eprintln!("{n:8} LSDAs with {encodings}");
    }
    for (filter, n) in &stats.filters {
        eprintln!("{n:8} {filter} actions");
    }
    if !cases.is_empty() {
        let (compared, failed) = personality::compare(&cases);
        eprintln!("compared {compared} LSDAs with the oracle, {failed} differ");
        if failed != 0 {
            errors.push(format!("{failed} LSDAs differ from the oracle"));
        }
    }
    for error in errors.iter().take(50) {
        eprintln!("{error}");
    }
    assert!(errors.is_empty(), "{} errors", errors.len());
}
