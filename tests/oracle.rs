//! Differential test against the GNU C++ personality routine.
//!
//! `tests/oracle/oracle.c` decodes LSDAs with libgcc's pointer decoding and
//! the LSDA logic of libstdc++'s personality routine: it finds the call site
//! for a location and walks its actions, type table entries and exception
//! specifications. This test decodes the same LSDAs with the crate, prints
//! the results in the same format, and compares. The LSDAs are those of the
//! fixtures, random LSDAs in every encoding, and mutations of both that the
//! crate accepts.
//!
//! The oracle is built by `tests/oracle/build.sh`. The test runs the
//! commands in `LSDA_ORACLE64` and `LSDA_ORACLE32` (split at whitespace),
//! for 64- and 32-bit LSDAs, and is skipped without them. Set
//! `LSDA_ORACLE_ITERATIONS` to compare more random LSDAs.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

use lsda::read::{ActionOffset, Filter, GccExceptTable, Lsda, Reader, SpecEntry};
use lsda::write::{EndianVec, Writer as _};
use lsda::{BaseAddresses, Format, LittleEndian, LsdaOffset, RunTimeEndian, Unwinder};

mod elf;
mod random;
mod rng;
use random::{random_format, random_lsda};
use rng::{Rng, iterations};

/// The base addresses the oracle uses. Pc-relative values are relative to
/// the section, and the function starts at 0.
fn bases() -> BaseAddresses {
    BaseAddresses::default()
        .set_section(0)
        .set_text(0x1000)
        .set_data(0x20_0000)
        .set_function(0)
}

struct Case {
    label: String,
    format: Format,
    data: Vec<u8>,
    offset: usize,
    locations: Vec<u64>,
    expected: String,
}

impl Case {
    /// Describe the LSDA at `offset` as the oracle does, or return `None` if
    /// the crate rejects any part of it.
    fn new(label: String, data: Vec<u8>, offset: usize, format: Format) -> Option<Case> {
        let table = GccExceptTable::new(&data, LittleEndian, format);
        let lsda = table.lsda_at(LsdaOffset(offset)).ok()?;
        let tables = lsda.parse_tables().ok()?;
        let bases = bases();
        let mask = if format.address_size == 8 {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        };
        let lpstart = match lsda.lpstart() {
            Some(pointer) => pointer.address(&bases).ok()?,
            None => 0,
        };
        let mut out = String::new();
        let ttype_base = lsda
            .ttype_base()
            .map_or("-".to_string(), |base| format!("{base:x}"));
        let action_table = lsda.action_table_offset();
        writeln!(
            out,
            "hdr {lpstart:x} {:02x} {ttype_base} {:02x} {action_table:x}",
            lsda.ttype_encoding().0,
            lsda.call_site_encoding().0,
        )
        .unwrap();

        // Locations on either side of each call-site boundary.
        let mut locations = vec![0];
        if format.unwinder == Unwinder::SjLj {
            locations = (1..=tables.call_sites.len() as u64).collect();
        } else {
            for call_site in &tables.call_sites {
                let start = call_site.start;
                let end = start.wrapping_add(call_site.length);
                for location in [start.wrapping_sub(1), start, end.wrapping_sub(1), end] {
                    if location <= mask && !locations.contains(&location) {
                        locations.push(location);
                    }
                }
            }
            locations.truncate(64);
        }

        for &location in &locations {
            write!(out, "loc {location:x} ").unwrap();
            let Some(call_site) = lsda.find_call_site(location).ok()? else {
                writeln!(out, "-").unwrap();
                continue;
            };
            let landing_pad = if format.unwinder == Unwinder::SjLj || call_site.landing_pad == 0 {
                call_site.landing_pad
            } else {
                lpstart.wrapping_add(call_site.landing_pad) & mask
            };
            write!(out, "{landing_pad:x} ").unwrap();
            let Some(first) = call_site.action else {
                writeln!(out, "-").unwrap();
                continue;
            };
            writeln!(out, "{:x}", action_table + first.0).unwrap();

            describe_actions(&lsda, first, mask, &mut out)?;
        }
        Some(Case {
            label,
            format,
            data,
            offset,
            locations,
            expected: out,
        })
    }

    fn encode(&self, input: &mut Vec<u8>) {
        input.push(match self.format.unwinder {
            Unwinder::Dwarf => 0,
            Unwinder::ArmEhabi => 1,
            Unwinder::SjLj => 2,
        });
        input.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        input.extend_from_slice(&self.data);
        input.extend_from_slice(&(self.offset as u32).to_le_bytes());
        input.extend_from_slice(&(self.locations.len() as u32).to_le_bytes());
        for location in &self.locations {
            input.extend_from_slice(&location.to_le_bytes());
        }
    }
}

/// Describe the chain of actions starting at `first`, or return `None` if
/// the crate rejects any part of it.
fn describe_actions<R: Reader>(
    lsda: &Lsda<R>,
    first: ActionOffset,
    mask: u64,
    out: &mut String,
) -> Option<()> {
    let bases = bases();
    let arm = lsda.format().unwinder == Unwinder::ArmEhabi;
    let action_table = lsda.action_table_offset();
    let mut actions = lsda.actions(first);
    while let Some(action) = actions.next().ok()? {
        let next = action.next.map_or("-".to_string(), |next| {
            format!("{:x}", action_table + next.0)
        });
        writeln!(
            out,
            "rec {:x} {} {next}",
            action_table + action.offset.0,
            action.filter.value()
        )
        .unwrap();
        match action.filter {
            Filter::Cleanup => {}
            Filter::Catch(index) => {
                let entry = lsda.type_entry(index).ok()?;
                let value = if arm {
                    entry.value() & mask
                } else {
                    entry.address(&bases).ok()?
                };
                writeln!(out, "type {value:x}").unwrap();
            }
            Filter::ExceptionSpec(offset) => {
                let mut entries = lsda.exception_spec(offset).ok()?;
                while let Some(entry) = entries.next().ok()? {
                    match entry {
                        SpecEntry::Type(index) => {
                            let entry = lsda.type_entry(index).ok()?;
                            let value = entry.address(&bases).ok()?;
                            writeln!(out, "spec {index:x} {value:x}").unwrap();
                        }
                        SpecEntry::TypeInfo(pointer) => {
                            writeln!(out, "word {:x}", pointer.value()).unwrap();
                        }
                    }
                }
            }
        }
    }
    Some(())
}

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
        let (data, offset, format) = if i % 2 == 0 {
            let format = random_format(rng);
            let lsda = random_lsda(rng, format);
            let prefix = rng.below(8) as usize;
            let mut w = EndianVec::new(LittleEndian);
            w.write(&vec![0; prefix]).unwrap();
            if lsda.write(&mut w, format, &bases()).is_err() {
                continue;
            }
            (w.into_vec(), prefix, format)
        } else {
            fixtures[rng.below(fixtures.len() as u64) as usize].clone()
        };
        let mut data = data;
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

/// Run the oracle on the cases and return the output for each.
fn run_oracle(command: &str, cases: &[&Case]) -> Vec<String> {
    let mut input = Vec::new();
    for case in cases {
        case.encode(&mut input);
    }
    let mut parts = command.split_whitespace();
    let mut child = Command::new(parts.next().expect("empty oracle command"))
        .args(parts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run `{command}`: {e}"));
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    writer.join().unwrap().unwrap();
    assert!(child.wait().unwrap().success(), "`{command}` failed");
    let outputs: Vec<String> = output
        .split_inclusive("end\n")
        .map(|case| case.strip_suffix("end\n").unwrap_or(case).to_string())
        .collect();
    assert_eq!(outputs.len(), cases.len(), "oracle output is incomplete");
    outputs
}

#[test]
fn test_oracle() {
    let oracles = [
        (8, std::env::var("LSDA_ORACLE64").ok()),
        (4, std::env::var("LSDA_ORACLE32").ok()),
    ];
    if oracles.iter().all(|(_, command)| command.is_none()) {
        eprintln!("skipped: set LSDA_ORACLE64 and LSDA_ORACLE32 (see tests/oracle/build.sh)");
        return;
    }

    let mut cases = Vec::new();
    fixture_cases(&mut cases);
    let fixtures = cases.len();
    let mut rng = Rng(0x0dd5_eed5_1234_5678);
    let iterations = iterations("LSDA_ORACLE_ITERATIONS", 20_000);
    random_cases(&mut cases, &mut rng, iterations);

    let mut compared = 0;
    let mut failures = Vec::new();
    for (address_size, command) in oracles {
        let Some(command) = command else {
            eprintln!("skipped {address_size}-byte addresses: no oracle");
            continue;
        };
        let selected: Vec<&Case> = cases
            .iter()
            .filter(|case| case.format.address_size == address_size)
            .collect();
        let outputs = run_oracle(&command, &selected);
        for (case, output) in selected.into_iter().zip(outputs) {
            compared += 1;
            if output != case.expected {
                failures.push((case, output));
            }
        }
    }
    eprintln!(
        "compared {compared} LSDAs ({fixtures} from fixtures), {} differ",
        failures.len()
    );
    // Group the differences by format and by the first lines that differ.
    let mut kinds = std::collections::BTreeMap::new();
    let mut shown_kinds = Vec::new();
    for (case, output) in &failures {
        let (expected, actual) = case
            .expected
            .lines()
            .zip(output.lines().chain(std::iter::repeat("<missing>")))
            .find(|(a, b)| a != b)
            .unwrap_or(("<missing>", "<extra>"));
        let tag = |line: &str| line.split(' ').next().unwrap_or("").to_string();
        let kind = format!("{:?}: {} / {}", case.format, tag(expected), tag(actual));
        *kinds.entry(kind.clone()).or_insert(0) += 1;
        shown_kinds.push(kind);
    }
    for (kind, count) in &kinds {
        eprintln!("{count:6} {kind}");
    }
    let shown = rng::iterations("LSDA_ORACLE_SHOW", 10) as usize;
    let filter = std::env::var("LSDA_ORACLE_KIND").unwrap_or_default();
    for ((case, output), _) in failures
        .iter()
        .zip(&shown_kinds)
        .filter(|(_, kind)| kind.contains(&filter))
        .take(shown)
    {
        let end = case.data.len().min(case.offset + 96);
        let expected: Vec<&str> = case.expected.lines().collect();
        let actual: Vec<&str> = output.lines().collect();
        let first = (0..=expected.len())
            .find(|&i| expected.get(i) != actual.get(i))
            .unwrap_or(expected.len());
        let context = |lines: &[&str]| {
            lines[first.saturating_sub(4).min(lines.len())..(first + 3).min(lines.len())].join(
                "
",
            )
        };
        eprintln!(
            "--- {} ({:?}), bytes from the LSDA: {:02x?}
{}
--- crate (line {first}):
{}
--- oracle:
{}",
            case.label,
            case.format,
            &case.data[case.offset..end],
            expected[0],
            context(&expected),
            context(&actual),
        );
    }
    assert!(failures.is_empty(), "{} LSDAs differ", failures.len());
}
