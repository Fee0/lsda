//! Comparison with the LSDA oracle (`oracle.c`), shared by the tests.
//!
//! The oracle decodes LSDAs with libgcc's pointer decoding and the LSDA
//! logic of libstdc++'s personality routine: it finds the call site for a
//! location and walks its actions, type table entries and exception
//! specifications. [`Case::new`] decodes an LSDA with the crate and prints
//! the results in the oracle's format.
//!
//! The oracles are built by `build.sh`, and run by the commands in
//! `LSDA_ORACLE64` and `LSDA_ORACLE32` (split at whitespace), for 64- and
//! 32-bit LSDAs.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::process::{Command, Stdio};

use lsda::read::{ActionOffset, Filter, GccExceptTable, Lsda, Reader, SpecEntry};
use lsda::{BaseAddresses, Format, LittleEndian, LsdaOffset, Unwinder};

/// The base addresses the oracle uses. Pc-relative values are relative to
/// the start of the data, and the function starts at 0.
pub fn bases() -> BaseAddresses {
    BaseAddresses::default()
        .set_section(0)
        .set_text(0x1000)
        .set_data(0x20_0000)
        .set_function(0)
}

/// The oracle commands that are set, with the address size of each.
pub fn oracles() -> Vec<(u8, String)> {
    [(8, "LSDA_ORACLE64"), (4, "LSDA_ORACLE32")]
        .into_iter()
        .filter_map(|(size, var)| Some((size, std::env::var(var).ok()?)))
        .collect()
}

/// A little-endian LSDA, and how the crate decodes it.
pub struct Case {
    pub label: String,
    pub format: Format,
    pub data: Vec<u8>,
    pub offset: usize,
    locations: Vec<u64>,
    expected: String,
}

impl Case {
    /// Describe the LSDA at `offset` in `data` as the oracle does, or return
    /// `None` if the crate rejects any part of it.
    pub fn new(label: String, data: Vec<u8>, offset: usize, format: Format) -> Option<Case> {
        let table = GccExceptTable::new(&data, LittleEndian, format);
        let lsda = table.lsda_at(LsdaOffset(offset)).ok()?;
        let tables = lsda.parse_tables().ok()?;
        let mask = if format.address_size == 8 {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        };

        let lpstart = match lsda.lpstart() {
            Some(pointer) => pointer.address(&bases()).ok()?,
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

/// Run the cases through the oracles that are set, report the differences,
/// and return the number of cases compared and the number that differ.
///
/// Set `LSDA_ORACLE_SHOW` to the number of differences to print (10 by
/// default), and `LSDA_ORACLE_KIND` to print only those whose kind (as
/// listed in the summary) contains it.
pub fn compare(cases: &[Case]) -> (usize, usize) {
    let mut compared = 0;
    let mut failures = Vec::new();
    for (address_size, command) in oracles() {
        let selected: Vec<&Case> = cases
            .iter()
            .filter(|case| case.format.address_size == address_size)
            .collect();
        if selected.is_empty() {
            continue;
        }
        let outputs = run_oracle(&command, &selected);
        for (case, output) in selected.into_iter().zip(outputs) {
            compared += 1;
            if output != case.expected {
                failures.push((case, output));
            }
        }
    }

    // Group the differences by format and by the first lines that differ.
    let mut kinds = BTreeMap::new();
    let mut failure_kinds = Vec::new();
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
        failure_kinds.push(kind);
    }
    for (kind, count) in &kinds {
        eprintln!("{count:6} {kind}");
    }

    let shown = std::env::var("LSDA_ORACLE_SHOW")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10);
    let filter = std::env::var("LSDA_ORACLE_KIND").unwrap_or_default();
    for ((case, output), _) in failures
        .iter()
        .zip(&failure_kinds)
        .filter(|(_, kind)| kind.contains(&filter))
        .take(shown)
    {
        let expected: Vec<&str> = case.expected.lines().collect();
        let actual: Vec<&str> = output.lines().collect();
        let first = (0..=expected.len())
            .find(|&i| expected.get(i) != actual.get(i))
            .unwrap_or(expected.len());
        let context = |lines: &[&str]| {
            let start = first.saturating_sub(4).min(lines.len());
            lines[start..(first + 3).min(lines.len())].join("\n")
        };
        let end = case.data.len().min(case.offset + 96);
        eprintln!(
            "--- {} ({:?}), bytes from the LSDA: {:02x?}\n{}\n--- crate (line {first}):\n{}\n--- oracle:\n{}",
            case.label,
            case.format,
            &case.data[case.offset..end],
            expected[0],
            context(&expected),
            context(&actual),
        );
    }
    (compared, failures.len())
}
