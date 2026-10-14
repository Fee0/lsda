//! Dump the LSDAs of an ELF file.
//!
//! Usage: `cargo run --example lsdadump -- <file>`
//!
//! The LSDAs are found through the FDEs in `.eh_frame`, or through
//! `.ARM.exidx` for Arm files. Relocatable objects are shown with a synthetic
//! layout in which each section has its own address.

use std::{env, fs, process};

use lsda::read::{Filter, Lsda, Reader, SpecEntry};

#[path = "../tests/elf/mod.rs"]
mod elf;

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("Usage: lsdadump <file>");
        process::exit(2);
    };
    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        process::exit(1);
    });
    let file = object::File::parse(&*data).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        process::exit(1);
    });
    let Some(section) = elf::load(&file) else {
        eprintln!("{path}: no LSDA section");
        process::exit(1);
    };
    if let Err(e) = dump(&section) {
        eprintln!("{path}: {e}");
        process::exit(1);
    }
}

fn dump(s: &elf::LsdaSection<'_>) -> lsda::read::Result<()> {
    println!(
        "{} at 0x{:x}, {} bytes, {} LSDAs{}",
        s.name,
        s.address,
        s.data.len(),
        s.lsdas.len(),
        if s.relocatable {
            " (synthetic layout)"
        } else {
            ""
        },
    );
    let table = s.table();
    let bases = s.bases();
    for function in &s.lsdas {
        println!();
        println!(
            "[0x{:04x}] function {}",
            function.offset.0,
            s.describe(function.function)
        );
        let (lsda, range) =
            elf::parse_lsda(&table, function.offset, s.next_offset(function.offset))?;
        if range {
            println!("  a call-site range: the call-site table ends at the next LSDA");
        }
        dump_lsda(s, &lsda, &bases)?;
    }
    Ok(())
}

fn dump_lsda<R: Reader>(
    s: &elf::LsdaSection<'_>,
    lsda: &Lsda<R>,
    bases: &lsda::BaseAddresses,
) -> lsda::read::Result<()> {
    match lsda.lpstart() {
        Some(lpstart) => println!(
            "  @LPStart {} 0x{:x}",
            lpstart.encoding(),
            lpstart.address(bases)?
        ),
        None => println!("  @LPStart omitted"),
    }
    match lsda.ttype_base() {
        Some(base) => println!("  @TType {} base 0x{base:x}", lsda.ttype_encoding()),
        None => println!("  @TType omitted"),
    }
    println!("  call sites {}", lsda.call_site_encoding());

    let tables = lsda.parse_tables()?;
    for call_site in &tables.call_sites {
        print!(
            "    [0x{:x}, 0x{:x}) landing pad ",
            call_site.start,
            call_site.start + call_site.length
        );
        if call_site.landing_pad == 0 {
            print!("none");
        } else {
            print!("+0x{:x}", call_site.landing_pad);
        }
        match call_site.action {
            Some(action) => println!(", action 0x{:x}", action.0),
            None => println!(", cleanup only"),
        }
    }
    println!("  actions (ends at 0x{:x})", tables.action_table_end);
    for action in &tables.actions {
        let filter = match action.filter {
            Filter::Cleanup => "cleanup".to_string(),
            Filter::Catch(index) => format!("catch type {index}"),
            Filter::ExceptionSpec(offset) => format!("exception spec {}", offset.0),
        };
        match action.next {
            Some(next) => println!("    0x{:x}: {filter}, next 0x{:x}", action.offset.0, next.0),
            None => println!("    0x{:x}: {filter}", action.offset.0),
        }
    }
    if !tables.types.is_empty() {
        println!("  types");
    }
    for (index, pointer) in tables.types.iter().enumerate() {
        if pointer.is_null() {
            println!("    {}: catch (...)", index + 1);
            continue;
        }
        let address = pointer.address(bases)?;
        let name = s
            .type_name(address, pointer.is_indirect())
            .map(|name| format!(" ({name})"))
            .unwrap_or_default();
        let indirect = if pointer.is_indirect() { "*" } else { "" };
        println!("    {}: {indirect}0x{address:x}{name}", index + 1);
    }
    for spec in &tables.exception_specs {
        let entries: Vec<String> = spec
            .entries
            .iter()
            .map(|entry| match entry {
                SpecEntry::Type(index) => format!("type {index}"),
                SpecEntry::TypeInfo(pointer) => format!("0x{:x}", pointer.value()),
            })
            .collect();
        println!(
            "  exception spec {}: throw({})",
            spec.offset.0,
            entries.join(", ")
        );
    }
    println!("  ends at 0x{:x}", tables.end);
    Ok(())
}
