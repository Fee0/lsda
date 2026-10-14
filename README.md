# lsda

[![Crates.io](https://img.shields.io/crates/v/lsda.svg)](https://crates.io/crates/lsda)
[![Docs.rs](https://docs.rs/lsda/badge.svg)](https://docs.rs/lsda)
[![CI](https://github.com/Fee0/lsda/actions/workflows/ci.yml/badge.svg)](https://github.com/Fee0/lsda/actions/workflows/ci.yml)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-blue.svg)](#installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust library for reading and writing the language-specific data area
(LSDA) of GCC-compatible exception handling: the `.gcc_except_table`
section used by C++ (`__gxx_personality_v0`), and the LSDA at the end of
generic-model `.ARM.extab` entries.

- **Read and write.** Parse LSDAs from section data, or build them in memory
  and encode them.
- **Lossless.** Converting the LSDAs of a section and writing them back
  reproduces it byte for byte, including alignment padding and padded
  `@TType` offsets (see [Limitations](#limitations)).
- **Every variant.** The DWARF unwinder, the Arm EHABI (word-sized
  exception specifications) and SJLJ / WebAssembly (index-based call sites);
  every `DW_EH_PE_*` pointer encoding; 16-, 32- and 64-bit addresses; little
  and big endian.
- **Relocation-aware.** Read relocatable objects through a `Relocate` hook,
  and record relocations for symbol addresses when writing.
- **Portable.** `no_std` (requires `alloc`), zero-copy reading, no required
  dependencies.

## Specification

The LSDA has no standalone specification. Its format is defined by the
producers and consumers below, which agree on it; this crate follows them.

| | |
|---|---|
| Producer | GCC [`gcc/except.cc`](https://github.com/gcc-mirror/gcc/blob/master/gcc/except.cc) (`output_one_function_exception_table`) |
| Consumer | libstdc++ [`libsupc++/eh_personality.cc`](https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/eh_personality.cc), libgcc [`unwind-pe.h`](https://github.com/gcc-mirror/gcc/blob/master/libgcc/unwind-pe.h) |
| Also | LLVM [`EHStreamer.cpp`](https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/EHStreamer.cpp), libc++abi [`cxa_personality.cpp`](https://github.com/llvm/llvm-project/blob/main/libcxxabi/src/cxa_personality.cpp) |
| Pointer encodings | Linux Standard Base Core Specification 5.0, "Exception Frames" (`DW_EH_PE_*`) |

An LSDA is laid out as follows:

```text
@LPStart encoding  u8          DW_EH_PE_omit: landing pads are relative to the function
@LPStart           encoded     only if the encoding is not omit
@TType encoding    u8          DW_EH_PE_omit: no type table
@TType base offset uleb128     only if the encoding is not omit; from the end of this field
call-site encoding u8
call-site length   uleb128
call-site table    start, length, landing pad (encoded), action (uleb128) per entry
action table       filter (sleb128), next displacement (sleb128) per record
padding            to align the type table
type table         entries in @TType encoding; entry N is at base - N * size
--- @TType base ---
exception specs    uleb128 type indices, 0-terminated (Arm EHABI: TARGET2 words)
```

## Coverage

| Area | Supported |
|---|---|
| Header | `@LPStart` in any encoding, `@TType` encoding and base offset, call-site encoding |
| Call sites | DWARF and Arm EHABI (start, length, landing pad, action), SJLJ / Wasm (landing pad, action); lookup of the call site for a location, as the personality routine does |
| Actions | Cleanups, catches and exception specifications; chains, with cycle detection |
| Type table | Every fixed-size `DW_EH_PE_*` encoding, with `pcrel`, `textrel`, `datarel`, `funcrel`, `aligned` and `indirect`; null entries (`catch (...)`) |
| Exception specifications | ULEB128 type index lists; Arm EHABI `R_ARM_TARGET2` word lists |
| Extent | The extent of the action, type and exception specification tables, which is not recorded, inferred as GCC and LLVM emit them |

## Installation

```toml
[dependencies]
lsda = "0.1"
```

Minimum supported Rust version: **1.88** (edition 2024).

### Cargo features

| Feature | Default | Description |
|---|:---:|---|
| `read` | ✓ | The `read` module |
| `write` | ✓ | The `write` module |
| `fallible-iterator` | | Implements `fallible_iterator::FallibleIterator` for all iterators |

## Usage

### Reading

LSDAs are not self-delimiting, so they are reached by offset: from the `L`
augmentation of an FDE in `.eh_frame` (for example with
[`gimli`](https://crates.io/crates/gimli)), or from an `.ARM.extab` entry
(for example with [`ehabi`](https://crates.io/crates/ehabi)).

```rust
use lsda::read::{Filter, GccExceptTable};
use lsda::{BaseAddresses, Format, LittleEndian, LsdaOffset};

let table = GccExceptTable::new(section_data, LittleEndian, Format::new(8));
let bases = BaseAddresses::default().set_section(section_address);
let lsda = table.lsda_at(LsdaOffset(lsda_offset))?;

// The call site that covers an offset in the function.
if let Some(call_site) = lsda.find_call_site(pc - function_start)? {
    println!("landing pad +{:#x}", call_site.landing_pad);
    if let Some(first) = call_site.action {
        let mut actions = lsda.actions(first)?;
        while let Some(action) = actions.next()? {
            match action.filter {
                Filter::Cleanup => println!("cleanup"),
                Filter::Catch(index) => {
                    let type_info = lsda.type_entry(index)?;
                    println!("catch {:#x}", type_info.address(&bases)?);
                }
                Filter::ExceptionSpec(offset) => {
                    let mut types = lsda.exception_spec(offset)?;
                    while let Some(entry) = types.next()? {
                        println!("may throw {entry:?}");
                    }
                }
            }
        }
    }
}

// Or decode every table at once.
let tables = lsda.parse_tables()?;
println!("{} call sites, ends at {:#x}", tables.call_sites.len(), tables.end);
```

Encoded pointers are returned as `Pointer` values, which record their
encoding and section offset and resolve against `BaseAddresses`. Use
`Format::arm_ehabi()` for `.ARM.extab`, and
`Format::new(n).with_unwinder(Unwinder::SjLj)` for SJLJ tables.

### Relocatable objects

In a relocatable object the type table entries are the targets of
relocations (such as `R_X86_64_PC32` against `DW.ref._ZTIi`). Wrap the
section data in a `RelocateReader` with an implementation of `Relocate`,
which maps each relocated field to its value under a layout of your choice.

### Writing

```rust
use lsda::write::{Action, Address, CallSite, EndianVec, Filter, GccExceptTable, Lsda};
use lsda::{BaseAddresses, Encoding, Format, LittleEndian};

// try { g(); } catch (int) { ... }
let mut lsda = Lsda::new();
lsda.ttype_encoding = Encoding::INDIRECT_PCREL_SDATA4;
let int = lsda.add_type(Some(Address::Constant(dw_ref_ztii)));
let catch_int = lsda.add_action(Action { filter: Filter::Catch(int), next: None });
lsda.call_sites.push(CallSite {
    start: 0x10,
    length: 0x08,
    landing_pad: 0x40,
    action: Some(catch_int),
});

let mut table = GccExceptTable::new(Format::new(8));
let id = table.add_lsda(lsda);

let mut section = EndianVec::new(LittleEndian);
let bases = BaseAddresses::default().set_section(section_address);
let offsets = table.write(&mut section, &bases)?;
println!("LSDA at {:#x}", offsets.get(id).0);
```

The writer computes every offset: action displacements, call-site action
indices, exception specification filters, the type table alignment padding
and the `@TType` base offset (padding the ULEB128 when the layout requires
it, as assemblers do). `Lsda::write` writes a single LSDA, for example after
the unwinding instructions of an `.ARM.extab` entry.

For relocatable output, implement `RelocateWriter` and use
`Address::Symbol`: absolute and pc-relative pointers become `Absolute` and
`Relative` relocations, and Arm EHABI type references `Target2`. The addend
is also stored in the field, as REL relocations require.

`GccExceptTable::from_read` converts a parsed section, given the offsets of
its LSDAs, for modification and rewriting.

### Dumping an ELF file

```sh
cargo run --example lsdadump -- path/to/file.o
```

Finds every LSDA through `.eh_frame` (or `.ARM.exidx`) and prints its
header, call sites, actions, type table (with symbol names where the
relocations of an object file allow) and exception specifications.

## Limitations

- **Offsets come from elsewhere.** The crate does not parse `.eh_frame` or
  `.ARM.extab`; the caller provides the offset of each LSDA.
- **Inferred extent.** The lengths of the action, type and exception
  specification tables are not recorded. `parse_tables` reads the action
  records reachable from the call sites and the exception specifications they
  reference, and takes the type table to fill the space between the action
  table and the type table base. Data that no call site refers to, which
  GCC and LLVM never emit, is not decoded.
- **Round-trip conditions.** `from_read` converts an LSDA only if writing it
  reproduces its bytes exactly, and keeps it as raw bytes otherwise: for
  example with a non-minimal LEB128 value outside the `@TType` base offset,
  or an action table with unreferenced trailing records. Gaps between LSDAs
  that are not zero alignment padding are kept as raw bytes too.
- **Relocated values.** Through a `RelocateReader`, `from_read` compares
  against the stored (unrelocated) bytes, so LSDAs with relocated fields are
  kept raw. Apply the relocations to a copy of the section first to convert
  them.
- **Call-site values are offsets.** Call-site encodings must have the
  `DW_EH_PE_absptr` application, as every producer emits; libgcc rejects
  the others too.
- **`R_ARM_TARGET2` values are raw.** Their interpretation is
  platform-specific (absolute, GOT-relative or place-relative).

## Testing

```sh
cargo test
```

The integration tests use objects and shared libraries built by GCC 7.5 and
clang 10 from `tests/data/src/eh.cpp` (rebuild with `tests/data/build.sh`):
cleanups, single and multiple handlers, nested `try` blocks, dynamic
exception specifications, `throw()`, `noexcept`, rethrow, and a function with
enough handlers for multi-byte LEB128 values. The targets are x86-64, i386,
AArch64, big-endian PowerPC64 and Arm EHABI. They verify:

- every LSDA parses identically through the relocation layer and from the
  relocated section, and LSDAs do not overlap;
- every call site is found by `find_call_site`;
- each function decodes to what its source says, with `type_info` symbols
  named through the relocations of the object files;
- a byte-identical `from_read` → write round trip of every section, with
  every LSDA converted.

`tests/fuzz.rs` checks robustness and consistency. Random sections and
mutations of the fixtures, in both byte orders and with every unwinder
variant and address size, go through every read path; every call must return
`Ok` or `Err`, and whenever `from_read` succeeds, writing must reproduce the
section exactly. Random LSDAs in every encoding must read back as written and
convert back to the same bytes. It runs 20,000 iterations per test by
default; set `LSDA_FUZZ_ITERATIONS` for longer runs (preferably in debug
mode, where integer overflow panics).

## License

Licensed under the [MIT License](LICENSE).
