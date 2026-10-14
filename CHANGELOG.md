# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-14

Initial release.

### Added

- Reading of LSDAs (`.gcc_except_table`, and the LSDA of `.ARM.extab`
  entries) as produced by GCC and LLVM and consumed by libstdc++ and
  libc++abi: the header, call-site table, action table, type table and
  exception specification table.
- The DWARF, Arm EHABI and SJLJ / WebAssembly variants, every `DW_EH_PE_*`
  pointer encoding, 16-, 32- and 64-bit addresses, and both byte orders.
- Call-site lookup (`Lsda::find_call_site`), action chains with cycle
  detection, and `Lsda::parse_tables`, which decodes every table and infers
  the extent of the LSDA.
- Reading of relocatable objects through `RelocateReader` and `Relocate`.
- Writing through `GccExceptTable` and `Lsda`, with computed offsets,
  alignment padding and `@TType` base offset, and `Absolute`, `Relative` and
  `Target2` relocations recorded by `RelocateWriter`.
- Lossless conversion of parsed sections with `GccExceptTable::from_read`,
  including the unreferenced action records, type table entries and exception
  specifications that producers leave, and padded LEB128 call-site values
  (RISC-V).
- LLVM call-site ranges (`-fbasic-block-sections`), with
  `Lsda::with_call_site_table_end`.
- `no_std` support (requires `alloc`) and an optional `fallible-iterator`
  feature.
- The `lsdadump` example, which dumps the LSDAs of an ELF file.
- A differential test against libgcc's and libstdc++'s decoding, and a test
  against a corpus of Debian binaries for eight architectures.

[Unreleased]: https://github.com/Fee0/lsda/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Fee0/lsda/releases/tag/v0.1.0
