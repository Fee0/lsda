#!/usr/bin/env python3
"""Download a corpus of real ELF files for the corpus test.

Fetches a fixed set of Debian packages, mostly C++ libraries, for every
Debian architecture (x86-64, i386, AArch64, Arm EHABI hard- and soft-float,
little-endian PowerPC64, big-endian s390x and RISC-V), and extracts every
ELF file they contain into OUT/<arch>/<package>/.

Usage:
    python scripts/fetch_corpus.py OUT [--suite stable] [--arch amd64 ...]

Then run:
    LSDA_CORPUS=OUT cargo test --release --test corpus -- --nocapture
"""

import argparse
import io
import lzma
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

MIRROR = "https://deb.debian.org/debian"
ARCHES = ["amd64", "i386", "arm64", "armhf", "armel", "ppc64el", "s390x", "riscv64"]

# Regular expressions matched against package names. When several packages
# match (versioned library names), the last in sorted order is used.
PACKAGES = [
    # Built by GCC.
    r"libstdc\+\+6",
    r"libgcc-s1",
    r"libc6",
    r"libicu\d+",
    r"libqt6core6(t64)?",
    r"libboost-filesystem\d[\d.]*",
    r"libboost-regex\d[\d.]*",
    r"libboost-program-options\d[\d.]*",
    r"libprotobuf\d+(t64)?",
    r"libz3-4",
    r"libapt-pkg\d[\d.]*",
    r"libyaml-cpp\d[\d.]*",
    r"libtbb\d+",
    r"libxerces-c3[\d.]*",
    r"libpoppler\d+",
    # Built by clang.
    r"libc\+\+1-\d+",
    r"libc\+\+abi1-\d+",
]


def fetch(url):
    with urllib.request.urlopen(url) as response:
        return response.read()


def package_index(suite, arch):
    data = lzma.decompress(fetch(f"{MIRROR}/dists/{suite}/main/binary-{arch}/Packages.xz"))
    packages = {}
    for stanza in data.decode("utf-8", "replace").split("\n\n"):
        fields = dict(
            line.split(": ", 1) for line in stanza.splitlines() if ": " in line and not line.startswith(" ")
        )
        if "Package" in fields and "Filename" in fields:
            packages[fields["Package"]] = fields["Filename"]
    return packages


def ar_members(data):
    """Yield (name, bytes) for each member of an ar archive (.deb)."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        offset += 60
        yield name, data[offset : offset + size]
        offset += size + (size & 1)


def extract_elf_files(deb, out_dir):
    count = 0
    for name, member in ar_members(deb):
        if not name.startswith("data.tar"):
            continue
        with tarfile.open(fileobj=io.BytesIO(member), mode="r:*") as tar:
            for info in tar:
                if not info.isfile():
                    continue
                content = tar.extractfile(info).read()
                if not content.startswith(b"\x7fELF"):
                    continue
                target = out_dir / info.name.lstrip("./").replace("/", "_")
                target.write_bytes(content)
                count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--suite", default="stable")
    parser.add_argument("--arch", action="append", choices=ARCHES, help="only these architectures")
    args = parser.parse_args()

    for arch in args.arch or ARCHES:
        print(f"{arch}: reading package index", flush=True)
        index = package_index(args.suite, arch)
        for pattern in PACKAGES:
            matches = sorted(name for name in index if re.fullmatch(pattern, name))
            if not matches:
                print(f"  {pattern}: no match, skipped", file=sys.stderr)
                continue
            package = matches[-1]
            out_dir = args.out / arch / package
            if out_dir.exists() and any(out_dir.iterdir()):
                print(f"  {package}: already present")
                continue
            out_dir.mkdir(parents=True, exist_ok=True)
            deb = fetch(f"{MIRROR}/{index[package]}")
            count = extract_elf_files(deb, out_dir)
            print(f"  {package}: {count} ELF files ({len(deb) // 1024} KiB)", flush=True)


if __name__ == "__main__":
    main()
