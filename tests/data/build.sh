#!/bin/sh
# Rebuild the ELF fixtures from src/eh.cpp.
#
# Requires g++ with 32-bit multilib, and clang with ld.lld. The checked-in
# files were built with GCC 7.5 and clang 10, except the split functions,
# built with GCC 14.2 and clang 19.1 (Debian trixie).
set -e
cd "$(dirname "$0")"
GXX=${GXX:-g++}
CLANG=${CLANG:-clang++}
GXX_NEW=${GXX_NEW:-g++-14}
CLANG_NEW=${CLANG_NEW:-clang++-19}
FLAGS="-std=c++14 -O1 -fno-asynchronous-unwind-tables -Wno-deprecated"

# GCC: relocatable objects (non-PIC and PIC) and a shared library.
$GXX $FLAGS -fno-pic -c src/eh.cpp -o gcc-x86_64.o
$GXX $FLAGS -fPIC -c src/eh.cpp -o gcc-x86_64-pic.o
$GXX $FLAGS -m32 -fno-pic -c src/eh.cpp -o gcc-i386.o
$GXX $FLAGS -fPIC -shared -nostdlib src/eh.cpp -o gcc-x86_64.so

# clang: objects for several targets, a big-endian one, and shared libraries
# (including Arm EHABI, where the LSDAs are in .ARM.extab).
for target in x86_64-linux-gnu i686-linux-gnu aarch64-linux-gnu powerpc64-linux-gnu; do
    $CLANG --target=$target $FLAGS -c src/eh.cpp -o clang-${target%%-*}.o
done
for target in x86_64-linux-gnu armv7a-linux-gnueabihf; do
    $CLANG --target=$target $FLAGS -fPIC -shared -nostdlib -fuse-ld=lld \
        src/eh.cpp -o clang-${target%%-*}.so
done

# Split functions, with an LSDA for each part: GCC's hot/cold partitioning,
# and LLVM's call-site ranges for basic block sections (with an explicit
# @LPStart).
$GXX_NEW $FLAGS -O2 -freorder-blocks-and-partition -fPIC -shared -nostdlib \
    src/eh.cpp -o gcc14-x86_64-split.so
$CLANG_NEW $FLAGS -O2 -fbasic-block-sections=all -fPIC -shared -nostdlib \
    -fuse-ld=lld src/eh.cpp -o clang19-x86_64-bbsections.so
