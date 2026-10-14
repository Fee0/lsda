#!/bin/sh
# Builds the LSDA oracle (oracle.c) for 64- and 32-bit addresses.
#
#   tests/personality/build.sh [output directory]
#
# Requires curl and a C compiler that can target both widths (on Debian and
# Ubuntu, gcc-multilib), or set ORACLE_WIDTHS to the widths to build. Static
# binaries also run under WSL; set ORACLE_LDFLAGS=-static for them. Then run
# the comparison with
#
#   LSDA_ORACLE64=<dir>/oracle64 LSDA_ORACLE32=<dir>/oracle32 cargo test --test oracle
set -eu

GCC_TAG=releases/gcc-14.2.0
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/../../target/oracle}
mkdir -p "$out"

curl -sSfL -o "$out/unwind-pe.h.orig" \
    "https://raw.githubusercontent.com/gcc-mirror/gcc/$GCC_TAG/libgcc/unwind-pe.h"

# The only change: report indirect pointers instead of following them.
sed 's/result = \*(_Unwind_Internal_Ptr \*) result;/result = oracle_indirect (result);/' \
    "$out/unwind-pe.h.orig" > "$out/unwind-pe.h"
if ! grep -q 'oracle_indirect (result)' "$out/unwind-pe.h" ||
    grep -q '\*(_Unwind_Internal_Ptr \*) result' "$out/unwind-pe.h"; then
    echo "build.sh: patching unwind-pe.h failed" >&2
    exit 1
fi

for width in ${ORACLE_WIDTHS:-64 32}; do
    ${CC:-gcc} -m"$width" -std=gnu11 -O1 -Wall -Werror -I"$out" \
        ${ORACLE_LDFLAGS:-} -o "$out/oracle$width" "$here/oracle.c"
done
echo "built in $out"
