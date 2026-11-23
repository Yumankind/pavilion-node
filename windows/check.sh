#!/bin/bash
# Compile-checks the node for Windows from a Mac (`cargo check`, nothing is linked or run). ring's build script
# compiles a little C for the target and archives it; without the Windows SDK, small stub headers and a stand-in for
# lib.exe let it finish. The stubs live in the target folder, never in the source tree.
set -euo pipefail
cd "$(dirname "$0")/.."
rustup target list --installed | grep -q x86_64-pc-windows-msvc || rustup target add x86_64-pc-windows-msvc
T=${CARGO_TARGET_DIR:-$(pwd)/target}
S="$T/win-check-include"; mkdir -p "$S"
echo '#define assert(x) ((void)0)' > "$S/assert.h"
printf '#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t); void *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t); void *memmove(void *, const void *, size_t);\n' > "$S/string.h"
printf '#include <stddef.h>\nvoid abort(void);\n' > "$S/stdlib.h"
printf '#!/bin/sh\nfor a in "$@"; do case "$a" in /OUT:*|-out:*) : > "${a#*:}";; esac; done\n' > "$S/fake-lib.sh"; chmod +x "$S/fake-lib.sh"
CFLAGS_x86_64_pc_windows_msvc="-I$S" AR_x86_64_pc_windows_msvc="$S/fake-lib.sh" cargo check -j "${JOBS:-4}" --target x86_64-pc-windows-msvc "$@"
