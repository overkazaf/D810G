#!/bin/bash
# Build OLLVM-obfuscated test binaries
# Requires: clang with OLLVM passes or obfuscator-llvm

set -e

cat > /tmp/d810g_test.c << 'EOF'
#include <stdio.h>

int target_function(int x, int y) {
    int result = 0;
    if (x > 0) {
        result = x + y;
    } else {
        result = x - y;
    }
    if (result > 100) {
        result = result % 100;
    }
    return result;
}

int main() {
    printf("%d\n", target_function(42, 17));
    return 0;
}
EOF

# Normal compilation (for comparison baseline)
gcc -O0 -o "$(dirname "$0")/d810g_test_normal" /tmp/d810g_test.c 2>/dev/null || \
    echo "gcc not available, skipping normal binary"

# With OLLVM (if available):
# clang -mllvm -fla -mllvm -sub -mllvm -bcf -o d810g_test_ollvm /tmp/d810g_test.c

echo "Sample build complete. Place OLLVM-compiled binaries in this directory."
