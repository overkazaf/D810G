// BEFORE D810G — Bogus Control Flow
// Ghidra decompiler output

int compute_hash(int x, int y) {
    int result;

    // Bogus branch #1 — x*x >= 0 is ALWAYS true
    if ((x * x) >= 0) {
        result = (x | y) - (x & y);
    } else {
        // Dead code — never reached
        result = x * 0x539 + y * 0x1337;
        result = result ^ 0xDEADBEEF;
    }

    // Bogus branch #2 — (x & 1) == 2 is ALWAYS false
    if (((x & 1) == 2)) {
        // Dead code — never reached
        result = ~result ^ 0xCAFEBABE;
    } else {
        result = result + (x & y);
    }

    result = result - (x | y);
    return result;
}
