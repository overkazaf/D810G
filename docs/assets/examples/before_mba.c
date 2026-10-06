// BEFORE D810G — MBA obfuscation (OLLVM -sub flag)
// Ghidra decompiler output for compute_hash()

int compute_hash(int x, int y) {
    int result;

    // Original: x ^ y
    // Obfuscated via MBA:
    result = (x | y) - (x & y);

    // Original: result + (x & y)
    // Obfuscated via MBA:
    result = ((result | (x & y)) - (result & (x & y))) +
             2 * (result & (x & y));

    // Original: result - (x | y)
    // Obfuscated via MBA:
    result = result + (~(x | y) + 1);

    return result;
}
