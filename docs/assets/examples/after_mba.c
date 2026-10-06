// AFTER D810G — MBA expressions simplified

int compute_hash(int x, int y) {
    int result;

    result = x ^ y;          // was: (x | y) - (x & y)
    result = result + (x & y); // was: complex MBA
    result = result - (x | y); // was: result + (~(x | y) + 1)

    return result;
}
