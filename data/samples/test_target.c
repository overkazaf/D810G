#include <stdio.h>
#include <stdlib.h>

// Simulates a simple function that would be obfuscated
int check_license(const char *key) {
    int sum = 0;
    for (int i = 0; key[i] != '\0'; i++) {
        sum += key[i];
    }
    if (sum == 0x1a4) {
        return 1;
    }
    return 0;
}

int compute_hash(int x, int y) {
    int result = x ^ y;
    result = result + (x & y);
    result = result - (x | y);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <key>\n", argv[0]);
        return 1;
    }
    if (check_license(argv[1])) {
        printf("License valid! Hash: %d\n", compute_hash(42, 17));
    } else {
        printf("Invalid license.\n");
    }
    return 0;
}
