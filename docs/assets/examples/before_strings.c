// BEFORE D810G — OLLVM String Encryption
// Ghidra decompiler output

void print_messages(void) {
    char encrypted_1[] = {0x2d, 0x2a, 0x26, 0x22, 0x27, 0x1f,
                          0x0a, 0x36, 0x22, 0x35, 0x2a, 0x21};
    // XOR key: 0x45
    // Decrypted: "Hello, World"

    char encrypted_2[] = {0x14, 0x3a, 0x27, 0x37, 0x30, 0x34, 0x22};
    // XOR key: 0x45
    // Decrypted: "License"

    // decrypt at runtime...
    for (int i = 0; i < sizeof(encrypted_1); i++) {
        encrypted_1[i] ^= 0x45;
    }
    puts(encrypted_1);
}
