// BEFORE D810G — OLLVM Control Flow Flattening
// Ghidra decompiler output for check_license()

int check_license(char *param_1) {
    int iVar1;
    int local_1c;
    int local_18;
    int local_14;
    int local_10;

    local_10 = 0x2b8a7c3f;  // state variable
    local_1c = 0;
    local_18 = 0;

    while (true) {
        switch(local_10) {
        case 0x2b8a7c3f:
            local_14 = *(char *)(param_1 + local_18);
            if (local_14 == 0) {
                local_10 = 0x7d3e9a15;  // goto check_sum
            } else {
                local_10 = 0x4f1c82d6;  // goto accumulate
            }
            break;
        case 0x4f1c82d6:
            local_1c = local_1c + local_14;
            local_18 = local_18 + 1;
            local_10 = 0x2b8a7c3f;  // goto loop_head
            break;
        case 0x7d3e9a15:
            if (local_1c == 0x1a4) {
                local_10 = 0xa5b3c1d2;  // goto return_true
            } else {
                local_10 = 0xe8f47209;  // goto return_false
            }
            break;
        case 0xa5b3c1d2:
            return 1;
        case 0xe8f47209:
            return 0;
        }
    }
}
