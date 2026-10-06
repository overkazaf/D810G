// AFTER D810G — Original control flow restored

int check_license(char *param_1) {
    int sum = 0;
    int i = 0;

    while (*(char *)(param_1 + i) != '\0') {
        sum = sum + *(char *)(param_1 + i);
        i = i + 1;
    }

    if (sum == 0x1a4) {
        return 1;
    }
    return 0;
}
