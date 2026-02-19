// libcaesar.c
// Простая XOR-библиотека для шифрования/дешифрования

static unsigned char g_key = 0;  // ключ хранится внутри библиотеки

// Устанавливает ключ шифрования
void set_key(char key) {
    g_key = (unsigned char)key;
}

// XOR-шифрование/дешифрование
void caesar(void* src, void* dst, int len) {
    unsigned char* s = (unsigned char*)src;
    unsigned char* d = (unsigned char*)dst;

    for (int i = 0; i < len; i++) {
        d[i] = s[i] ^ g_key;
    }
}
