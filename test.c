#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #define LIB_HANDLE HMODULE
    #define LIB_OPEN(lib) LoadLibraryA(lib)   // Явно ANSI-версия
    #define LIB_SYM(handle, sym) GetProcAddress(handle, sym)
    #define LIB_CLOSE(handle) FreeLibrary(handle)
    #define LIB_ERROR() "LoadLibrary/GetProcAddress failed"
#else
    #include <dlfcn.h>
    #define LIB_HANDLE void*
    #define LIB_OPEN(lib) dlopen(lib, RTLD_LAZY)
    #define LIB_SYM(handle, sym) dlsym(handle, sym)
    #define LIB_CLOSE(handle) dlclose(handle)
    #define LIB_ERROR() dlerror()
#endif

typedef void (*set_key_t)(char);
typedef void (*caesar_t)(void*, void*, int);

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage: %s <libpath> <key> <input> <output>\n", argv[0]);
        return 1;
    }

    const char* libpath = argv[1];
    const char* key_arg = argv[2];
    const char* infile = argv[3];
    const char* outfile = argv[4];

    // --- обработка ключа: символ или число ---
    char key;
    char* endptr;
    long num_key = strtol(key_arg, &endptr, 10);
    if (*endptr == '\0' && num_key >= 0 && num_key <= 255) {
        key = (char)num_key;
    } else {
        key = key_arg[0];
    }

    // --- загрузка библиотеки ---
    LIB_HANDLE handle = LIB_OPEN(libpath);
    if (!handle) {
        fprintf(stderr, "Library load error: %s\n", LIB_ERROR());
        return 1;
    }

    set_key_t set_key = (set_key_t)LIB_SYM(handle, "set_key");
    caesar_t caesar = (caesar_t)LIB_SYM(handle, "caesar");

    if (!set_key || !caesar) {
        fprintf(stderr, "Symbol lookup error: %s\n", LIB_ERROR());
        LIB_CLOSE(handle);
        return 1;
    }

    // --- чтение входного файла ---
    FILE* fin = fopen(infile, "rb");
    if (!fin) {
        perror("fopen input");
        LIB_CLOSE(handle);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long size = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(size);
    if (!buffer) {
        perror("malloc");
        fclose(fin);
        LIB_CLOSE(handle);
        return 1;
    }

    size_t bytes_read = fread(buffer, 1, size, fin);
    fclose(fin);

    if (bytes_read != size) {
        fprintf(stderr, "Warning: only %zu bytes read\n", bytes_read);
    }

    // --- шифрование ---
    set_key(key);
    caesar(buffer, buffer, (int)bytes_read);  // размер файла в учебных целях умещается в int

    // --- запись результата ---
    FILE* fout = fopen(outfile, "wb");
    if (!fout) {
        perror("fopen output");
        free(buffer);
        LIB_CLOSE(handle);
        return 1;
    }

    fwrite(buffer, 1, bytes_read, fout);
    fclose(fout);

    free(buffer);
    LIB_CLOSE(handle);
    return 0;
}