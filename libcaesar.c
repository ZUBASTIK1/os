// Библиотека шифрования с защитой ключа и состояния шифра в памяти.
//
// Эволюция по заданиям:
//   - Задание 5: XOR-шифр, ключ в защищённой mmap-области (PROT_NONE между
//     использованиями + SIGSEGV-обработчик на попытку записи).
//   - Задание 6: RC4. Мастер-ключ хранится в общей защищённой странице.
//     Для каждого файла RC4 инициализируется как конкатенация мастер-ключа и
//     16-байтовой соли.
//   - Задание 6 (доработка): потоковое шифрование по кусочкам. Состояние RC4
//     (S-box + счётчики i, j) вынесено в ОТДЕЛЬНЫЙ КОНТЕКСТ на каждый поток.
//     Контекст хранится в собственной защищённой mmap-странице: между вызовами
//     PROT_NONE, на время шифрования чанка — PROT_READ|PROT_WRITE. Это
//     позволяет шифровать файл частями (init один раз, crypt много раз),
//     сохраняя требование "внутреннее состояние шифра недоступно вне процедуры
//     шифрования" — состояние недоступно для прямого доступа даже строже, чем
//     раньше (попытка записи в него вызовет SIGSEGV).
//
// Потокобезопасность: мастер-ключ общий, доступ к нему сериализован мьютексом.
// Состояние RC4 у каждого потока СВОЁ (свой контекст), поэтому потоки,
// шифрующие разные файлы, не мешают друг другу.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>

// Размер защищённой mmap-области под мастер-ключ. Одна страница (4 КБ) с
// запасом перекрывает любой разумный ключ. Соль (16 байт) сюда не пишется —
// она не секретна и хранится в открытом виде в образе.
#define KEY_BUF_SIZE 4096
#define SALT_SIZE    16

// ---------------------------------------------------------------------------
// Общая защищённая страница с мастер-ключом
// ---------------------------------------------------------------------------
static unsigned char *g_key_page = NULL;   // NULL — ключ не установлен
static size_t         g_key_len  = 0;      // фактическая длина мастер-ключа

// Мьютекс для синхронизации доступа к мастер-ключу. Между использованиями
// страница имеет PROT_NONE; без мьютекса один поток мог бы поставить PROT_NONE,
// пока другой ещё читает байт ключа, что вызвало бы SIGSEGV.
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

// Флаг, что обработчик SIGSEGV установлен (ставится один раз)
static int g_sigsegv_installed = 0;

// ---------------------------------------------------------------------------
// Реестр защищённых страниц контекстов RC4.
//
// SIGSEGV-обработчик должен уметь отличить "удар в защищённую память" от
// настоящего бага. Раньше он проверял только страницу мастер-ключа. Теперь
// защищённых страниц несколько (по одной на контекст потока), поэтому ведём
// небольшой реестр их адресов, чтобы обработчик мог проверить попадание
// в любую из них. Доступ к реестру защищён отдельным мьютексом.
// ---------------------------------------------------------------------------
#define MAX_CTX_PAGES 64
static unsigned char *g_ctx_pages[MAX_CTX_PAGES];
static size_t         g_ctx_page_count = 0;
static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;

static void registry_add(unsigned char *page) {
    pthread_mutex_lock(&g_registry_mutex);
    if (g_ctx_page_count < MAX_CTX_PAGES)
        g_ctx_pages[g_ctx_page_count++] = page;
    pthread_mutex_unlock(&g_registry_mutex);
}

static void registry_remove(unsigned char *page) {
    pthread_mutex_lock(&g_registry_mutex);
    for (size_t i = 0; i < g_ctx_page_count; i++) {
        if (g_ctx_pages[i] == page) {
            g_ctx_pages[i] = g_ctx_pages[g_ctx_page_count - 1];
            g_ctx_page_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_registry_mutex);
}

// ---------------------------------------------------------------------------
// Структура контекста RC4. Размещается ВНУТРИ защищённой страницы целиком,
// поэтому защита PROT_NONE покрывает и S-box, и счётчики i/j.
// ---------------------------------------------------------------------------
typedef struct {
    unsigned char S[256];   // таблица перестановки RC4
    unsigned int  i;        // счётчик i (PRGA)
    unsigned int  j;        // счётчик j (PRGA)
    int           ready;    // 1 после успешного KSA (init)
} rc4_ctx_t;

// ---------------------------------------------------------------------------
// SIGSEGV-обработчик. Различает попытку записи в защищённую память (ключ или
// любой контекст RC4) от прочих ошибок доступа. Использует только
// async-signal-safe функции (write, _exit).
// ---------------------------------------------------------------------------
static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)ucontext;

    static const char msg_key[] =
        "[SECURITY] SIGSEGV: attempt to modify protected key/state memory detected. "
        "Terminating.\n";
    static const char msg_other[] =
        "[SECURITY] SIGSEGV: invalid memory access (not in protected region). "
        "Terminating.\n";

    int in_protected = 0;
    unsigned char *addr = info ? (unsigned char*)info->si_addr : NULL;

    // Попадание в страницу мастер-ключа?
    if (addr && g_key_page &&
        addr >= g_key_page && addr < g_key_page + KEY_BUF_SIZE) {
        in_protected = 1;
    }
    // Попадание в любую страницу контекста? (реестр; без мьютекса — в обработчике
    // сигнала блокировки нежелательны, а чтение указателей атомарно достаточно
    // для нашей цели — диагностического сообщения.)
    if (!in_protected && addr) {
        for (size_t k = 0; k < g_ctx_page_count && k < MAX_CTX_PAGES; k++) {
            unsigned char *p = g_ctx_pages[k];
            if (p && addr >= p && addr < p + sizeof(rc4_ctx_t)) {
                in_protected = 1;
                break;
            }
        }
    }

    if (in_protected)
        write(STDERR_FILENO, msg_key, sizeof(msg_key) - 1);
    else
        write(STDERR_FILENO, msg_other, sizeof(msg_other) - 1);

    _exit(2);
}

static int install_sigsegv_handler(void) {
    if (g_sigsegv_installed) return 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("sigaction(SIGSEGV)");
        return -1;
    }
    g_sigsegv_installed = 1;
    return 0;
}

// Освобождение страницы мастер-ключа с предварительным затиранием.
// Регистрируется через atexit().
static void cleanup_key(void) {
    if (g_key_page == NULL) return;
    if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect (cleanup RW)");
    } else {
        memset(g_key_page, 0, KEY_BUF_SIZE);
        if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_NONE) != 0)
            perror("mprotect (cleanup NONE)");
    }
    if (munmap(g_key_page, KEY_BUF_SIZE) != 0)
        perror("munmap");
    g_key_page = NULL;
    g_key_len = 0;
}

// ---------------------------------------------------------------------------
// Установка мастер-ключа произвольной длины в защищённую страницу.
// Возвращает 0 при успехе, -1 при ошибке.
// ---------------------------------------------------------------------------
int set_master_key(const char *key, size_t key_len) {
    if (key == NULL || key_len == 0 || key_len > KEY_BUF_SIZE) {
        fprintf(stderr, "set_master_key: invalid key (len=%zu)\n", key_len);
        return -1;
    }

    if (g_key_page == NULL) {
        g_key_page = mmap(NULL, KEY_BUF_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_key_page == MAP_FAILED) {
            perror("mmap");
            g_key_page = NULL;
            return -1;
        }
        memset(g_key_page, 0, KEY_BUF_SIZE);

        if (install_sigsegv_handler() != 0) {
            munmap(g_key_page, KEY_BUF_SIZE);
            g_key_page = NULL;
            return -1;
        }
        if (atexit(cleanup_key) != 0)
            fprintf(stderr, "atexit registration failed\n");
    } else {
        if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect (set_master_key RW)");
            return -1;
        }
        memset(g_key_page, 0, KEY_BUF_SIZE);  // затираем старый ключ
    }

    memcpy(g_key_page, key, key_len);
    g_key_len = key_len;

    if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_NONE) != 0) {
        perror("mprotect (set_master_key NONE)");
        return -1;
    }
    return 0;
}

// ===========================================================================
// КОНТЕКСТНЫЙ RC4 API (потоковое шифрование по кусочкам)
// ===========================================================================

// Создаёт контекст RC4 в собственной защищённой странице.
// Возвращает непрозрачный указатель (void*) или NULL при ошибке.
// Каждый поток должен создать свой контекст.
void* rc4_ctx_create(void) {
    // Выделяем целую страницу под структуру контекста (mprotect работает с
    // гранулярностью страниц, поэтому структура должна занимать свою страницу).
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (page < sizeof(rc4_ctx_t)) page = 4096;

    unsigned char *mem = mmap(NULL, page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap (rc4_ctx_create)");
        return NULL;
    }
    memset(mem, 0, page);

    // На случай, если контекст создаётся раньше set_master_key — гарантируем,
    // что обработчик SIGSEGV установлен (защита состояния работает независимо).
    install_sigsegv_handler();

    registry_add(mem);

    // Закрываем доступ до первого init.
    if (mprotect(mem, page, PROT_NONE) != 0) {
        perror("mprotect (rc4_ctx_create NONE)");
        registry_remove(mem);
        munmap(mem, page);
        return NULL;
    }
    return mem;
}

// Уничтожает контекст: затирает состояние и освобождает страницу.
void rc4_ctx_destroy(void *ctx) {
    if (ctx == NULL) return;
    unsigned char *mem = (unsigned char*)ctx;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (page < sizeof(rc4_ctx_t)) page = 4096;

    if (mprotect(mem, page, PROT_READ | PROT_WRITE) == 0) {
        memset(mem, 0, page);                 // затираем S-box и счётчики
    } else {
        perror("mprotect (rc4_ctx_destroy RW)");
    }
    registry_remove(mem);
    if (munmap(mem, page) != 0)
        perror("munmap (rc4_ctx_destroy)");
}

// Инициализация контекста (KSA) для конкретного файла.
// Ключ инициализации = мастер-ключ || соль.
// Возвращает 0 при успехе, -1 при ошибке.
int rc4_ctx_init(void *ctx, const unsigned char *salt) {
    if (ctx == NULL || salt == NULL) {
        fprintf(stderr, "rc4_ctx_init: invalid arguments\n");
        return -1;
    }
    if (g_key_page == NULL || g_key_len == 0) {
        fprintf(stderr, "rc4_ctx_init: master key is not set\n");
        return -1;
    }

    rc4_ctx_t *c = (rc4_ctx_t*)ctx;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (page < sizeof(rc4_ctx_t)) page = 4096;

    // Открываем страницу контекста на чтение-запись для заполнения S-box.
    if (mprotect((void*)c, page, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect (rc4_ctx_init RW)");
        return -1;
    }

    // Инициализация S перестановкой 0..255.
    for (int k = 0; k < 256; k++)
        c->S[k] = (unsigned char)k;

    // KSA: читаем мастер-ключ под мьютексом (общая защищённая страница).
    size_t key_total = g_key_len + SALT_SIZE;

    pthread_mutex_lock(&g_key_mutex);
    if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_READ) != 0) {
        perror("mprotect (rc4_ctx_init key READ)");
        pthread_mutex_unlock(&g_key_mutex);
        // вернём страницу контекста в закрытое состояние перед выходом
        mprotect((void*)c, page, PROT_NONE);
        return -1;
    }

    unsigned int j = 0;
    for (int k = 0; k < 256; k++) {
        unsigned char key_byte;
        size_t idx = (size_t)k % key_total;
        if (idx < g_key_len)
            // volatile — чтобы компилятор честно читал из защищённой страницы.
            key_byte = ((volatile unsigned char*)g_key_page)[idx];
        else
            key_byte = salt[idx - g_key_len];
        j = (j + c->S[k] + key_byte) & 0xFF;
        unsigned char tmp = c->S[k];
        c->S[k] = c->S[j];
        c->S[j] = tmp;
    }

    // Мастер-ключ больше не нужен — закрываем его страницу.
    if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_NONE) != 0)
        perror("mprotect (rc4_ctx_init key NONE)");
    pthread_mutex_unlock(&g_key_mutex);

    // Сбрасываем счётчики PRGA — поток начинается с начала.
    c->i = 0;
    c->j = 0;
    c->ready = 1;

    // Закрываем доступ к контексту до первого crypt.
    if (mprotect((void*)c, page, PROT_NONE) != 0) {
        perror("mprotect (rc4_ctx_init NONE)");
        return -1;
    }
    return 0;
}

// Шифрование/расшифровка одного куска (PRGA), продолжая состояние контекста.
// Можно вызывать многократно — состояние (S, i, j) сохраняется между вызовами.
// Возвращает 0 при успехе, -1 при ошибке.
int rc4_ctx_crypt(void *ctx, const void *in, void *out, size_t len) {
    if (ctx == NULL) {
        fprintf(stderr, "rc4_ctx_crypt: null context\n");
        return -1;
    }
    if (len == 0) return 0;
    if (in == NULL || out == NULL) {
        fprintf(stderr, "rc4_ctx_crypt: null buffer\n");
        return -1;
    }

    rc4_ctx_t *c = (rc4_ctx_t*)ctx;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (page < sizeof(rc4_ctx_t)) page = 4096;

    // Открываем состояние на чтение-запись только на время шифрования чанка.
    if (mprotect((void*)c, page, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect (rc4_ctx_crypt RW)");
        return -1;
    }
    if (!c->ready) {
        fprintf(stderr, "rc4_ctx_crypt: context not initialized\n");
        mprotect((void*)c, page, PROT_NONE);
        return -1;
    }

    const unsigned char *in_p  = (const unsigned char*)in;
    unsigned char       *out_p = (unsigned char*)out;

    // Работаем напрямую с состоянием в защищённой странице (volatile, чтобы
    // байты состояния не кэшировались в обход страницы).
    volatile unsigned char *S = c->S;
    unsigned int i = c->i;
    unsigned int j = c->j;

    for (size_t n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        unsigned char K = S[(S[i] + S[j]) & 0xFF];
        out_p[n] = in_p[n] ^ K;
    }

    // Сохраняем счётчики обратно в контекст.
    c->i = i;
    c->j = j;

    // Закрываем состояние до следующего вызова.
    if (mprotect((void*)c, page, PROT_NONE) != 0) {
        perror("mprotect (rc4_ctx_crypt NONE)");
        return -1;
    }
    return 0;
}

// ===========================================================================
// Одноразовый RC4 (init+crypt за один вызов). Используется в -get, где файл
// расшифровывается целиком. Реализован поверх контекстного API, чтобы не
// дублировать логику KSA/PRGA.
// Внутреннее состояние — временный контекст, живущий только внутри функции.
// ===========================================================================
int rc4_crypt(const unsigned char *salt, const void *in, void *out, size_t len) {
    void *ctx = rc4_ctx_create();
    if (!ctx) return -1;
    int rc = rc4_ctx_init(ctx, salt);
    if (rc == 0 && len > 0)
        rc = rc4_ctx_crypt(ctx, in, out, len);
    rc4_ctx_destroy(ctx);
    return rc;
}

// ===========================================================================
// Унаследованные функции (задание 5). Оставлены для обратной совместимости
// и демонстрации SIGSEGV. В новом secure_copy не вызываются.
// ===========================================================================
void set_key(char key) {
    unsigned char k = (unsigned char)key;
    set_master_key((const char*)&k, 1);
}

void caesar(void* src, void* dst, int len) {
    if (g_key_page == NULL) {
        fprintf(stderr, "caesar: key is not set\n");
        return;
    }
    if (len <= 0) return;

    pthread_mutex_lock(&g_key_mutex);
    if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_READ) != 0) {
        perror("mprotect (caesar READ)");
        pthread_mutex_unlock(&g_key_mutex);
        return;
    }
    unsigned char k = ((volatile unsigned char*)g_key_page)[0];
    if (mprotect(g_key_page, KEY_BUF_SIZE, PROT_NONE) != 0) {
        perror("mprotect (caesar NONE)");
        pthread_mutex_unlock(&g_key_mutex);
        return;
    }
    pthread_mutex_unlock(&g_key_mutex);

    unsigned char* s = (unsigned char*)src;
    unsigned char* d = (unsigned char*)dst;
    for (int n = 0; n < len; n++)
        d[n] = s[n] ^ k;
    k = 0; (void)k;
}

// Возвращает указатель на страницу мастер-ключа — только для демонстрации
// попытки прямой записи (ожидаемо приведёт к SIGSEGV).
void* get_key_ptr(void) {
    return (void*)g_key_page;
}

// Демонстрация защиты СОСТОЯНИЯ шифра (S-box), а не только ключа.
// Создаёт контекст RC4, инициализирует его переданной солью (чтобы S-box был
// заполнен и страница переведена в PROT_NONE) и возвращает указатель на эту
// защищённую страницу. Прямая запись по нему ожидаемо приведёт к SIGSEGV.
// Требует, чтобы мастер-ключ уже был установлен (нужен для KSA).
// Контекст намеренно НЕ уничтожается: программа всё равно завершится по
// SIGSEGV сразу после попытки записи (это демонстрация).
void* get_state_ptr(void) {
    void *ctx = rc4_ctx_create();
    if (!ctx) return NULL;
    unsigned char demo_salt[SALT_SIZE];
    memset(demo_salt, 0, sizeof(demo_salt));   // соль для демо неважна
    if (rc4_ctx_init(ctx, demo_salt) != 0) {
        rc4_ctx_destroy(ctx);
        return NULL;
    }
    return ctx;
}
