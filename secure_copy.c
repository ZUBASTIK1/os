// secure_copy — утилита создания и работы с файловым образом, в котором
// файлы хранятся в зашифрованном виде (RC4 с уникальной солью на файл).
//
// Формат образа (последовательность записей, без заголовка):
//   [4 байта]  file_size  — длина содержимого файла (little-endian, uint32)
//   [4 байта]  name_len   — длина имени файла              (little-endian, uint32)
//   [16 байт]  salt       — соль RC4 (генерируется отдельно для каждого файла)
//   [name_len] name       — имя файла (НЕ шифруется — нужно для -list без ключа)
//   [file_size] data      — содержимое файла, ЗАШИФРОВАННОЕ RC4(master_key||salt)
//
// Команды:
//   ./secure_copy -add  -key K -image I.img file1 file2 dir/...
//   ./secure_copy -list -image I.img
//   ./secure_copy -get  -image I.img -key K -out result_file file_name
//
// Параллелизм: при добавлении нескольких файлов используется пул потоков,
// не более 5. Запись в образ синхронизирована мьютексом — несколько потоков
// готовят зашифрованные буферы параллельно, а финальная запись в файл идёт
// последовательно (соответствует требованию "параллельная обработка" при
// сохранении целостности образа).

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

// -----------------------------------------------------------------------------
// Константы формата
// -----------------------------------------------------------------------------
#define SALT_SIZE       16
#define HEADER_SIZE     (4 + 4 + SALT_SIZE)   // 24 байта на запись (без имени и данных)
#define MAX_NAME_LEN    4096                  // защита от мусора при чтении образа
// Длина файла хранится в 4 байтах (uint32), поэтому максимум, который можно
// записать в заголовок, — 0xFFFFFFFF (= 4 ГиБ - 1 байт). Ровно 4 ГиБ
// (4294967296) уже не помещается в uint32, поэтому условие — СТРОГО меньше
// 4 ГиБ. MAX_FILE_SIZE = 2^32 = первое недопустимое значение; всё, что >=,
// отвергается.
#define MAX_FILE_SIZE   (UINT64_C(1) << 32)   // 4 ГиБ — первый запрещённый размер (>= отвергается)
#define CHUNK_SIZE      (64 * 1024)           // буфер чтения файлов при добавлении

// Максимум одновременно работающих потоков по требованию задания: "не более 5".
#define MAX_WORKERS     5

// -----------------------------------------------------------------------------
// Указатели на функции из libcaesar.so (динамическая загрузка)
// -----------------------------------------------------------------------------
typedef int  (*set_master_key_fn)(const char*, size_t);
// Контекстный RC4 API (потоковое шифрование по кусочкам, состояние в защищённой памяти).
// Используется и при -add, и при -get: init один раз на файл, crypt — много раз по чанкам.
typedef void* (*rc4_ctx_create_fn)(void);
typedef int   (*rc4_ctx_init_fn)(void*, const unsigned char*);
typedef int   (*rc4_ctx_crypt_fn)(void*, const void*, void*, size_t);
typedef void  (*rc4_ctx_destroy_fn)(void*);
// Демо-функции из библиотеки (для --demo-attack): возвращают указатели на
// защищённые страницы ключа и состояния шифра. Могут отсутствовать в старых
// версиях библиотеки — поэтому при загрузке они не обязательны.
typedef void* (*get_key_ptr_fn)(void);
typedef void* (*get_state_ptr_fn)(void);

static set_master_key_fn lib_set_master_key = NULL;
static rc4_ctx_create_fn  lib_rc4_ctx_create  = NULL;
static rc4_ctx_init_fn    lib_rc4_ctx_init    = NULL;
static rc4_ctx_crypt_fn   lib_rc4_ctx_crypt   = NULL;
static rc4_ctx_destroy_fn lib_rc4_ctx_destroy = NULL;
static get_key_ptr_fn     lib_get_key_ptr     = NULL;  // для демонстрации (не обязательна)
static get_state_ptr_fn   lib_get_state_ptr   = NULL;  // для демонстрации (не обязательна)
static void *lib_handle = NULL;

// -----------------------------------------------------------------------------
// Логирование (перенесено из задания 5).
// Каждая операция (-add для файла, -get) пишется в log.txt с временной меткой.
// Лог-файл общий для всех потоков, поэтому запись в него защищена мьютексом.
// -----------------------------------------------------------------------------
static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Записывает в buf текущее локальное время в формате ГГГГ-ММ-ДД ЧЧ:ММ:СС.
// Использует localtime_r (а не localtime): обычная localtime возвращает
// указатель на общий статический буфер, что вызывает гонку данных при
// одновременном вызове из нескольких потоков (worker'ы логируют параллельно).
// localtime_r пишет результат в переданную локальную структуру — она на стеке
// вызывающего потока, гонки нет.
static void get_timestamp(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&t, &tm_buf);
    if (tm_info == NULL) { snprintf(buf, len, "unknown-time"); return; }
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Потокобезопасная запись строки в лог. Если лог не открыт — тихо игнорирует
// (логирование не должно ломать основную работу).
static void log_event(const char *fmt, ...) {
    if (log_file == NULL) return;

    pthread_mutex_lock(&log_mutex);

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    fprintf(log_file, "[%s] ", timestamp);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);
    fputc('\n', log_file);
    fflush(log_file);
    pthread_mutex_unlock(&log_mutex);
}

// -----------------------------------------------------------------------------
// Глобальные флаги и состояние программы
// -----------------------------------------------------------------------------
static volatile sig_atomic_t keep_running = 1;

// Обработчик Ctrl+C: сбрасывает глобальный флаг, чтобы циклы завершились
// штатно, без аварийной остановки в середине записи в образ.
static void sig_handler(int sig) {
    // подавляет предупреждение компилятора о неиспользуемом параметре sig (вам не важно, какой именно сигнал пришёл).
    (void)sig;
    /* keep_running = 0; – изменяет глобальную переменную keep_running на 0.
Флаг keep_running проверяется в потоках-воркерах (в add_worker в цикле while (keep_running)) и 
в основном цикле добавления файлов (for (int i = 0; i < input_count && keep_running; i++)). 
Когда keep_running становится 0:
Воркеры завершаются, когда очередь пуста (или сразу, если queue_pop вернёт NULL).
Основной цикл перестаёт добавлять новые задачи в очередь.
После завершения всех потоков программа корректно закрывает образ и освобождает ресурсы. */
    keep_running = 0;
}

// -----------------------------------------------------------------------------
// Низкоуровневые помощники для сериализации/десериализации little-endian uint32
// -----------------------------------------------------------------------------
static void write_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v        & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static uint32_t read_u32_le(const unsigned char *p) {
    return  (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

// -----------------------------------------------------------------------------
// Генерация соли из /dev/urandom. При ошибке откатывается на rand() —
// для криптографических целей такой откат слаб, но программа продолжает
// работать (требование задания: не падать аварийно).
// -----------------------------------------------------------------------------
static int generate_salt(unsigned char salt[SALT_SIZE]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t got = 0;
        while (got < SALT_SIZE) {
            ssize_t n = read(fd, salt + got, SALT_SIZE - got);
            if (n <= 0) { close(fd); goto fallback; }
            got += n;
        }
        close(fd);
        return 0;
    }
fallback:
    fprintf(stderr, "warning: /dev/urandom unavailable, using weak random salt\n");
    {
        static int seeded = 0;
        if (!seeded) { srand((unsigned)time(NULL) ^ (unsigned)getpid()); seeded = 1; }
        for (int i = 0; i < SALT_SIZE; i++) salt[i] = (unsigned char)(rand() & 0xFF);
    }
    return 0;
}


// -----------------------------------------------------------------------------
// Рекурсивный обход директории. Для каждого обычного файла вызывает
// callback с (фактический_путь, имя_для_образа). Имя для образа строится
// относительно "корня" из аргумента командной строки и включает имя самой
// директории (например: "in/sub/file.txt" для аргумента "in").
// При ошибке (нет прав, битая ссылка) — пишет в stderr и продолжает.
// -----------------------------------------------------------------------------
typedef int (*walk_cb_t)(const char *src_path, const char *stored_name, void *user);

static int walk_recursive(const char *src_path, const char *stored_prefix,
                          walk_cb_t cb, void *user) {
    struct stat st;
    if (lstat(src_path, &st) != 0) {
        fprintf(stderr, "lstat(%s): %s\n", src_path, strerror(errno));
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        return cb(src_path, stored_prefix, user);
    }

    if (!S_ISDIR(st.st_mode)) {
        // Не обычный файл и не директория (symlink/устройство/...) — пропускаем.
        fprintf(stderr, "skip non-regular: %s\n", src_path);
        return 0;
    }

    DIR *d = opendir(src_path);
    if (!d) {
        fprintf(stderr, "opendir(%s): %s\n", src_path, strerror(errno));
        return -1;
    }

    int rc = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char child_src[4096];
        char child_stored[4096];
        int n1 = snprintf(child_src, sizeof(child_src), "%s/%s", src_path, e->d_name);
        int n2 = snprintf(child_stored, sizeof(child_stored), "%s/%s", stored_prefix, e->d_name);
        if (n1 < 0 || n1 >= (int)sizeof(child_src) ||
            n2 < 0 || n2 >= (int)sizeof(child_stored)) {
            fprintf(stderr, "path too long, skipping: %s/%s\n", src_path, e->d_name);
            rc = -1;
            continue;
        }

        if (walk_recursive(child_src, child_stored, cb, user) != 0) rc = -1;
    }
    closedir(d);
    return rc;
}

// -----------------------------------------------------------------------------
// ДВУХПРОХОДНОЕ ПАРАЛЛЕЛЬНОЕ ДОБАВЛЕНИЕ (вариант А)
//
// Проблема обычной параллельной записи: записи в образе имеют переменную длину
// (имя + содержимое), поэтому смещение записи N известно только после того,
// как записаны все предыдущие. Решение — два прохода:
//
//   Проход 1 (последовательный): собираем список всех файлов, узнаём их размеры
//   и длины имён, генерируем соль для каждого, и ВЫЧИСЛЯЕМ смещение каждой
//   записи в образе. Затем растягиваем файл образа до итогового размера
//   (ftruncate), чтобы все смещения существовали физически.
//
//   Проход 2 (параллельный, до MAX_WORKERS потоков): каждый поток берёт задачу
//   из очереди. У задачи УЖЕ ЕСТЬ готовое смещение, поэтому поток шифрует файл
//   по кусочкам своим RC4-контекстом и пишет результат через pwrite() в своё
//   место образа. Поскольку области записи у потоков не пересекаются, мьютекс
//   на запись НЕ НУЖЕН — это настоящая параллельная запись.
// -----------------------------------------------------------------------------

// Одно задание на добавление: путь на диске, имя в образе, размеры, соль и
// заранее вычисленное смещение записи в образе.
typedef struct {
    char         *src_path;       // путь к файлу на диске
    char         *stored_name;    // имя в образе
    uint32_t      file_size;      // размер содержимого
    uint32_t      name_len;       // длина имени
    unsigned char salt[SALT_SIZE];// соль для этого файла
    off_t         offset;         // смещение начала записи в образе
    int           result;         // 0 = ок, -1 = ошибка (заполняется в проходе 2)
} add_job_t;

// Растущий массив заданий (заполняется в проходе 1 при обходе файлов/директорий).
typedef struct {
    add_job_t *jobs;
    size_t     count;
    size_t     cap;
    // Имена, уже присутствующие в существующем образе (читаются до прохода 1).
    // Нужны для запрета дубликатов: новое имя не должно совпасть ни с уже
    // лежащим в образе, ни с другим именем из текущего запуска.
    char     **existing;
    size_t     existing_count;
    size_t     existing_cap;
    int        skipped_dup;   // сколько файлов пропущено как дубликаты
    int        collect_errors;// сколько файлов не удалось собрать (stat/тип/размер)
} job_list_t;

// Проверяет, встречалось ли имя уже: среди имён в образе (existing) или среди
// уже собранных заданий (jobs). Возвращает 1, если дубликат, иначе 0.
static int joblist_name_exists(const job_list_t *jl, const char *name) {
    for (size_t i = 0; i < jl->existing_count; i++)
        if (strcmp(jl->existing[i], name) == 0) return 1;
    for (size_t i = 0; i < jl->count; i++)
        if (strcmp(jl->jobs[i].stored_name, name) == 0) return 1;
    return 0;
}

// Читает имена всех записей из уже существующего образа в jl->existing.
// Образ может отсутствовать (новый) — это не ошибка. Возвращает 0 при успехе,
// -1 при повреждённом образе (тогда -add лучше прервать выше).
static int joblist_load_existing(job_list_t *jl, const char *image_path) {
    int fd = open(image_path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return 0;  // образа ещё нет — дубликатов быть не может
        fprintf(stderr, "open(%s) for dup-check: %s\n", image_path, strerror(errno));
        return -1;
    }

    int rc = 0;
    for (;;) {
        unsigned char header[HEADER_SIZE];
        ssize_t r = read(fd, header, HEADER_SIZE);
        if (r == 0) break;               // EOF — дочитали все записи
        if (r != HEADER_SIZE) {
            fprintf(stderr, "corrupt image (header) during dup-check\n");
            rc = -1; break;
        }
        uint32_t fsize = read_u32_le(header + 0);
        uint32_t nlen  = read_u32_le(header + 4);
        if (nlen == 0 || nlen > MAX_NAME_LEN) {
            fprintf(stderr, "corrupt image (name length) during dup-check\n");
            rc = -1; break;
        }

        char *name = malloc((size_t)nlen + 1);
        if (!name) { fprintf(stderr, "malloc failed\n"); rc = -1; break; }
        if (read(fd, name, nlen) != (ssize_t)nlen) {
            fprintf(stderr, "corrupt image (name) during dup-check\n");
            free(name); rc = -1; break;
        }
        name[nlen] = '\0';

        // Перепрыгиваем зашифрованное содержимое.
        if (lseek(fd, (off_t)fsize, SEEK_CUR) == (off_t)-1) {
            fprintf(stderr, "lseek during dup-check: %s\n", strerror(errno));
            free(name); rc = -1; break;
        }

        // Складываем имя в existing.
        if (jl->existing_count == jl->existing_cap) {
            size_t nc = jl->existing_cap ? jl->existing_cap * 2 : 16;
            char **ne = realloc(jl->existing, nc * sizeof(char*));
            if (!ne) { fprintf(stderr, "realloc failed\n"); free(name); rc = -1; break; }
            jl->existing = ne;
            jl->existing_cap = nc;
        }
        jl->existing[jl->existing_count++] = name;
    }
    close(fd);
    return rc;
}

static int joblist_add(job_list_t *jl, const char *src_path, const char *stored_name) {
    // stat для размера.
    struct stat st;
    if (stat(src_path, &st) != 0) {
        fprintf(stderr, "stat(%s): %s\n", src_path, strerror(errno));
        log_event("ADD %s -> SKIPPED (stat failed: %s)", src_path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "not a regular file: %s\n", src_path);
        log_event("ADD %s -> SKIPPED (not a regular file)", src_path);
        return -1;
    }
    if ((uint64_t)st.st_size >= MAX_FILE_SIZE) {
        fprintf(stderr,
                "file too large (>= 4GiB, not representable in 4-byte length): %s\n",
                src_path);
        log_event("ADD %s -> SKIPPED (too large, >= 4GiB)", src_path);
        return -1;
    }
    size_t nlen = strlen(stored_name);
    if (nlen == 0 || nlen > MAX_NAME_LEN) {
        fprintf(stderr, "invalid stored name length for %s\n", src_path);
        log_event("ADD %s -> SKIPPED (invalid name length %zu)", src_path, nlen);
        return -1;
    }

    // Запрет дубликатов: имя не должно совпадать ни с уже лежащим в образе,
    // ни с другим именем из текущего запуска. Дубликат пропускаем с
    // предупреждением (остальные файлы добавляются).
    if (joblist_name_exists(jl, stored_name)) {
        fprintf(stderr, "warning: duplicate name skipped: %s (source: %s)\n",
                stored_name, src_path);
        log_event("ADD %s -> SKIPPED (duplicate name, source: %s)",
                  stored_name, src_path);
        jl->skipped_dup++;
        return 0;   // не ошибка — просто пропуск
    }

    if (jl->count == jl->cap) {
        size_t nc = jl->cap ? jl->cap * 2 : 16;
        add_job_t *nj = realloc(jl->jobs, nc * sizeof(add_job_t));
        if (!nj) { fprintf(stderr, "realloc failed\n"); return -1; }
        jl->jobs = nj;
        jl->cap = nc;
    }

    add_job_t *j = &jl->jobs[jl->count];
    memset(j, 0, sizeof(*j));
    j->src_path    = strdup(src_path);
    j->stored_name = strdup(stored_name);
    if (!j->src_path || !j->stored_name) {
        free(j->src_path); free(j->stored_name);
        fprintf(stderr, "strdup failed\n");
        return -1;
    }
    j->file_size = (uint32_t)st.st_size;
    j->name_len  = (uint32_t)nlen;
    generate_salt(j->salt);     // соль на каждый файл — отдельно
    j->offset    = 0;           // вычислим после полного сбора
    j->result    = 0;
    jl->count++;
    return 0;
}

// Колбэк для walk_recursive: добавляет файл в список заданий.
static int collect_job(const char *src_path, const char *stored_name, void *user) {
    job_list_t *jl = (job_list_t*)user;
    if (joblist_add(jl, src_path, stored_name) != 0) {
        // не падаем — пропускаем проблемный файл, остальные обработаем,
        // но запоминаем, что была ошибка сбора (для корректного кода возврата).
        jl->collect_errors++;
        return -1;
    }
    return 0;
}

// -----------------------------------------------------------------------------
// Простая потокобезопасная очередь индексов заданий для прохода 2.
// Воркеры берут индекс следующего задания атомарно (под мьютексом).
// -----------------------------------------------------------------------------
typedef struct {
    job_list_t     *jl;
    int             img_fd;
    size_t          next;        // индекс следующего необработанного задания
    pthread_mutex_t mutex;       // защищает next
} add_pool_t;

// Обрабатывает одно задание: шифрует файл по кусочкам и пишет в образ через
// pwrite в заранее вычисленное смещение. Возвращает 0/-1.
static int process_job(add_job_t *job, int img_fd) {
    // 1) Пишем заголовок: [file_size][name_len][salt] — 24 байта.
    unsigned char header[HEADER_SIZE];
    write_u32_le(header + 0, job->file_size);
    write_u32_le(header + 4, job->name_len);
    memcpy(header + 8, job->salt, SALT_SIZE);

    off_t pos = job->offset;
    ssize_t w = pwrite(img_fd, header, HEADER_SIZE, pos);
    if (w != (ssize_t)HEADER_SIZE) {
        fprintf(stderr, "pwrite header failed for %s: %s\n",
                job->stored_name, strerror(errno));
        return -1;
    }
    pos += HEADER_SIZE;

    // 2) Пишем имя (в открытом виде).
    w = pwrite(img_fd, job->stored_name, job->name_len, pos);
    if (w != (ssize_t)job->name_len) {
        fprintf(stderr, "pwrite name failed for %s: %s\n",
                job->stored_name, strerror(errno));
        return -1;
    }
    pos += job->name_len;

    // 3) Шифруем содержимое ПО КУСОЧКАМ и пишем pwrite. Память — только буфер
    //    одного чанка, независимо от размера файла.
    if (job->file_size == 0)
        return 0;  // пустой файл — содержимого нет

    // Создаём СВОЙ контекст RC4 для этого задания/потока.
    void *ctx = lib_rc4_ctx_create();
    if (!ctx) {
        fprintf(stderr, "rc4_ctx_create failed for %s\n", job->stored_name);
        return -1;
    }
    if (lib_rc4_ctx_init(ctx, job->salt) != 0) {
        fprintf(stderr, "rc4_ctx_init failed for %s\n", job->stored_name);
        lib_rc4_ctx_destroy(ctx);
        return -1;
    }

    FILE *fin = fopen(job->src_path, "rb");
    if (!fin) {
        fprintf(stderr, "fopen(%s): %s\n", job->src_path, strerror(errno));
        lib_rc4_ctx_destroy(ctx);
        return -1;
    }

    unsigned char *buf = malloc(CHUNK_SIZE);
    if (!buf) {
        fprintf(stderr, "malloc(chunk) failed for %s\n", job->src_path);
        fclose(fin);
        lib_rc4_ctx_destroy(ctx);
        return -1;
    }

    int ok = 1;
    uint32_t remaining = job->file_size;
    while (remaining > 0) {
        size_t want = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
        size_t got = fread(buf, 1, want, fin);
        if (got == 0) {
            // файл оказался короче, чем при stat — это ошибка целостности
            fprintf(stderr, "short read on %s (file changed?)\n", job->src_path);
            ok = 0;
            break;
        }
        // Шифруем чанк, продолжая состояние контекста.
        if (lib_rc4_ctx_crypt(ctx, buf, buf, got) != 0) {
            fprintf(stderr, "rc4_ctx_crypt failed for %s\n", job->src_path);
            ok = 0;
            break;
        }
        // Пишем зашифрованный чанк в своё место образа.
        ssize_t ww = pwrite(img_fd, buf, got, pos);
        if (ww != (ssize_t)got) {
            fprintf(stderr, "pwrite data failed for %s: %s\n",
                    job->stored_name, strerror(errno));
            ok = 0;
            break;
        }
        pos += got;
        remaining -= (uint32_t)got;
    }

    free(buf);
    fclose(fin);
    lib_rc4_ctx_destroy(ctx);
    return ok ? 0 : -1;
}

// Рабочий поток прохода 2: берёт индексы заданий из пула, обрабатывает.
static void* add_worker(void *arg) {
    add_pool_t *pool = (add_pool_t*)arg;
    for (;;) {
        if (!keep_running) break;

        // Атомарно берём следующий индекс задания.
        pthread_mutex_lock(&pool->mutex);
        size_t idx = pool->next;
        if (idx >= pool->jl->count) {
            pthread_mutex_unlock(&pool->mutex);
            break;
        }
        pool->next++;
        pthread_mutex_unlock(&pool->mutex);

        add_job_t *job = &pool->jl->jobs[idx];
        job->result = process_job(job, pool->img_fd);
        if (job->result == 0) {
            printf("added: %s (%u bytes)\n", job->stored_name, job->file_size);
            log_event("ADD %s (%u bytes) -> OK", job->stored_name, job->file_size);
        } else {
            log_event("ADD %s -> FAILED", job->stored_name);
        }
    }
    return NULL;
}

// -----------------------------------------------------------------------------
// Команда -add (двухпроходная, с параллельной pwrite-записью)
// -----------------------------------------------------------------------------
static int cmd_add(const char *image_path, char **inputs, int input_count) {
    // Открываем образ на чтение-запись: O_CREAT — создаём, если нет.
    // НЕ используем O_APPEND, потому что пишем pwrite в конкретные смещения.
    int fd = open(image_path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", image_path, strerror(errno));
        return 1;
    }

    // Текущий размер образа = смещение, с которого начнём дописывать новые
    // записи (поддержка добавления в существующий образ).
    off_t base_offset = lseek(fd, 0, SEEK_END);
    if (base_offset == (off_t)-1) {
        fprintf(stderr, "lseek(end): %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    // ---------- ПРОХОД 1: сбор заданий и вычисление смещений ----------
    job_list_t jl;
    memset(&jl, 0, sizeof(jl));

    // Считываем имена, уже лежащие в образе, чтобы запретить дубликаты
    // относительно существующего содержимого. Если образ повреждён — прерываем
    // -add, чтобы не дописывать в битый файл.
    if (joblist_load_existing(&jl, image_path) != 0) {
        fprintf(stderr, "aborting -add due to corrupt existing image\n");
        log_event("ADD ABORTED: corrupt existing image '%s'", image_path);
        for (size_t i = 0; i < jl.existing_count; i++) free(jl.existing[i]);
        free(jl.existing);
        close(fd);
        return 1;
    }

    for (int i = 0; i < input_count && keep_running; i++) {
        const char *in = inputs[i];
        struct stat st;
        if (stat(in, &st) != 0) {
            fprintf(stderr, "stat(%s): %s\n", in, strerror(errno));
            log_event("ADD %s -> SKIPPED (stat failed: %s)", in, strerror(errno));
            jl.collect_errors++;
            continue;
        }
        if (S_ISREG(st.st_mode)) {
            const char *slash = strrchr(in, '/');
            const char *base  = slash ? slash + 1 : in;
            collect_job(in, base, &jl);
        } else if (S_ISDIR(st.st_mode)) {
            // stored_prefix = basename исходной директории (отбросив хвостовые '/'),
            // поэтому для "in/" имена будут вида "in/sub/file.txt".
            char copy[4096];
            strncpy(copy, in, sizeof(copy) - 1);
            copy[sizeof(copy) - 1] = '\0';
            size_t L = strlen(copy);
            while (L > 1 && copy[L-1] == '/') copy[--L] = '\0';
            const char *slash = strrchr(copy, '/');
            const char *base  = slash ? slash + 1 : copy;
            if (base[0] == '\0' || strcmp(base, ".") == 0) base = "root";
            walk_recursive(in, base, collect_job, &jl);
        } else {
            fprintf(stderr, "skip (not file/dir): %s\n", in);
            log_event("ADD %s -> SKIPPED (not file or directory)", in);
            jl.collect_errors++;
        }
    }

    if (jl.count == 0) {
        // Разбираем, почему нечего добавлять:
        //   - были ошибки сбора (файл не найден, не тот тип, слишком большой) —
        //     это реальная ошибка, код возврата 1;
        //   - все кандидаты оказались дубликатами (ошибок сбора не было) —
        //     это нормальный исход, код возврата 0.
        if (jl.collect_errors > 0) {
            fprintf(stderr, "no files added (%d error(s), %d duplicate(s))\n",
                    jl.collect_errors, jl.skipped_dup);
            log_event("ADD: no files added (%d errors, %d duplicates)",
                      jl.collect_errors, jl.skipped_dup);
        } else if (jl.skipped_dup > 0) {
            printf("nothing to add: all %d candidate(s) were duplicates\n",
                   jl.skipped_dup);
            log_event("ADD: nothing to add (all %d were duplicates)", jl.skipped_dup);
        } else {
            fprintf(stderr, "no files to add\n");
            log_event("ADD: no files to add");
        }
        for (size_t i = 0; i < jl.existing_count; i++) free(jl.existing[i]);
        free(jl.existing);
        free(jl.jobs);
        close(fd);
        // Ошибка (1), только если были ошибки сбора. Чистые дубликаты или
        // пустой ввод без ошибок — это не провал.
        return jl.collect_errors > 0 ? 1 : 0;
    }

    // Вычисляем смещение каждой записи: начинаем с конца текущего образа,
    // дальше каждая запись занимает HEADER_SIZE + name_len + file_size.
    off_t cursor = base_offset;
    for (size_t i = 0; i < jl.count; i++) {
        jl.jobs[i].offset = cursor;
        cursor += HEADER_SIZE + jl.jobs[i].name_len + jl.jobs[i].file_size;
    }
    off_t final_size = cursor;

    // Растягиваем образ до итогового размера, чтобы все pwrite-смещения
    // попадали в существующий файл.
    if (ftruncate(fd, final_size) != 0) {
        fprintf(stderr, "ftruncate(%s, %lld): %s\n",
                image_path, (long long)final_size, strerror(errno));
        for (size_t i = 0; i < jl.count; i++) {
            free(jl.jobs[i].src_path); free(jl.jobs[i].stored_name);
        }
        for (size_t i = 0; i < jl.existing_count; i++) free(jl.existing[i]);
        free(jl.existing);
        free(jl.jobs);
        close(fd);
        return 1;
    }

    // ---------- ПРОХОД 2: параллельное шифрование и pwrite ----------
    add_pool_t pool;
    pool.jl = &jl;
    pool.img_fd = fd;
    pool.next = 0;
    pthread_mutex_init(&pool.mutex, NULL);

    // Число потоков = min(MAX_WORKERS, число файлов).
    int nthreads = (jl.count < (size_t)MAX_WORKERS) ? (int)jl.count : MAX_WORKERS;
    pthread_t workers[MAX_WORKERS];
    int started = 0;
    for (int i = 0; i < nthreads; i++) {
        if (pthread_create(&workers[i], NULL, add_worker, &pool) != 0) {
            fprintf(stderr, "pthread_create failed (worker %d)\n", i);
            break;
        }
        started++;
    }

    if (started == 0) {
        // Не удалось создать ни одного потока — обработаем в текущем потоке.
        fprintf(stderr, "warning: running add in current thread (no workers)\n");
        add_worker(&pool);
    } else {
        for (int i = 0; i < started; i++)
            pthread_join(workers[i], NULL);
    }

    pthread_mutex_destroy(&pool.mutex);

    // Подсчёт результатов.
    int added = 0, failed = 0;
    for (size_t i = 0; i < jl.count; i++) {
        if (jl.jobs[i].result == 0) added++;
        else failed++;
    }

    // Откат при сбое: если хотя бы один файл не записался (или операция была
    // прервана по Ctrl+C посреди прохода 2), в образе на месте незаписанных
    // записей осталась бы "дыра" из нулей (файл уже растянут ftruncate до
    // полного размера). Нулевой заголовок сбил бы разметку и сделал образ
    // нечитаемым. Поэтому делаем -add атомарным: при сбое обрезаем образ
    // обратно до base_offset — размера, который он имел ДО этого -add.
    // Для нового образа это 0 (пустой файл), для существующего — возврат к
    // прежнему содержимому без частично добавленных записей.
    int aborted = (failed > 0) || (!keep_running);
    if (aborted) {
        if (ftruncate(fd, base_offset) != 0) {
            fprintf(stderr, "rollback ftruncate(%s, %lld): %s\n",
                    image_path, (long long)base_offset, strerror(errno));
        } else {
            fprintf(stderr,
                    "rollback: image truncated back to %lld bytes "
                    "(no partial records left)\n", (long long)base_offset);
        }
        // Скидываем счётчик успешно добавленных — в образе их больше нет.
        added = 0;
        log_event("ADD ABORTED -> image rolled back to %lld bytes",
                  (long long)base_offset);
    }

    // fsync — гарантия записи (или отката) на диск.
    if (fsync(fd) != 0)
        fprintf(stderr, "fsync(%s): %s\n", image_path, strerror(errno));
    close(fd);

    printf("\n=== ADD SUMMARY ===\n");
    printf("Added:   %d\n", added);
    printf("Failed:  %d\n", failed);
    printf("Skipped: %d (duplicate names)\n", jl.skipped_dup);
    if (jl.collect_errors > 0)
        printf("Errors:  %d (could not be read/collected)\n", jl.collect_errors);
    if (aborted)
        printf("Result:  ABORTED — image rolled back, nothing added\n");

    log_event("ADD SUMMARY: added=%d failed=%d skipped=%d errors=%d%s",
              added, failed, jl.skipped_dup, jl.collect_errors,
              aborted ? " (ABORTED, rolled back)" : "");

    // Освобождаем ресурсы.
    for (size_t i = 0; i < jl.count; i++) {
        free(jl.jobs[i].src_path);
        free(jl.jobs[i].stored_name);
    }
    for (size_t i = 0; i < jl.existing_count; i++)
        free(jl.existing[i]);
    free(jl.existing);
    free(jl.jobs);

    // Ненулевой код возврата, если был откат ИЛИ если какие-то файлы не
    // удалось собрать (например, часть указанных файлов не существует).
    return (aborted || jl.collect_errors > 0) ? 1 : 0;
}


// -----------------------------------------------------------------------------
// Команда -list
//
// Итерируется по записям образа, читая заголовок (24 байта) и имя, после чего
// перепрыгивает содержимое через lseek. Ключ при этом НЕ нужен — имена в
// открытом виде. Список собирается в массив и сортируется по имени.
// -----------------------------------------------------------------------------
typedef struct {
    char    *name;
    uint32_t size;
} list_entry_t;

static int cmp_list_entries(const void *a, const void *b) {
    const list_entry_t *la = (const list_entry_t*)a;
    const list_entry_t *lb = (const list_entry_t*)b;
    return strcmp(la->name, lb->name);
}

static int cmd_list(const char *image_path) {
    int fd = open(image_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", image_path, strerror(errno));
        return 1;
    }

    list_entry_t *entries = NULL;
    size_t cap = 0, n = 0;
    int exit_code = 0;

    for (;;) {
        unsigned char header[HEADER_SIZE]; // создаётся массив на 24 байта Он будет использован для временного хранения считанного заголовка.
        // системный вызов read пытается считать ровно HEADER_SIZE 
        // байт из файла образа (дескриптор fd) в массив header. 
        ssize_t r = read(fd, header, HEADER_SIZE); 
        if (r == 0) break; // EOF — нормальное завершение
        if (r < 0) {
            fprintf(stderr, "read header: %s\n", strerror(errno));
            exit_code = 1; break;
        }
        if (r != HEADER_SIZE) {
            fprintf(stderr, "truncated image (header)\n");
            exit_code = 1; break;
        }

        uint32_t fsize = read_u32_le(header + 0);
        uint32_t nlen  = read_u32_le(header + 4);
        // salt в header+8 нас не интересует при листинге.

        if (nlen == 0 || nlen > MAX_NAME_LEN) {
            fprintf(stderr, "invalid name length in image: %u\n", nlen);
            exit_code = 1; break;
        }

        char *name = malloc((size_t)nlen + 1);
        if (!name) {
            fprintf(stderr, "malloc failed\n");
            exit_code = 1; break;
        }
        r = read(fd, name, nlen);
        if (r != (ssize_t)nlen) {
            fprintf(stderr, "truncated image (name)\n");
            free(name);
            exit_code = 1; break;
        }
        name[nlen] = '\0';

        // Перепрыгиваем зашифрованное содержимое.
        if (lseek(fd, (off_t)fsize, SEEK_CUR) == (off_t)-1) {
            fprintf(stderr, "lseek: %s\n", strerror(errno));
            free(name);
            exit_code = 1; break;
        }

        // Кладём в массив. управляет динамическим массивом записей (структур list_entry_t)
        if (n == cap) {
            // определяет новую вместимость: если cap не ноль, удваиваем; иначе начинаем с 16.
            size_t new_cap = cap ? cap * 2 : 16;
            list_entry_t *ne = realloc(entries, new_cap * sizeof(list_entry_t));
            if (!ne) { free(name); exit_code = 1; break; }
            entries = ne;
            cap = new_cap;
        }
        entries[n].name = name;
        entries[n].size = fsize;
        n++;
    }
    close(fd);

    // Сортировка и вывод.
    if (n > 0) qsort(entries, n, sizeof(list_entry_t), cmp_list_entries);

    for (size_t i = 0; i < n; i++) {
        printf("%10u  %s\n", entries[i].size, entries[i].name);
        free(entries[i].name);
    }
    free(entries);

    return exit_code;
}

// -----------------------------------------------------------------------------
// Команда -get
//
// Ищет запись с указанным именем, читает соль и шифртекст, расшифровывает
// и пишет результат в файл out_path. Если в образе несколько записей с
// одинаковым именем (что формально допустимо), используется ПЕРВАЯ найденная.
// -----------------------------------------------------------------------------
static int cmd_get(const char *image_path, const char *file_name,
                   const char *out_path) {
    int fd = open(image_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", image_path, strerror(errno));
        log_event("GET %s -> ERROR (cannot open image '%s': %s)",
                  file_name, image_path, strerror(errno));
        return 1;
    }

    int found = 0;
    int exit_code = 0;

    for (;;) {
        unsigned char header[HEADER_SIZE];
        ssize_t r = read(fd, header, HEADER_SIZE);
        if (r == 0) break; // EOF
        if (r < 0) {
            fprintf(stderr, "read header: %s\n", strerror(errno));
            exit_code = 1; break;
        }
        if (r != HEADER_SIZE) {
            fprintf(stderr, "truncated image (header)\n");
            exit_code = 1; break;
        }

        uint32_t fsize = read_u32_le(header + 0);
        uint32_t nlen  = read_u32_le(header + 4);
        unsigned char salt[SALT_SIZE];
        memcpy(salt, header + 8, SALT_SIZE);

        if (nlen == 0 || nlen > MAX_NAME_LEN) {
            fprintf(stderr, "invalid name length in image: %u\n", nlen);
            exit_code = 1; break;
        }
        // Выделяем память под имя (плюс байт для завершающего нуля).
        char *name = malloc((size_t)nlen + 1);
        if (!name) { exit_code = 1; break; }
        r = read(fd, name, nlen);
        if (r != (ssize_t)nlen) {
            fprintf(stderr, "truncated image (name)\n");
            free(name); exit_code = 1; break;
        }
        name[nlen] = '\0';

        if (strcmp(name, file_name) == 0) {
            // Найдено — расшифровываем ПО КУСОЧКАМ и пишем в out_path.
            // Память — только буфер одного чанка, независимо от размера файла.
            free(name);

            FILE *fout = fopen(out_path, "wb");
            if (!fout) {
                fprintf(stderr, "fopen(%s): %s\n", out_path, strerror(errno));
                exit_code = 1; break;
            }

            if (fsize > 0) {
                // Создаём контекст RC4 и инициализируем его солью этой записи.
                void *ctx = lib_rc4_ctx_create();
                if (!ctx) {
                    fprintf(stderr, "rc4_ctx_create failed\n");
                    fclose(fout); exit_code = 1; break;
                }
                if (lib_rc4_ctx_init(ctx, salt) != 0) {
                    fprintf(stderr, "rc4_ctx_init failed for %s\n", file_name);
                    lib_rc4_ctx_destroy(ctx); fclose(fout); exit_code = 1; break;
                }

                unsigned char *buf = malloc(CHUNK_SIZE);
                if (!buf) {
                    fprintf(stderr, "malloc(chunk) failed\n");
                    lib_rc4_ctx_destroy(ctx); fclose(fout); exit_code = 1; break;
                }

                uint32_t remaining = fsize;
                int ok = 1;
                while (remaining > 0) {
                    size_t want = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
                    size_t got = 0;
                    while (got < want) {
                        ssize_t k = read(fd, buf + got, want - got);
                        if (k <= 0) {
                            fprintf(stderr, "truncated image (data) or read error\n");
                            ok = 0; break;
                        }
                        got += (size_t)k;
                    }
                    if (!ok) break;
                    // Расшифровываем чанк, продолжая состояние контекста.
                    if (lib_rc4_ctx_crypt(ctx, buf, buf, got) != 0) {
                        fprintf(stderr, "rc4_ctx_crypt failed for %s\n", file_name);
                        ok = 0; break;
                    }
                    if (fwrite(buf, 1, got, fout) != got) {
                        fprintf(stderr, "fwrite(%s): %s\n", out_path, strerror(errno));
                        ok = 0; break;
                    }
                    remaining -= (uint32_t)got;
                }

                free(buf);
                lib_rc4_ctx_destroy(ctx);
                if (!ok) { fclose(fout); exit_code = 1; break; }
            }

            fclose(fout);
            found = 1;
            printf("extracted: %s -> %s (%u bytes)\n", file_name, out_path, fsize);
            log_event("GET %s -> %s (%u bytes) OK", file_name, out_path, fsize);
            break;
        }

        // Не совпало — перепрыгиваем содержимое и идём дальше.
        free(name);
        if (lseek(fd, (off_t)fsize, SEEK_CUR) == (off_t)-1) {
            fprintf(stderr, "lseek: %s\n", strerror(errno));
            exit_code = 1; break;
        }
    }

    close(fd);

    if (!found && exit_code == 0) {
        fprintf(stderr, "file not found in image: %s\n", file_name);
        log_event("GET %s -> NOT FOUND", file_name);
        return 2;
    }
    if (exit_code != 0)
        log_event("GET %s -> ERROR (image read/decrypt/write failed)", file_name);
    return exit_code;
}

// -----------------------------------------------------------------------------
// Загрузка библиотеки libcaesar.so
// -----------------------------------------------------------------------------
static int load_library(void) {
    lib_handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!lib_handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return -1;
    }
    // dlsym Ищут в библиотеке символы с указанными именами и возвращают их адреса (тип void*).
    // В итоге lib_set_master_key теперь указывает на функцию set_master_key из библиотеки.
    *(void **)(&lib_set_master_key) = dlsym(lib_handle, "set_master_key");
    *(void **)(&lib_rc4_ctx_create)  = dlsym(lib_handle, "rc4_ctx_create");
    *(void **)(&lib_rc4_ctx_init)    = dlsym(lib_handle, "rc4_ctx_init");
    *(void **)(&lib_rc4_ctx_crypt)   = dlsym(lib_handle, "rc4_ctx_crypt");
    *(void **)(&lib_rc4_ctx_destroy) = dlsym(lib_handle, "rc4_ctx_destroy");
    if (!lib_set_master_key ||
        !lib_rc4_ctx_create || !lib_rc4_ctx_init ||
        !lib_rc4_ctx_crypt  || !lib_rc4_ctx_destroy) {
        fprintf(stderr, "dlsym: required symbols not found in libcaesar.so\n");
        dlclose(lib_handle);
        lib_handle = NULL;
        return -1;
    }
    // Демо-функции необязательны (могут отсутствовать в старых версиях
    // библиотеки) — отсутствие не является ошибкой загрузки.
    *(void **)(&lib_get_key_ptr)   = dlsym(lib_handle, "get_key_ptr");
    *(void **)(&lib_get_state_ptr) = dlsym(lib_handle, "get_state_ptr");
    return 0;
}

// -----------------------------------------------------------------------------
// Парсинг командной строки и диспетчеризация команд.
// Все флаги вида "-add", "-list", "-get", "-key", "-image", "-out" — именно
// с одной дефисом, как указано в задании.
// -----------------------------------------------------------------------------
static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -add  -key KEY -image IMAGE FILE_OR_DIR ...\n"
        "  %s -list -image IMAGE\n"
        "  %s -get  -image IMAGE -key KEY -out OUT_FILE FILE_NAME\n"
        "\n"
        "Demonstration (optional, must follow the command):\n"
        "  %s -add -key KEY -image IMAGE --demo-attack [key|state] FILE ...\n"
        "      attempt a direct write to protected key/state memory (expects SIGSEGV)\n",
        prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    // Обработчик Ctrl+C — чтобы прервать длительный -add без потери файла образа.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Определяем команду по первому флагу.
    enum { CMD_NONE, CMD_ADD, CMD_LIST, CMD_GET } cmd = CMD_NONE;
    if      (strcmp(argv[1], "-add")  == 0) cmd = CMD_ADD;
    else if (strcmp(argv[1], "-list") == 0) cmd = CMD_LIST;
    else if (strcmp(argv[1], "-get")  == 0) cmd = CMD_GET;
    else { print_usage(argv[0]); return 1; }

    // Открываем лог как можно раньше — чтобы фиксировать в том числе ошибки
    // на этапе разбора аргументов и подготовки (нет ключа, нет образа и т.п.).
    // Логирование не критично: при ошибке открытия просто продолжаем без него.
    log_file = fopen("log.txt", "a");
    if (!log_file)
        fprintf(stderr, "warning: cannot open log.txt: %s\n", strerror(errno));
    log_event("=== START: command='%s' ===", argv[1]);

    // Парсинг остальных аргументов.
    const char *image_path = NULL;
    const char *key_str    = NULL;
    const char *out_path   = NULL;
    int demo_attack = 0;            // 0 — нет; 1 — атака на ключ; 2 — атака на состояние
    char **positional = NULL;
    int positional_count = 0;

    // Выделяем массив под позиционные аргументы максимально возможного размера.
    positional = malloc(sizeof(char*) * argc);
    if (!positional) { fprintf(stderr, "malloc failed\n"); return 1; }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-key") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "-key requires a value\n"); free(positional); return 1; }
            key_str = argv[++i];
        } else if (strcmp(argv[i], "-image") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "-image requires a value\n"); free(positional); return 1; }
            image_path = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "-out requires a value\n"); free(positional); return 1; }
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--demo-attack") == 0) {
            // По умолчанию демонстрируем атаку на ключ. Если следующий аргумент —
            // "key" или "state", уточняем цель (и поглощаем его).
            demo_attack = 1;
            if (i + 1 < argc) {
                if (strcmp(argv[i+1], "key") == 0)        { demo_attack = 1; i++; }
                else if (strcmp(argv[i+1], "state") == 0) { demo_attack = 2; i++; }
            }
        } else if (argv[i][0] == '-' && strlen(argv[i]) > 1) {
            // Любой другой -flag — ошибка.
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            free(positional);
            return 1;
        } else {
            positional[positional_count++] = argv[i];
        }
    }

    if (image_path == NULL) {
        fprintf(stderr, "missing -image\n");
        log_event("ERROR: missing -image -> aborted");
        free(positional); return 1;
    }

    // Команды, требующие ключ и работу с шифрованием, заранее загружают библиотеку.
    if (cmd == CMD_ADD || cmd == CMD_GET) {
        if (key_str == NULL) {
            fprintf(stderr, "missing -key\n");
            log_event("ERROR: missing -key -> aborted");
            free(positional); return 1;
        }
        if (load_library() != 0) {
            log_event("ERROR: cannot load libcaesar.so -> aborted");
            free(positional); return 1;
        }

        // Передаём мастер-ключ в защищённую mmap-область и сразу же затираем
        // локальную копию в argv (это лишь снижает window of exposure: argv
        // всё равно остаётся в /proc/<pid>/cmdline, но это требование к
        // запуску, а не к самой программе).
        size_t klen = strlen(key_str);
        if (lib_set_master_key(key_str, klen) != 0) {
            fprintf(stderr, "set_master_key failed\n");
            log_event("ERROR: set_master_key failed -> aborted");
            dlclose(lib_handle); free(positional); return 1;
        }
        // Затираем строку ключа в argv по месту.
        volatile char *kp = (volatile char*)key_str;
        for (size_t i = 0; i < klen; i++) kp[i] = 0;

        // Демонстрация защиты памяти (перенесено из задания 5).
        // Пытаемся напрямую записать в защищённую область — ключа или состояния
        // шифра. Ожидаемо: ядро шлёт SIGSEGV, обработчик в libcaesar выводит
        // сообщение и завершает программу с кодом 2. Если строка записи всё же
        // выполнилась — защита не сработала (этого быть не должно).
        if (demo_attack) {
            volatile unsigned char *p = NULL;
            const char *what = NULL;
            if (demo_attack == 2) {
                what = "state (S-box)";
                if (lib_get_state_ptr) p = (volatile unsigned char*)lib_get_state_ptr();
                else fprintf(stderr, "[demo-attack] get_state_ptr not available\n");
            } else {
                what = "key";
                if (lib_get_key_ptr) p = (volatile unsigned char*)lib_get_key_ptr();
                else fprintf(stderr, "[demo-attack] get_key_ptr not available\n");
            }

            if (p != NULL) {
                fprintf(stderr,
                    "[demo-attack] Attempting direct write to protected %s at %p ...\n",
                    what, (void*)p);
                log_event("DEMO-ATTACK on %s -> attempting write (expect SIGSEGV)", what);
                fflush(stderr);
                p[0] = 0xFF;   // <-- эта строка вызовет SIGSEGV
                // Сюда попадём только если защита НЕ сработала.
                fprintf(stderr,
                    "[demo-attack] ERROR: write succeeded, protection failed!\n");
                dlclose(lib_handle);
                free(positional);
                return 3;
            }
        }
    }

    int rc = 0;
    switch (cmd) {
        case CMD_ADD:
            if (positional_count < 1) {
                fprintf(stderr, "no input files/dirs for -add\n");
                rc = 1; break;
            }
            rc = cmd_add(image_path, positional, positional_count);
            break;

        case CMD_LIST:
            if (positional_count != 0) {
                fprintf(stderr, "warning: -list ignores positional args\n");
            }
            rc = cmd_list(image_path);
            break;

        case CMD_GET:
            if (out_path == NULL) {
                fprintf(stderr, "missing -out\n"); rc = 1; break;
            }
            if (positional_count != 1) {
                fprintf(stderr, "-get requires exactly one file name argument\n");
                rc = 1; break;
            }
            rc = cmd_get(image_path, positional[0], out_path);
            break;

        default:
            print_usage(argv[0]); rc = 1; break;
    }

    free(positional);
    log_event("=== END: command='%s' exit_code=%d ===", argv[1], rc);
    if (log_file) fclose(log_file);
    if (lib_handle) dlclose(lib_handle);
    return rc;
}
