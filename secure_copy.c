#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef void (*set_key_fn)(char);
typedef void (*caesar_fn)(void*, void*, int);
typedef void* (*get_key_ptr_fn)(void); // получение указателя на защищённую область (для демонстрации)

/* Количество потоков по умолчанию (можно переопределить при сборке) */
#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif

static volatile sig_atomic_t keep_running = 1;
static FILE *log_file = NULL;

static set_key_fn set_key = NULL;
static caesar_fn caesar = NULL;
static get_key_ptr_fn get_key_ptr = NULL; // для демонстрации попытки записи в защищённую память
static void *lib_handle = NULL;

/* Возвращает указатель на имя файла без ведущего пути (basename) */
static const char* get_basename(const char *path) {
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/* Обработчик Ctrl+C: сбрасывает глобальный флаг продолжения работы */
static void sig_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

/* Записывает в buf текущее локальное время в формате ГГГГ-ММ-ДД ЧЧ:ММ:СС */
static void get_timestamp(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* Статистика по одному обработанному файлу */
typedef struct {
    char filename[512]; //имя файла
    double time_taken; // затраченное время в секундах
    int success; // 0 = успех, иначе код ошибки
} file_stat_t;

// Структуры для параллельного пула (используются только при num_threads > 1)

typedef struct {
    char **files; // массив указателей на имена обрабатываемых файлов
    int total;  // максимальная ёмкость очереди (равна количеству файлов)
    int head; // индекс первого элемента (откуда извлекают)
    int tail;  // индекс для следующего добавляемого элемента (куда кладут)
    int count; // текущее число элементов в очереди
    int done; // флаг, означающий, что новые файлы больше добавляться не будут
    pthread_mutex_t mutex; // мьютекс для защиты полей структуры
    pthread_cond_t cond; // условная переменная для ожидания/уведомления о появлении/освобождении задач
} task_queue_t;

// Инициализирует очередь задач для параллельного пула.
static void queue_init(task_queue_t *q, char **files, int total) {
    q->files = files;
    q->total = total;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->done = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

// Уничтожает мьютекс и условную переменную очереди (очистка ресурсов)
static void queue_destroy(task_queue_t *q) {
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

// Добавляет имя файла в очередь задач (с блокировкой при переполнении)
static void queue_push(task_queue_t *q, const char *filename) {
    pthread_mutex_lock(&q->mutex);
    while (q->count >= q->total && !q->done)
        pthread_cond_wait(&q->cond, &q->mutex);
    q->files[q->tail] = (char*)filename;
    q->tail = (q->tail + 1) % q->total;
    q->count++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

// Извлекает имя файла из очереди (блокируется, если очередь пуста)
// Возвращает NULL, когда очередь опустела и помечена как завершённая (done)
static char* queue_pop(task_queue_t *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0 && !q->done)
        pthread_cond_wait(&q->cond, &q->mutex);
    if (q->count == 0 && q->done) {
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }
    char *filename = q->files[q->head];
    q->head = (q->head + 1) % q->total;
    q->count--;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
    return filename;
}

// Устанавливает флаг завершения очереди и оповещает все ожидающие потоки
static void queue_set_done(task_queue_t *q) {
    pthread_mutex_lock(&q->mutex);
    q->done = 1;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

// Обработка одного файла (без параметра key, т.к. ключ уже установлен глобально)
// Обрабатывает один файл: читает, шифрует (XOR с глобально установленным ключом)
// записывает результат в out_dir, замеряет время выполнения и пишет запись в лог
// Возвращает затраченное время в секундах, через success возвращает статус (0 – ОК)
// Размер чанка для потоковой обработки файла.
// Файл шифруется не целиком, а кусками по CHUNK_SIZE байт. Это даёт двум
// важным эффектам:
//   1) меньше памяти на поток (нужен буфер CHUNK_SIZE, а не размер файла);
//   2) между чанками поток отпускает мьютекс ключа, что позволяет другим
//      потокам успеть поработать с ключом — частичная параллельность.
#define CHUNK_SIZE (64 * 1024)   // 64 КБ — компромисс между гранулярностью и накладными расходами

static double process_one_file(const char *filename, const char *out_dir, int *success) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Формирование выходного пути и запись результата
    const char *base = get_basename(filename);
    char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, base); // <-- формируем путь вида "out_dir/имя_файла"

    printf("Processing: %s -> %s\n", filename, out_path);

    FILE *fin = fopen(filename, "rb"); // <-- открываем входной файл
    *success = 0;
    char result_str[32] = "success";

    if (!fin) {
        perror(filename);
        *success = -1;
        strcpy(result_str, "error(open)");
    } else {
        FILE *fout = fopen(out_path, "wb");
        if (!fout) {
            perror(out_path);
            *success = -1;
            strcpy(result_str, "error(create)");
            fclose(fin);
        } else {
            // Буфер для одного чанка (выделяется один раз на весь файл)
            unsigned char *buffer = malloc(CHUNK_SIZE);
            if (!buffer) {
                perror("malloc");
                *success = -1;
                strcpy(result_str, "error(malloc)");
            } else {
                // Потоковая обработка файла чанками по CHUNK_SIZE байт.
                // Каждый вызов caesar() — короткий захват мьютекса в библиотеке,
                // между чанками другой поток может вклиниться и поработать.
                size_t bytes_read;
                while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, fin)) > 0) {
                    caesar(buffer, buffer, (int)bytes_read);   // <-- шифруем один чанк
                    if (fwrite(buffer, 1, bytes_read, fout) != bytes_read) {
                        perror("fwrite");
                        *success = -1;
                        strcpy(result_str, "error(write)");
                        break;
                    }
                }
                free(buffer);
            }
            fclose(fout);
            fclose(fin);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file,
            "[%s] %s processed %s (%s) in %.3f sec\n",
            timestamp, filename, filename, result_str, elapsed); // <-- пишем в log.txt
    fflush(log_file); // <-- сбрасываем буфер

    return elapsed;
}


// Аргументы, передаваемые каждому рабочему потоку в параллельном режиме
typedef struct {
    task_queue_t *queue; // указатель на общую очередь задач (файлы для обработки)
    const char *out_dir; // выходной каталог для сохранения зашифрованных файлов
    file_stat_t *stats; // массив для записи статистики по каждому обработанному файлу
    int *next_stat_idx; // общий счётчик для определения индекса записи в stats
    pthread_mutex_t *stat_mutex; // мьютекс для защиты next_stat_idx при конкурентном доступе
} worker_arg_t;

// Функция рабочего потока в параллельном режиме
static void* parallel_worker(void *arg) {
    worker_arg_t *warg = (worker_arg_t*)arg;
    task_queue_t *q = warg->queue;
    const char *out_dir = warg->out_dir;
    file_stat_t *stats = warg->stats;
    int *next_idx = warg->next_stat_idx;
    pthread_mutex_t *stat_mutex = warg->stat_mutex;

    while (keep_running) {
        char *filename = queue_pop(q); // получить следующий файл (блокируется при пустой очереди)
        if (!filename) break; // очередь завершена – выход из потока

        int success;
        double t = process_one_file(filename, out_dir, &success); // обработка файла
        
        // Безопасное сохранение статистики: общий индекс защищён мьютексом
        pthread_mutex_lock(stat_mutex);
        int idx = *next_idx;
        (*next_idx)++;
        pthread_mutex_unlock(stat_mutex);

        stats[idx].time_taken = t;
        stats[idx].success = success;
        strncpy(stats[idx].filename, filename, sizeof(stats[idx].filename)-1);
    }
    return NULL;
}

// Единая функция обработки
static double run_with_threads(int num_threads, int file_count, char *file_list[],
                               const char *out_dir, file_stat_t *stats) {
    if (num_threads == 1) {
        // Последовательный режим (без накладных расходов)
        printf("\n=== SEQUENTIAL MODE ===\n");
        struct timespec total_start, total_end;
        clock_gettime(CLOCK_MONOTONIC, &total_start);

        for (int i = 0; i < file_count && keep_running; i++) {
            int success;
            double t = process_one_file(file_list[i], out_dir, &success);
            if (stats) {
                stats[i].time_taken = t;
                stats[i].success = success;
                strncpy(stats[i].filename, file_list[i], sizeof(stats[i].filename)-1);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &total_end);
        double total_time = (total_end.tv_sec - total_start.tv_sec) +
                            (total_end.tv_nsec - total_start.tv_nsec) / 1e9;

        int success_count = 0;
        if (stats)
            for (int i = 0; i < file_count; i++)
                if (stats[i].success == 0) success_count++;

        printf("Total files: %d\n", file_count);
        printf("Successfully processed: %d\n", success_count);
        printf("Total time: %.3f sec\n", total_time);
        printf("Average per file: %.3f sec\n", total_time / file_count);
        return total_time;
    } else {
        // Параллельный режим с пулом потоков
        printf("\n=== PARALLEL MODE (max %d threads) ===\n", num_threads);

        task_queue_t queue;
        queue_init(&queue, file_list, file_count); // <-- создаём очередь, общую для всех потоков

        for (int i = 0; i < file_count; i++)
            queue_push(&queue, file_list[i]); // <-- кладём все файлы в общую очередь
        queue_set_done(&queue); // <-- помечаем, что новых файлов не будет

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        worker_arg_t warg;
        warg.queue = &queue;
        warg.out_dir = out_dir;
        warg.stats = stats;
        int stat_idx = 0;
        warg.next_stat_idx = &stat_idx;
        pthread_mutex_t stat_mutex = PTHREAD_MUTEX_INITIALIZER;
        warg.stat_mutex = &stat_mutex;

        struct timespec total_start, total_end;
        clock_gettime(CLOCK_MONOTONIC, &total_start);

        for (int i = 0; i < num_threads; i++)
            pthread_create(&threads[i], NULL, parallel_worker, &warg);

        for (int i = 0; i < num_threads; i++)
            pthread_join(threads[i], NULL);

        clock_gettime(CLOCK_MONOTONIC, &total_end);
        double total_time = (total_end.tv_sec - total_start.tv_sec) +
                            (total_end.tv_nsec - total_start.tv_nsec) / 1e9;

        int success_count = 0;
        for (int i = 0; i < file_count; i++)
            if (stats[i].success == 0) success_count++;

        printf("Total files: %d\n", file_count);
        printf("Successfully processed: %d\n", success_count);
        printf("Total time: %.3f sec\n", total_time);
        printf("Average per file: %.3f sec\n", total_time / file_count);

        free(threads);
        queue_destroy(&queue);
        pthread_mutex_destroy(&stat_mutex);
        return total_time;
    }
}

// сравнительная таблица
static void print_comparison(int file_count,
                             double time_chosen, const char *chosen_mode,
                             double time_alt, const char *alt_mode) {
    printf("\n=== COMPARISON ===\n");
    printf("Files processed: %d\n", file_count);
    printf("%-12s : %.3f sec\n", chosen_mode, time_chosen);
    printf("%-12s : %.3f sec\n", alt_mode, time_alt);
    if (time_chosen > 0) {
        printf("Speedup (alt / chosen) : %.2fx\n", time_alt / time_chosen);
    }
}

int main(int argc, char *argv[]) {
    int arg_offset = 1;
    enum { MODE_AUTO, MODE_SEQUENTIAL, MODE_PARALLEL } mode = MODE_AUTO;
    int demo_attack = 0; // если 1 — после установки ключа выполняется попытка записи в защищённую память (для демонстрации)

    // Разбор опциональных флагов в начале командной строки.
    // Поддерживаются (в любом порядке):
    //   --mode=sequential|parallel
    //   --demo-attack       — продемонстрировать попытку записи в защищённую память
    while (argc > arg_offset && strncmp(argv[arg_offset], "--", 2) == 0) {
        if (strncmp(argv[arg_offset], "--mode=", 7) == 0) {
            const char *mode_str = argv[arg_offset] + 7;
            if (strcmp(mode_str, "sequential") == 0) {
                mode = MODE_SEQUENTIAL;
            } else if (strcmp(mode_str, "parallel") == 0) {
                mode = MODE_PARALLEL;
            } else {
                fprintf(stderr, "Unknown mode: %s\n", mode_str);
                return 1;
            }
        } else if (strcmp(argv[arg_offset], "--demo-attack") == 0) {
            demo_attack = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[arg_offset]);
            return 1;
        }
        arg_offset++;
    }

    if (argc - arg_offset < 3) {
        fprintf(stderr,
            "Usage: %s [--mode=sequential|parallel] [--demo-attack] file1 ... fileN outdir key\n",
            argv[0]);
        return 1;
    }

    int file_count = argc - arg_offset - 2;
    if (file_count < 1) {
        fprintf(stderr, "Error: at least one input file required\n");
        return 1;
    }

    char **file_list = &argv[arg_offset];
    const char *out_dir = argv[argc - 2];
    const char *key_str = argv[argc - 1];

    // Разбор ключа из строки. Ключ существует в локальной переменной только
    // на время вызова set_key() — далее он живёт исключительно в защищённой
    // mmap-области внутри libcaesar (по требованию задания: "запрещается
    // хранить ключ в обычных переменных").
    char key_local;
    {
        char *endptr;
        long num_key = strtol(key_str, &endptr, 10);
        if (*endptr == '\0' && num_key >= 0 && num_key <= 255)
            key_local = (char)num_key;
        else
            key_local = key_str[0];
    }

    int is_auto = (mode == MODE_AUTO);

    int chosen_threads;
    const char *chosen_mode_name;
    if (is_auto) {
        // < 5 файлов – 1 поток (sequential), иначе WORKERS_COUNT потоков (parallel)
        chosen_threads = (file_count < 5) ? 1 : WORKERS_COUNT;
        chosen_mode_name = (chosen_threads == 1) ? "sequential" : "parallel";
        printf("Auto mode: %d files -> %s\n", file_count, chosen_mode_name);
    } else {
        chosen_threads = (mode == MODE_SEQUENTIAL) ? 1 : WORKERS_COUNT;
        chosen_mode_name = (mode == MODE_SEQUENTIAL) ? "sequential" : "parallel";
    }

    lib_handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!lib_handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    *(void **)(&set_key) = dlsym(lib_handle, "set_key");
    *(void **)(&caesar)  = dlsym(lib_handle, "caesar");
    *(void **)(&get_key_ptr) = dlsym(lib_handle, "get_key_ptr"); // может отсутствовать в старых версиях, не критично
    if (!set_key || !caesar) {
        fprintf(stderr, "dlsym failed\n");
        dlclose(lib_handle);
        return 1;
    }

    // Передаём ключ в библиотеку, где он немедленно копируется в защищённую
    // mmap-область, после чего права страницы аннулируются (PROT_NONE).
    set_key(key_local);
    // Затираем локальную копию ключа в стеке — теперь ключ существует
    // ТОЛЬКО внутри защищённой памяти библиотеки.
    *(volatile char*)&key_local = 0;

    // Демонстрация защиты памяти (по требованию задания):
    // "продемонстрировать попытку записи в защищённую память".
    // Если флаг --demo-attack установлен, пытаемся напрямую модифицировать
    // байт ключа через возвращённый указатель. Ожидаемо: ядро отправит
    // SIGSEGV, обработчик в libcaesar выведет сообщение и завершит
    // программу с ненулевым кодом возврата.
    if (demo_attack) {
        if (!get_key_ptr) {
            fprintf(stderr, "[demo-attack] get_key_ptr not available in library\n");
        } else {
            volatile unsigned char *p = (volatile unsigned char*)get_key_ptr();
            fprintf(stderr,
                "[demo-attack] Attempting direct write to protected memory at %p ...\n",
                (void*)p);
            fflush(stderr);
            p[0] = 0xFF; // <-- эта строка вызовет SIGSEGV
            // Если мы здесь оказались — защита не сработала (этого не должно быть)
            fprintf(stderr, "[demo-attack] ERROR: write succeeded, protection failed!\n");
            return 3;
        }
    }

    struct stat st = {0};
    if (stat(out_dir, &st) == -1) {
        if (mkdir(out_dir, 0755) != 0) {
            perror("mkdir");
            return 1;
        }
    }

    log_file = fopen("log.txt", "a");
    if (!log_file) {
        perror("log.txt");
        return 1;
    }

    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    file_stat_t *stats = calloc(file_count, sizeof(file_stat_t));
    if (!stats) {
        perror("calloc");
        return 1;
    }

    double time_chosen, time_alt;

    time_chosen = run_with_threads(chosen_threads, file_count, file_list, out_dir, stats);

    if (is_auto) {
        char alt_out_dir[512];
        snprintf(alt_out_dir, sizeof(alt_out_dir), "%s_alt", out_dir);
        if (mkdir(alt_out_dir, 0755) != 0 && errno != EEXIST) {
            perror("mkdir alt_out_dir");
        }

        memset(stats, 0, file_count * sizeof(file_stat_t));
        keep_running = 1;

        int alt_threads = (chosen_threads == 1) ? WORKERS_COUNT : 1;
        const char *alt_mode_name = (alt_threads == 1) ? "sequential" : "parallel";

        printf("\n--- Running alternative mode (%s) for comparison ---\n", alt_mode_name);

        time_alt = run_with_threads(alt_threads, file_count, file_list, alt_out_dir, stats);

        print_comparison(file_count, time_chosen, chosen_mode_name, time_alt, alt_mode_name);
    }

    free(stats);
    fclose(log_file);
    dlclose(lib_handle);

    return 0;
}