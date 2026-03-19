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

static volatile sig_atomic_t keep_running = 1;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *log_file = NULL;

static int total_files = 0;
static char **file_list = NULL;
static const char *out_dir = NULL;
static char key = 0;

static set_key_fn set_key = NULL;
static caesar_fn caesar = NULL;
static void *lib_handle = NULL;

static int next_file_idx = 0;
static int completed_files = 0;

static const char* get_basename(const char *path) {
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static void sig_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

static int lock_with_timeout(pthread_mutex_t *m, const char *thread_id) {
    struct timespec ts;
    int ret;

    while (keep_running) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;

        ret = pthread_mutex_timedlock(m, &ts);

        if (ret == 0) return 0;

        if (ret == ETIMEDOUT) {
            fprintf(stderr, "[WARNING] %s: possible deadlock (>5s)\n", thread_id);
            continue;
        }

        if (ret == EINTR) continue;

        fprintf(stderr, "mutex error: %d\n", ret);
        return -1;
    }
    return -1;
}

static void get_timestamp(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

static void* worker_thread(void *arg) {
    (void)arg;

    char thread_id[32];
    snprintf(thread_id, sizeof(thread_id), "Thread %lu",
             (unsigned long)pthread_self());

    while (keep_running) {
        if (lock_with_timeout(&mutex, thread_id) != 0)
            break;

        int idx = next_file_idx;

        if (idx >= total_files) {
            pthread_mutex_unlock(&mutex);
            break;
        }

        next_file_idx++;
        char *filename = file_list[idx];

        pthread_mutex_unlock(&mutex);

        // --- ВАЖНО: только basename ---
        const char *base = get_basename(filename);

        char out_path[512];
        snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, base);

        // DEBUG (можешь удалить потом)
        printf("IN: %s -> OUT: %s\n", filename, out_path);

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        FILE *fin = fopen(filename, "rb");

        int success = 0;
        char result_str[32] = "success";

        if (!fin) {
            perror(filename);
            success = -1;
            strcpy(result_str, "error(open)");
        } else {
            fseek(fin, 0, SEEK_END);
            long fsize = ftell(fin);
            fseek(fin, 0, SEEK_SET);

            unsigned char *buffer = malloc(fsize);

            if (!buffer) {
                perror("malloc");
                success = -1;
                strcpy(result_str, "error(malloc)");
            } else {
                fread(buffer, 1, fsize, fin);

                caesar(buffer, buffer, fsize);

                FILE *fout = fopen(out_path, "wb");

                if (!fout) {
                    perror(out_path);
                    success = -1;
                    strcpy(result_str, "error(create)");
                } else {
                    fwrite(buffer, 1, fsize, fout);
                    fclose(fout);
                }

                free(buffer);
            }

            fclose(fin);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);

        double elapsed =
            (end.tv_sec - start.tv_sec) +
            (end.tv_nsec - start.tv_nsec) / 1e9;

        if (lock_with_timeout(&mutex, thread_id) != 0)
            break;

        if (success == 0)
            completed_files++;

        char timestamp[64];
        get_timestamp(timestamp, sizeof(timestamp));

        fprintf(log_file,
                "[%s] %s processed %s (%s) in %.3f sec\n",
                timestamp, thread_id, filename, result_str, elapsed);

        fflush(log_file);

        pthread_mutex_unlock(&mutex);
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s file1 ... fileN outdir key\n", argv[0]);
        return 1;
    }

    int num_files = argc - 2;

    out_dir = argv[num_files];
    const char *key_str = argv[num_files + 1];

    char *endptr;
    long num_key = strtol(key_str, &endptr, 10);

    if (*endptr == '\0' && num_key >= 0 && num_key <= 255)
        key = (char)num_key;
    else
        key = key_str[0];

    lib_handle = dlopen("./libcaesar.so", RTLD_LAZY);
    if (!lib_handle) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    *(void **)(&set_key) = dlsym(lib_handle, "set_key");
    *(void **)(&caesar)  = dlsym(lib_handle, "caesar");

    if (!set_key || !caesar) {
        fprintf(stderr, "dlsym failed\n");
        return 1;
    }

    set_key(key);

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

    total_files = num_files - 1;
    file_list = &argv[1];

    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    pthread_t threads[3];

    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }

    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    if (lock_with_timeout(&mutex, "Main") == 0) {
        char timestamp[64];
        get_timestamp(timestamp, sizeof(timestamp));

        fprintf(log_file,
                "[%s] All threads finished. Total: %d\n",
                timestamp, completed_files);

        pthread_mutex_unlock(&mutex);
    }

    fclose(log_file);
    dlclose(lib_handle);
    pthread_mutex_destroy(&mutex);

    return 0;
}