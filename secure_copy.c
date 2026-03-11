//исходный код программы (задание №2)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <mqueue.h>
#include <fcntl.h>      // для O_CREAT и т.п.

// Функции из библиотеки libcaesar
extern void set_key(char key);
extern void caesar(void* src, void* dst, int len);

#define BLOCK_SIZE 16
#define QUEUE_NAME "/secure_copy_q"
#define QUEUE_DEPTH 8   // глубина очереди (ограниченный буфер)

typedef struct {
    char data[BLOCK_SIZE];
    int  len;           // количество байт данных (0 – особый случай)
    int  eof;           // флаг конца файла (1 – завершение)
} Chunk;

static volatile sig_atomic_t keep_running = 1;
static const char *out_path = NULL;   // для удаления файла при прерывании
static mqd_t mq;                       // дескриптор очереди

// Обработчик SIGINT
static void sigint_handler(int sig) {
    (void)sig;
    keep_running = 0;
    // Отправляем пустой «ядовитый» элемент, чтобы разбудить consumer
    Chunk poison = { .len = 0, .eof = 1 };
    mq_send(mq, (const char*)&poison, sizeof(Chunk), 0);
    // Примечание: mq_send может не успеть выполниться мгновенно,
    // но это нормально – main потом дождётся завершения потоков.
}

// Поток-производитель (чтение + шифрование)
void* producer_thread(void* arg) {
    FILE* fin = (FILE*)arg;
    while (keep_running) {
        Chunk chunk;
        memset(&chunk, 0, sizeof(chunk));
        chunk.len = fread(chunk.data, 1, BLOCK_SIZE, fin);
        if (chunk.len == 0) {
            // Конец файла – отправляем маркер завершения
            chunk.eof = 1;
            mq_send(mq, (const char*)&chunk, sizeof(Chunk), 0);
            break;
        }
        // Шифруем блок
        caesar(chunk.data, chunk.data, chunk.len);
        chunk.eof = 0;
        // Отправляем в очередь. Если очередь полна, mq_send заблокируется.
        // При сигнале keep_running станет 0, и мы должны выйти.
        // Можно использовать неблокирующий режим, но для простоты оставим блокировку.
        while (1) {
            int ret = mq_send(mq, (const char*)&chunk, sizeof(Chunk), 0);
            if (ret == 0) break;
            if (errno == EINTR) {
                // Сигнал прервал mq_send – проверяем keep_running
                if (!keep_running) {
                    return NULL;
                }
                continue; // пробуем снова
            }
            // Другая ошибка – выходим
            perror("mq_send");
            return NULL;
        }
    }
    return NULL;
}

// Поток-потребитель (запись в выходной файл)
void* consumer_thread(void* arg) {
    FILE* fout = (FILE*)arg;
    while (keep_running) {
        Chunk chunk;
        ssize_t received = mq_receive(mq, (char*)&chunk, sizeof(Chunk), NULL);
        if (received == -1) {
            if (errno == EINTR) {
                // Сигнал – проверяем keep_running
                continue;
            }
            perror("mq_receive");
            break;
        }
        if (chunk.eof) {
            break;  // конец файла
        }
        if (chunk.len > 0) {
            fwrite(chunk.data, 1, chunk.len, fout);
        }
    }
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <input> <output> <key>\n", argv[0]);
        return 1;
    }

    const char* infile = argv[1];
    const char* outfile = argv[2];
    const char* key_arg = argv[3];

    // --- разбор ключа (число или символ) ---
    char key;
    char* endptr;
    long num_key = strtol(key_arg, &endptr, 10);
    if (*endptr == '\0' && num_key >= 0 && num_key <= 255)
        key = (char)num_key;
    else
        key = key_arg[0];

    // --- открытие файлов ---
    FILE* fin = fopen(infile, "rb");
    if (!fin) {
        perror("fopen input");
        return 1;
    }

    FILE* fout = fopen(outfile, "wb");
    if (!fout) {
        perror("fopen output");
        fclose(fin);
        return 1;
    }

    // --- установка ключа в библиотеке ---
    set_key(key);

    // --- создание очереди сообщений ---
    struct mq_attr attr = {
        .mq_flags = 0,
        .mq_maxmsg = QUEUE_DEPTH,
        .mq_msgsize = sizeof(Chunk)
    };
    mq = mq_open(QUEUE_NAME, O_CREAT | O_RDWR, 0600, &attr);
    if (mq == (mqd_t)-1) {
        perror("mq_open");
        fclose(fin);
        fclose(fout);
        return 1;
    }

    // --- установка обработчика SIGINT ---
    out_path = outfile;  // запоминаем для возможного удаления
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        mq_close(mq);
        mq_unlink(QUEUE_NAME);
        fclose(fin);
        fclose(fout);
        return 1;
    }

    // --- создание потоков ---
    pthread_t producer, consumer;
    pthread_create(&producer, NULL, producer_thread, fin);
    pthread_create(&consumer, NULL, consumer_thread, fout);

    // --- ожидание завершения ---
    pthread_join(producer, NULL);
    pthread_join(consumer, NULL);

    // --- очистка ---
    fclose(fin);
    fclose(fout);
    mq_close(mq);
    mq_unlink(QUEUE_NAME);

    if (!keep_running) {
        // При прерывании удаляем выходной файл (чтобы не оставался мусор)
        remove(outfile);
        printf("Операция прервана пользователем\n");
        return 1;
    }

    return 0;
}