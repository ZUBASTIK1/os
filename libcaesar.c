// Исходный код библиотеки (XOR) с защитой ключа в памяти (задание 5)
//
// Ключ шифрования хранится в области памяти, выделенной через mmap
// с флагами MAP_PRIVATE | MAP_ANONYMOUS. Размер защищённой области — 16 байт.
// После записи ключа права на страницу понижаются до PROT_READ, что не даёт
// модифицировать ключ напрямую. Попытка записи приводит к SIGSEGV, который
// перехватывается собственным обработчиком (sigaction).

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>     // мьютекс для синхронизации доступа к защищённой памяти

#define KEY_SIZE 16  // размер защищённой области (по заданию)

// Указатель на защищённую страницу с ключом. NULL означает, что ключ ещё не
// инициализирован (set_key не вызывался).
static unsigned char *g_key_page = NULL;

// Мьютекс для синхронизации доступа к защищённой памяти.
// Нужен, потому что между использованиями ключа права страницы понижаются
// до PROT_NONE (полный запрет даже на чтение). Без мьютекса возможна гонка:
// один поток ставит PROT_NONE, другой в это же время ещё читает ключ
// и получает SIGSEGV. Мьютекс гарантирует, что только один поток работает
// с защищённой памятью в любой момент времени.
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

// Флаг, что обработчик SIGSEGV уже установлен (ставится один раз)
static int g_sigsegv_installed = 0;

// Обработчик SIGSEGV. Выводит информативное сообщение и завершает программу
// с ненулевым кодом возврата. Используются только async-signal-safe функции
// (write, _exit), потому что вызов из обработчика сигнала.
//
// Различает попытку записи в защищённую область ключа от других ошибок
// доступа (например, обращение к освобождённой памяти), используя si_addr
// из siginfo_t.
static void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig;
    (void)ucontext;

    static const char msg_key[] =
        "[SECURITY] SIGSEGV: attempt to modify protected key memory detected. "
        "Terminating.\n";
    static const char msg_other[] =
        "[SECURITY] SIGSEGV: invalid memory access (not in key region). "
        "Terminating.\n";

    // Проверяем, попадает ли адрес доступа в область защищённой страницы.
    // Если да — это легитимно перехваченная попытка модифицировать ключ.
    if (info != NULL && g_key_page != NULL &&
        (unsigned char*)info->si_addr >= g_key_page &&
        (unsigned char*)info->si_addr <  g_key_page + KEY_SIZE) {
        write(STDERR_FILENO, msg_key, sizeof(msg_key) - 1);
    } else {
        write(STDERR_FILENO, msg_other, sizeof(msg_other) - 1);
    }

    _exit(2);
}

// Установка обработчика SIGSEGV через sigaction (надёжнее, чем signal).
// Используем SA_SIGINFO, чтобы получить siginfo_t с адресом доступа.
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

// Освобождение защищённой памяти с предварительным затиранием нулями.
// Алгоритм по заданию: расширить права до PROT_READ|PROT_WRITE,
// заполнить нулями memset'ом, вернуть к исходным правам (PROT_NONE),
// освободить через munmap.
// Регистрируется через atexit() в set_key, поэтому будет вызвана при
// любом штатном завершении программы.
static void cleanup_key(void) {
    if (g_key_page == NULL) return;

    // Временно расширяем права до RW для затирания
    if (mprotect(g_key_page, KEY_SIZE, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect (cleanup RW)");
        // даже в случае ошибки попробуем освободить
    } else {
        memset(g_key_page, 0, KEY_SIZE);          // <-- затирание ключа нулями
        // Возвращаем к исходным правам — PROT_NONE (как было до cleanup)
        if (mprotect(g_key_page, KEY_SIZE, PROT_NONE) != 0) {
            perror("mprotect (cleanup NONE)");
        }
    }

    if (munmap(g_key_page, KEY_SIZE) != 0) {      // <-- освобождение памяти
        perror("munmap");
    }
    g_key_page = NULL;
}

// Устанавливает ключ шифрования в защищённую область памяти.
// По заданию:
//   1) выделить память через mmap (PROT_READ|PROT_WRITE для записи);
//   2) установить права на запись (mprotect PROT_READ|PROT_WRITE);
//   3) скопировать ключ через memcpy;
//   4) аннулировать права (mprotect PROT_NONE — "запрещающие доступ").
// Дополнительно при первом вызове:
//   - устанавливается обработчик SIGSEGV;
//   - регистрируется cleanup_key через atexit.
void set_key(char key) {
    if (g_key_page == NULL) {
        // Первый вызов — выделение памяти под ключ.
        // Базовая конфигурация защиты: PROT_READ|PROT_WRITE для начальной записи.
        g_key_page = mmap(NULL, KEY_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_key_page == MAP_FAILED) {
            perror("mmap");
            g_key_page = NULL;
            exit(1);
        }

        // Инициализация области нулями (на случай, если ключ короче KEY_SIZE)
        memset(g_key_page, 0, KEY_SIZE);

        // Первый mprotect — явная установка прав записи перед записью ключа
        // (по заданию: "Затем устанавливаются права на запись: mprotect(...)").
        if (mprotect(g_key_page, KEY_SIZE, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect (init RW)");
            exit(1);
        }

        // Установка обработчика SIGSEGV до того, как страница станет read-only
        if (install_sigsegv_handler() != 0) {
            exit(1);
        }

        // Гарантируем затирание ключа при штатном завершении программы
        if (atexit(cleanup_key) != 0) {
            fprintf(stderr, "atexit registration failed\n");
            exit(1);
        }
    } else {
        // Повторный вызов set_key — нужно временно открыть запись
        // (это и есть "перед использованием для записи").
        if (mprotect(g_key_page, KEY_SIZE, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect (set_key RW)");
            exit(1);
        }
    }

    // Запись ключа в защищённую область через memcpy (по заданию)
    unsigned char k = (unsigned char)key;
    memcpy(g_key_page, &k, 1);                    // <-- копируем ключ в mmap-область

    // Полное закрытие доступа: страница становится PROT_NONE между использованиями.
    // При каждом вызове caesar() права будут временно расширяться и снова закрываться.
    if (mprotect(g_key_page, KEY_SIZE, PROT_NONE) != 0) {
        perror("mprotect (set_key NONE)");
        exit(1);
    }

    // Локальная переменная k удаляется со стека по выходу из функции,
    // ключ остаётся только в защищённой mmap-области.
    k = 0;
}

// XOR-шифрование/дешифрование с использованием защищённого ключа.
//
// Алгоритм безопасной работы с ключом (по заданию):
//   1) захватываем мьютекс (только один поток в данный момент);
//   2) расширяем права страницы до PROT_READ (только чтение, по заданию);
//   3) шифруем данные с прямым обращением к защищённой памяти;
//   4) понижаем права до PROT_NONE (полное запрещение доступа);
//   5) отпускаем мьютекс.
//
// Мьютекс обязателен, потому что PROT_NONE между использованиями исключает
// параллельный доступ к ключу — если один поток ставит PROT_NONE в момент,
// когда другой читает байт ключа, второй получит SIGSEGV.
void caesar(void* src, void* dst, int len) {
    if (g_key_page == NULL) {
        fprintf(stderr, "caesar: key is not set\n");
        return;
    }

    // Захватываем мьютекс — теперь только этот поток работает с ключом
    pthread_mutex_lock(&g_key_mutex);

    // Расширение прав до PROT_READ (по заданию: "При каждом использовании ключа
    // для шифрования права временно расширяются до PROT_READ").
    // Страница до этого была PROT_NONE (запрещён любой доступ).
    if (mprotect(g_key_page, KEY_SIZE, PROT_READ) != 0) {
        perror("mprotect (caesar READ)");
        pthread_mutex_unlock(&g_key_mutex);
        return;
    }

    // Шифрование/дешифрование с прямым обращением к защищённой памяти.
    // Каст к (volatile unsigned char*) гарантирует, что компилятор не
    // закэширует значение байта ключа в регистре и будет честно читать
    // его из защищённой mmap-области на каждой итерации.
    unsigned char* s = (unsigned char*)src;
    unsigned char* d = (unsigned char*)dst;
    for (int i = 0; i < len; i++) {
        d[i] = s[i] ^ ((volatile unsigned char*)g_key_page)[0];   // <-- прямое обращение к защищённой памяти
    }

    // Полное закрытие доступа: между использованиями ключ нельзя ни читать,
    // ни писать. PROT_NONE — более строгая защита, чем PROT_READ.
    if (mprotect(g_key_page, KEY_SIZE, PROT_NONE) != 0) {
        perror("mprotect (caesar NONE)");
        pthread_mutex_unlock(&g_key_mutex);
        return;
    }

    // Отпускаем мьютекс — другие потоки могут теперь использовать ключ
    pthread_mutex_unlock(&g_key_mutex);
}

// Дополнительная функция для демонстрации защиты: возвращает указатель на
// защищённую область, чтобы в основной программе можно было показать
// попытку прямой записи (которая приведёт к SIGSEGV). Используется только
// для демонстрации (по заданию: "продемонстрировать попытку записи в
// защищённую память").
void* get_key_ptr(void) {
    return (void*)g_key_page;
}