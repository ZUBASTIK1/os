CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC
UNAME := $(shell uname -s)

# Определяем расширение библиотеки и команды установки в зависимости от ОС
ifeq ($(UNAME), Linux)
    LIB_EXT = so
    INSTALL_CMD = sudo cp libcaesar.$(LIB_EXT) /usr/local/lib/ && sudo ldconfig
    TEST_PROG_LDFLAGS = -ldl
else
    LIB_EXT = dll
    INSTALL_CMD = cp libcaesar.$(LIB_EXT) C:/Windows/System32/ || echo "Copy manually"
    TEST_PROG_LDFLAGS =
endif

all: libcaesar.$(LIB_EXT)

libcaesar.$(LIB_EXT): libcaesar.c
	$(CC) $(CFLAGS) -shared -o $@ $<

testprog: test.c
	$(CC) -o $@ $< $(TEST_PROG_LDFLAGS)

test: all testprog input.txt
	./testprog ./libcaesar.$(LIB_EXT) X input.txt encrypted.bin
	./testprog ./libcaesar.$(LIB_EXT) X encrypted.bin decrypted.bin
	fc /b input.txt decrypted.bin && echo "Test passed" || echo "Test failed"
	rm -f encrypted.bin decrypted.bin

install: libcaesar.$(LIB_EXT)
	$(INSTALL_CMD)

clean:
	rm -f *.o *.$(LIB_EXT) testprog encrypted.bin decrypted.bin