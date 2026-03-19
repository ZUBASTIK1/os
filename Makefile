CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC
LDFLAGS = -pthread -ldl
LIB = libcaesar.so
CMP_CMD = cmp

all: secure_copy

$(LIB): libcaesar.c
	$(CC) $(CFLAGS) -shared -o $@ $<

secure_copy: secure_copy.c $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -Wl,-rpath,'$$ORIGIN'

# Цель для проверки задания 3 (5 файлов) – файлы остаются после теста
test3: secure_copy
	@echo "Creating 5 test files..."
	@for i in 1 2 3 4 5; do \
		echo "Content of file $$i" > file$$i.txt; \
	done
	@mkdir -p test_out
	@echo "Running secure_copy with 5 files..."
	./secure_copy file1.txt file2.txt file3.txt file4.txt file5.txt test_out/ A
	@echo "Contents of log.txt:"
	@cat log.txt
	@echo "Test completed. Original files: file1.txt ... file5.txt, encrypted files: test_out/"

install: $(LIB)
	sudo cp $(LIB) /usr/local/lib/
	sudo ldconfig

clean:
	rm -f *.o *.so secure_copy log.txt
	rm -rf test_out
	rm -f file?.txt