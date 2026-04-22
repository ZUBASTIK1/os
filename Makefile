CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC
LDFLAGS = -pthread -ldl
LIB = libcaesar.so
CMP_CMD = cmp

# Количество потоков для параллельного режима (можно переопределить при сборке)
WORKERS ?= 4
CFLAGS += -DWORKERS_COUNT=$(WORKERS)

# Директория для всех тестовых артефактов
TEST_DIR = test_files

all: secure_copy

$(LIB): libcaesar.c
	$(CC) $(CFLAGS) -shared -o $@ $<

secure_copy: secure_copy.c $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -Wl,-rpath,'$$ORIGIN'

# Цель для проверки задания 3 (5 файлов) – файлы создаются в $(TEST_DIR)
test3: secure_copy
	@echo "=== Test 3: 5 files (legacy mode) ==="
	@mkdir -p $(TEST_DIR)
	@for i in 1 2 3 4 5; do \
		echo "Content of file $$i" > $(TEST_DIR)/file$$i.txt; \
	done
	@mkdir -p $(TEST_DIR)/test_out
	@echo "Running secure_copy with 5 files..."
	./secure_copy $(TEST_DIR)/file1.txt $(TEST_DIR)/file2.txt $(TEST_DIR)/file3.txt \
	              $(TEST_DIR)/file4.txt $(TEST_DIR)/file5.txt $(TEST_DIR)/test_out/ A
	@echo "Contents of log.txt:"
	@cat log.txt
	@echo "Test completed. Original files: $(TEST_DIR)/file*.txt, encrypted files: $(TEST_DIR)/test_out/"

# Цель для проверки практической работы №4 (10 файлов, автоматический режим)
test4: secure_copy
	@echo "=== Test 4: 10 files, auto mode (parallel/sequential) ==="
	@mkdir -p $(TEST_DIR)
	@echo "Creating 10 test files in $(TEST_DIR)..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		echo "Content of file number $$i" > $(TEST_DIR)/file$$i.txt; \
	done
	@mkdir -p $(TEST_DIR)/test_out
	@echo "Running in AUTO mode (should select parallel for >=5 files):"
	./secure_copy $(TEST_DIR)/file1.txt $(TEST_DIR)/file2.txt $(TEST_DIR)/file3.txt \
	              $(TEST_DIR)/file4.txt $(TEST_DIR)/file5.txt $(TEST_DIR)/file6.txt \
	              $(TEST_DIR)/file7.txt $(TEST_DIR)/file8.txt $(TEST_DIR)/file9.txt \
	              $(TEST_DIR)/file10.txt $(TEST_DIR)/test_out/ A
	@echo ""
	@echo "Running explicitly in SEQUENTIAL mode for comparison:"
	./secure_copy --mode=sequential $(TEST_DIR)/file1.txt $(TEST_DIR)/file2.txt \
	              $(TEST_DIR)/file3.txt $(TEST_DIR)/file4.txt $(TEST_DIR)/file5.txt \
	              $(TEST_DIR)/file6.txt $(TEST_DIR)/file7.txt $(TEST_DIR)/file8.txt \
	              $(TEST_DIR)/file9.txt $(TEST_DIR)/file10.txt $(TEST_DIR)/test_out_seq/ A
	@echo ""
	@echo "Running explicitly in PARALLEL mode:"
	./secure_copy --mode=parallel $(TEST_DIR)/file1.txt $(TEST_DIR)/file2.txt \
	              $(TEST_DIR)/file3.txt $(TEST_DIR)/file4.txt $(TEST_DIR)/file5.txt \
	              $(TEST_DIR)/file6.txt $(TEST_DIR)/file7.txt $(TEST_DIR)/file8.txt \
	              $(TEST_DIR)/file9.txt $(TEST_DIR)/file10.txt $(TEST_DIR)/test_out_par/ A
	@echo "=== Test 4 completed ==="

# Дополнительная цель для демонстрации с разным числом потоков
test4-workers: secure_copy
	@echo "=== Test 4 with WORKERS=$(WORKERS) threads ==="
	@mkdir -p $(TEST_DIR)
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		echo "Content of file $$i" > $(TEST_DIR)/file$$i.txt; \
	done
	@mkdir -p $(TEST_DIR)/test_out
	./secure_copy --mode=parallel $(TEST_DIR)/file1.txt $(TEST_DIR)/file2.txt \
	              $(TEST_DIR)/file3.txt $(TEST_DIR)/file4.txt $(TEST_DIR)/file5.txt \
	              $(TEST_DIR)/file6.txt $(TEST_DIR)/file7.txt $(TEST_DIR)/file8.txt \
	              $(TEST_DIR)/file9.txt $(TEST_DIR)/file10.txt $(TEST_DIR)/test_out/ A

install: $(LIB)
	sudo cp $(LIB) /usr/local/lib/
	sudo ldconfig

clean:
	rm -f *.o *.so secure_copy log.txt
	rm -rf $(TEST_DIR)