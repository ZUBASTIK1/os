CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC
LDFLAGS = -pthread -ldl
LIB = libcaesar.so

# Директория для тестовых артефактов
TEST_DIR = test_files

all: secure_copy

$(LIB): libcaesar.c
	$(CC) $(CFLAGS) -pthread -shared -o $@ $<

secure_copy: secure_copy.c $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -Wl,-rpath,'$$ORIGIN'

# ----------------------------------------------------------------------------
# test6 — основной тест по заданию №6:
#   1) собираем тестовую директорию глубиной 4;
#   2) -add для файлов и для директории;
#   3) -list (проверяем сортировку и размеры);
#   4) -get для нескольких файлов и сравнение с оригиналом (cmp).
# ----------------------------------------------------------------------------
test6: secure_copy
	@echo "=== Test 6: image with encrypted files ==="
	@rm -rf $(TEST_DIR)
	@mkdir -p $(TEST_DIR)
	@mkdir -p $(TEST_DIR)/in/a/b/c
	@echo "Single file 1" > $(TEST_DIR)/file1.txt
	@echo "Single file 2 content here" > $(TEST_DIR)/file2.txt
	@echo "Root inside dir" > $(TEST_DIR)/in/root.txt
	@echo "Depth 2 file" > $(TEST_DIR)/in/a/level2.txt
	@echo "Depth 3 file" > $(TEST_DIR)/in/a/b/level3.txt
	@echo "Depth 4 file (deepest)" > $(TEST_DIR)/in/a/b/c/level4.txt
	@echo ""
	@echo "--- 6.1: -add (single files + directory of depth 4) ---"
	./secure_copy -add -key "secret" -image $(TEST_DIR)/disk.img \
	              $(TEST_DIR)/file1.txt $(TEST_DIR)/file2.txt $(TEST_DIR)/in
	@echo ""
	@echo "--- 6.2: -list (sorted, with sizes) ---"
	./secure_copy -list -image $(TEST_DIR)/disk.img
	@echo ""
	@echo "--- 6.3: -get and verify content ---"
	@mkdir -p $(TEST_DIR)/restored
	./secure_copy -get -image $(TEST_DIR)/disk.img -key "secret" \
	              -out $(TEST_DIR)/restored/file1.txt file1.txt
	./secure_copy -get -image $(TEST_DIR)/disk.img -key "secret" \
	              -out $(TEST_DIR)/restored/level4.txt in/a/b/c/level4.txt
	./secure_copy -get -image $(TEST_DIR)/disk.img -key "secret" \
	              -out $(TEST_DIR)/restored/level3.txt in/a/b/level3.txt
	@echo ""
	@echo "Comparing original vs restored:"
	@cmp -s $(TEST_DIR)/file1.txt           $(TEST_DIR)/restored/file1.txt   && echo "  file1.txt: OK"   || echo "  file1.txt: FAIL"
	@cmp -s $(TEST_DIR)/in/a/b/c/level4.txt $(TEST_DIR)/restored/level4.txt  && echo "  level4.txt: OK"  || echo "  level4.txt: FAIL"
	@cmp -s $(TEST_DIR)/in/a/b/level3.txt   $(TEST_DIR)/restored/level3.txt  && echo "  level3.txt: OK"  || echo "  level3.txt: FAIL"
	@echo ""
	@echo "--- 6.4: -get with wrong key (must produce garbage, not crash) ---"
	@./secure_copy -get -image $(TEST_DIR)/disk.img -key "WRONG" \
	              -out $(TEST_DIR)/restored/wrong.txt file1.txt; \
	  if cmp -s $(TEST_DIR)/file1.txt $(TEST_DIR)/restored/wrong.txt; then \
	    echo "  FAIL: wrong key produced matching content"; \
	  else \
	    echo "  OK: wrong key produced different content (as expected)"; \
	  fi
	@echo ""
	@echo "--- 6.5: -get for missing file (must report error, not crash) ---"
	-./secure_copy -get -image $(TEST_DIR)/disk.img -key "secret" \
	              -out $(TEST_DIR)/restored/nope.txt does_not_exist.txt; \
	  echo "Exit code: $$?"
	@echo "=== Test 6 completed ==="

# Параллельность: создаём много файлов и измеряем общее время.
# Образ перезаписывается с нуля.
test6-parallel: secure_copy
	@echo "=== Test 6: parallel add of many files ==="
	@rm -rf $(TEST_DIR)/many
	@mkdir -p $(TEST_DIR)/many
	@for i in $$(seq 1 30); do \
	    dd if=/dev/urandom of=$(TEST_DIR)/many/file$$i.bin bs=64K count=4 status=none; \
	 done
	@rm -f $(TEST_DIR)/parallel.img
	@echo "Adding 30 files (parallel pwrite, up to 5 workers)..."
	./secure_copy -add -key "p4r4ll3l" -image $(TEST_DIR)/parallel.img $(TEST_DIR)/many | tail -3
	@./secure_copy -list -image $(TEST_DIR)/parallel.img | head -n 5
	@echo "(showing first 5 entries of the listing)"

# test6-memory — доказательство потоковой обработки по кусочкам:
# большой файл (200 МБ) обрабатывается при жёстком лимите виртуальной памяти.
# При старом подходе (чтение файла целиком в malloc) это упало бы.
test6-memory: secure_copy
	@echo "=== Test 6: constant-memory streaming (200MB under 64MB limit) ==="
	@mkdir -p $(TEST_DIR)
	@dd if=/dev/urandom of=$(TEST_DIR)/huge.bin bs=1M count=200 status=none
	@rm -f $(TEST_DIR)/huge.img
	@echo "--- add 200MB with ulimit -v 64MB ---"
	@bash -c 'ulimit -v 65536; ./secure_copy -add -key k -image $(TEST_DIR)/huge.img $(TEST_DIR)/huge.bin | tail -3'
	@echo "--- get 200MB with ulimit -v 64MB ---"
	@bash -c 'ulimit -v 65536; ./secure_copy -get -image $(TEST_DIR)/huge.img -key k -out $(TEST_DIR)/huge_r.bin huge.bin | tail -1'
	@cmp $(TEST_DIR)/huge.bin $(TEST_DIR)/huge_r.bin && echo "200MB roundtrip under 64MB RAM: OK" || echo "FAIL"
	@echo "=== Test 6 memory completed ==="

# test6-demo — демонстрация защиты памяти (перенесено из задания 5).
# Показывает SIGSEGV при попытке прямой записи в защищённый ключ и в S-box.
test6-demo: secure_copy
	@echo "=== Test 6: memory protection demo ==="
	@mkdir -p $(TEST_DIR)
	@echo "demo" > $(TEST_DIR)/demo.txt
	@echo "--- attack on KEY (expects SIGSEGV, exit 2) ---"
	-./secure_copy -add -key "k" -image $(TEST_DIR)/demo.img --demo-attack key $(TEST_DIR)/demo.txt; \
	  echo "exit code: $$?"
	@echo "--- attack on STATE / S-box (expects SIGSEGV, exit 2) ---"
	-./secure_copy -add -key "k" -image $(TEST_DIR)/demo.img --demo-attack state $(TEST_DIR)/demo.txt; \
	  echo "exit code: $$?"
	@echo "=== Test 6 demo completed ==="

# test6-log — проверка логирования: после add/get в log.txt появляются записи.
test6-log: secure_copy
	@echo "=== Test 6: logging ==="
	@mkdir -p $(TEST_DIR)
	@rm -f log.txt $(TEST_DIR)/log.img
	@echo "one" > $(TEST_DIR)/l1.txt
	@echo "two" > $(TEST_DIR)/l2.txt
	./secure_copy -add -key "k" -image $(TEST_DIR)/log.img $(TEST_DIR)/l1.txt $(TEST_DIR)/l2.txt > /dev/null
	./secure_copy -get -image $(TEST_DIR)/log.img -key "k" -out $(TEST_DIR)/l1_out.txt l1.txt > /dev/null
	@echo "--- contents of log.txt: ---"
	@cat log.txt
	@echo "=== Test 6 log completed ==="

clean:
	rm -f *.o *.so secure_copy log.txt
	rm -rf $(TEST_DIR)
