CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC
LDFLAGS = -pthread
LIB = libcaesar.so
CMP_CMD = cmp

all: secure_copy

# Зависимость от библиотеки (если не собрана, собираем)
$(LIB): libcaesar.c
	$(CC) $(CFLAGS) -shared -o $@ $<

secure_copy: secure_copy.c $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -L. -lcaesar -Wl,-rpath,'$$ORIGIN' -lrt
	
test: secure_copy
	@echo "Testing with small file..."
	./secure_copy input.txt output.bin X
	./secure_copy output.bin decrypted.bin X
	$(CMP_CMD) input.txt decrypted.bin && echo "Test passed" || echo "Test failed"


# Цель для проверки на файле размером 10 МБ
test2: secure_copy
	@echo "Creating 10MB test file..."
	dd if=/dev/urandom of=bigfile.bin bs=1M count=10 2>/dev/null
	@echo "Encrypting..."
	./secure_copy bigfile.bin encrypted.bin 42
	@echo "Decrypting..."
	./secure_copy encrypted.bin decrypted.bin 42
	$(CMP_CMD) bigfile.bin decrypted.bin && echo "Test passed" || echo "Test failed"


install: $(LIB)
	sudo cp $(LIB) /usr/local/lib/
	sudo ldconfig

clean:
	rm -f *.o *.so secure_copy encrypted.bin decrypted.bin bigfile.bin output.bin