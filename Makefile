CC = gcc
CFLAGS = -Wall -Wextra -pedantic-errors -std=c11 -fsanitize=undefined,address,leak -Wconversion

TARGET = safecipher

SRC = cli.c crypto.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
