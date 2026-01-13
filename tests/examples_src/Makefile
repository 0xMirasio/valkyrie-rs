CC      := gcc
CFLAGS  := -O3 -fPIC
LDFLAGS := -static -fno-stack-protector

BIN     := build/io
SRC     := io/io.c

.PHONY: all init io clean

all: io

init:
	@mkdir -p build

io: $(BIN)

$(BIN): $(SRC) | init
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf build
