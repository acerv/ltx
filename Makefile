CC = gcc
CFLAGS = -g -Imsgpack

all:
	$(CC) $(CFLAGS) \
		msgpack/unpack.c \
		msgpack/message.c \
		ltx.c \
		main.c \
		-o ltx

test:
	$(CC) $(CFLAGS) -lcheck \
		msgpack/message.c \
		tests/test_message.c \
		-o tests/test_message

	$(CC) $(CFLAGS) -lcheck \
		msgpack/message.c \
		msgpack/unpack.c \
		tests/test_unpack.c \
		-o tests/test_unpack

clean:
	rm -f ltx tests/test_message tests/test_unpack
