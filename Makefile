CC = gcc
CFLAGS = -pedantic -W -Wall -Imsgpack

all:
	$(CC) $(CFLAGS) \
		msgpack/unpack.c \
		msgpack/message.c \
		ltx.c \
		-o ltx

debug:
	$(CC) $(CFLAGS) \
		-g \
		-D DEBUG \
		msgpack/unpack.c \
		msgpack/message.c \
		ltx.c \
		-o ltx

test:
	$(CC) $(CFLAGS) \
		msgpack/message.c \
		tests/test_utils.c \
		-o tests/test_utils \
		`pkg-config --cflags --libs check`

	$(CC) $(CFLAGS) \
		msgpack/message.c \
		tests/test_message.c \
		-o tests/test_message \
		`pkg-config --cflags --libs check`

	$(CC) $(CFLAGS) \
		msgpack/message.c \
		msgpack/unpack.c \
		tests/test_unpack.c \
		-o tests/test_unpack \
		`pkg-config --cflags --libs check`

clean:
	rm -f ltx tests/test_utils tests/test_message tests/test_unpack
