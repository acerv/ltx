CC ?= gcc
CFLAGS ?= -pedantic -W -Wall
INCLUDES = -Imsgpack

# tests build configuration
TESTS_DEPS = \
	msgpack/message.c \
	msgpack/unpack.c

TESTS_SRCS = \
	tests/test_message.c \
	tests/test_unpack.c \
	tests/test_utils.c

TESTS = $(TESTS_SRCS:%.c=%)

# target build configuration
TARGET_SRCS = \
	msgpack/message.c \
	msgpack/unpack.c \
	ltx.c

TARGET = ltx

# make rules
.PHONY: $(TARGET) $(TESTS) clean debug

all: $(TARGET_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) \
		$(TARGET_SRCS) -o $(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: all

test: $(TESTS)

$(TESTS): $(TESTS_DEPS)
	$(CC) $(CFLAGS) $(INCLUDES) \
		$(TESTS_DEPS) $@.c -o $@ \
		`pkg-config --cflags --libs check`

clean:
	$(RM) $(TARGET) $(TESTS)
