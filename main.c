// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "ltx.h"

int main(int argc, char *argv[])
{
	int stdin_fd = STDIN_FILENO;
	int stdout_fd = STDOUT_FILENO;;

	if (argc >= 2 && strcmp(argv[1], "-i") && strcmp(argv[1], "--interactive")) {
		if (!strcmp(argv[1], "-s") || !strcmp(argv[1], "--serial")) {
			if (argc != 3) {
				printf("Serial port is not defined\n");
				return 1;
			}

			const char *port = argv[2];

			if (access(port, F_OK) != 0) {
				printf("%s doesn't exist\n", port);
				return 1;
			}

			stdin_fd = stdout_fd = open(port, O_RDWR | O_NOCTTY);
			if (stdin_fd == -1) {
				printf("Can't open %s (%s)\n", port, strerror(errno));
				return 1;
			}
		} else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
			printf(
				"Usage: ./ltx [-h|-i|-s]\n\n"
				"  -i | --interactive  communicate via stdin|stdout (default)\n"
				"  -s | --serial       communicate via serial port\n"
				"  -h | --help         print help message\n"
				"  -v | --version      print version\n\n"
			);
			return 0;
		} else if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
			printf("%s\n", VERSION);
			return 0;
		} else {
			printf("Unknown parameter: %s\n", argv[1]);
			return 1;
		}
	}

	struct ltx_session *session;

	session = ltx_session_init(stdin_fd, stdout_fd);
	ltx_start_event_loop(session);
	ltx_session_destroy(session);

	close(stdin_fd);
	close(stdout_fd);

	return 0;
}
