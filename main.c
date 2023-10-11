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
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "ltx.h"

int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	char *serial_port = NULL;
	int stdin_fd = STDIN_FILENO;
	int stdout_fd = STDOUT_FILENO;

	static struct option long_options[] = {
		{"serial", required_argument, NULL, 's'},
		{"version", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(
			argc,
			argv,
			"s:vh",
			long_options,
			&option_index)) != -1) {
		switch(opt) {
		case 's':
			serial_port = strdup(optarg);
			break;
		case 'v':
			printf("%s\n", VERSION);
			return 0;
		case 'h':
		default:
			printf(
				"Usage: ./ltx [-s|-v|-h]\n\n"
				"  -s | --serial       communicate via serial port\n"
				"  -v | --version      print version\n"
				"  -h | --help         print help message\n\n"
			);
			return 0;
		}
	}

	if (serial_port) {
		if (access(serial_port, F_OK) != 0) {
			printf("%s doesn't exist\n", serial_port);
			return 1;
		}

		stdin_fd = stdout_fd = open(serial_port, O_RDWR | O_NOCTTY);
		if (stdin_fd == -1) {
			printf("Can't open %s (%s)\n", serial_port, strerror(errno));
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
