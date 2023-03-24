// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#ifndef LTX_H
#define LTX_H

/* ltx session abstract object to implement */
typedef struct ltx_session ltx_session;

/* Initialize ltx session with specific stdin/stdout */
struct ltx_session *ltx_session_init(const int stdin_fd, const int stdout_fd);

/* Destroy current ltx session */
void ltx_session_destroy(struct ltx_session *session);

/* Start the main event loop */
void ltx_start_event_loop(struct ltx_session *session);

#endif /* LTX_H */
