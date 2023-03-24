// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#ifndef LTX_BASE_H
#define LTX_BASE_H

/* The current LTX version */
#define VERSION "0.1"

/* Code used to identify no commands. */
#define LTX_NONE 0xffff

/* Message sent when an error occurs.
 * Data structure is the following:
 *
 * | uint | str |
 */
#define LTX_ERROR 0xff

/* VERSION request.
 * Data structure is the following:
 *
 * | uint |
 *
 * The reply is the following:
 *
 * | uint | str |
 */
#define LTX_VERSION 0x00

/* PING request.
 * Data structure is the following:
 *
 * | uint |
 *
 * The reply is the following (PONG):
 *
 * | uint | uint |
 */
#define LTX_PING 0x01

/* Reply to PING request.
 * Data structure is the following:
 *
 * | uint | uint |
 *
 * Where second element is time stamp (CLOCK_MONOTONIC).
 */
#define LTX_PONG 0x02

/* GET_FILE request.
 * Data structure is the following:
 *
 * | uint | str |
 *
 * The reply is the following
 *
 * | uint | str | bin |
 */
#define LTX_GET_FILE 0x03

/* SET_FILE request.
 * Data structure is the following:
 *
 * | uint | str | bin |
 *
 * The reply is the following
 *
 * | uint | str |
 */
#define LTX_SET_FILE 0x04

/* ENV request.
 * Data structure is the following:
 *
 * | uint | uint | str | str |
 *
 * Once applied, the data structure is echoed back.
 */
#define LTX_ENV 0x05

/* CWD request.
 * Data structure is the following:
 *
 * | uint | uint | str |
 *
 * Once applied, the data structure is echoed back.
 */
#define LTX_CWD 0x06

/* EXEC request.
 * Data structure is the following:
 *
 * | uint | uint | str |
 *
 * The data structure is echoed back.
 */
#define LTX_EXEC 0x07

/* RESULT request. This is sent once execution has completed.
 * Data structure is the following:
 *
 * | uint | uint | uint | uint | uint |
 */
#define LTX_RESULT 0x08

/* LOG reply. This message is sent every time command executed via EXEC has
 * wrote on stdout. Data structure is the following:
 *
 * | uint | uint | uint | str |
 */
#define LTX_LOG 0x09

/* DATA reply. This is sent when GET_FILE is received.
 * Data structure is the following:
 *
 * | uint | bin |
 */
#define LTX_DATA 0xa0

/* KILL request. It kills a running command sending SIGKILL.
 * Data structure is the following:
 *
 * | uint | uint |
 *
 * The data structure is echoed back.
 */
#define LTX_KILL 0xa1

#endif /* LTX_BASE_H */
