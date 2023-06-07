// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Richard Palethorpe <rpalethorpe@suse.com>
 * Copyright (c) 2023 Andrea Cervesato <andrea.cervesato@suse.com>
 */

#ifndef LTX_BASE_H
#define LTX_BASE_H

/* The current LTX version */
#define VERSION "0.1"

/* Code used to identify no requests */
#define LTX_NONE 0xffff

/* Message sent when error occurs */
#define LTX_ERROR 0xff

/* VERSION request */
#define LTX_VERSION 0x00

/* PING request */
#define LTX_PING 0x01

/* PONG reply */
#define LTX_PONG 0x02

/* GET_FILE request */
#define LTX_GET_FILE 0x03

/* SET_FILE request. */
#define LTX_SET_FILE 0x04

/* ENV request */
#define LTX_ENV 0x05

/* CWD request */
#define LTX_CWD 0x06

/* EXEC request */
#define LTX_EXEC 0x07

/* RESULT request */
#define LTX_RESULT 0x08

/* LOG reply */
#define LTX_LOG 0x09

/* DATA reply */
#define LTX_DATA 0xa0

/* KILL request */
#define LTX_KILL 0xa1

#endif /* LTX_BASE_H */
