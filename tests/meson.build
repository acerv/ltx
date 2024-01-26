# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 SUSE LLC Andrea Cervesato <andrea.cervesato@suse.com>

tests = [
    'test_message.c',
    'test_unpack.c',
    'test_utils.c',
]

foreach src : tests
    bin = src.split('.')[0]
    exe = executable(
        bin,
        [ltx_msgpack_src, src],
        include_directories : ltx_include_dir,
        dependencies: dependency('check'),
    )
    test(bin, exe)
endforeach
