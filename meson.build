# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 SUSE LLC Andrea Cervesato <andrea.cervesato@suse.com>

project(
    'ltx',
    'c',
    license : 'GPL-2.0+',
    version : '0.1',
    default_options : [
        'c_std=gnu99',
        'warning_level=2',
    ],
    meson_version: '>=1.2.3'
)

if get_option('buildtype') == 'debug'
    add_global_arguments('-DDEBUG', language : 'c')
endif

ltx_include_dir = include_directories(
    'msgpack',
)

ltx_msgpack_src = files(
    'msgpack/message.c',
    'msgpack/unpack.c',
)

executable(
    'ltx',
    [
        ltx_msgpack_src,
        'ltx.c',
        'main.c',
    ],
    include_directories : ltx_include_dir,
    install : true,
    install_dir : 'bin',
)

if get_option('build_tests')
    subdir('tests')
endif
