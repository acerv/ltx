# Linux Test (Project) Executor

The `ltx` program runs on the system under test (SUT). It's primary
purpose is to run test executables in parallel and serialise the
results. It is a dumb program that executes simple commands sent to it
by a test scheduler. The commands are encoded as [MessagePack] arrays as
are the results.

The first element of the array is the message type, represented as an
integer. The rest of the array contents (if any) depend on the message
type.

In classic UNIX fashion, stdin and stdout are used to receive and send
commands. This makes LTX transport agnostic, a program such as
`socat`, `ssh` or just `sh` can be used to redirect the standard I/O
of LTX.

## Dependencies

LTX itself just needs Clang or GCC. The tests require Python 3.7+ with
`pytest` and `msgpack`. To build LTX, we can use `make` command:

    # regular build
    make
    # debug build
    make debug

For testing:

    # tests build
    make test

    # execute tests
    ./tests/test_utils
    ./tests/test_message
    ./tests/test_unpack

    # install python 3.7+ dependences
    virtualenv .venv
    source .venv/bin/activate
    pip install pytest msgpack

    # execute LTX communication tests
    pytest -v tests/test_ltx.py

We can also easily cross-compile LTX using `zig==0.11.0`. Beware that this is an
**experimental feature** and it's up to developers if they want to use it or
not.

## Messages

LTX is not intended to have a generic [MessagePack] parser. There are
several ways in which a message can be encoded. However you can assume
LTX only accepts the shortest possible encoding.

### Version

Check for LTX version.

Request:

| fixarray | uint   |
|:---------|:-------|
| `0x91`   | `0x00` |

Reply:

| fixarray | uint   | string   |
|:---------|:-------|:---------|
| `0x92`   | `0x00` | version  |

### Ping

Send ping to the service. Pong reply will have a nano seconds time stamp taken
with `CLOCK_MONOTONIC`.

Request:

| fixarray | uint   |
|:---------|:-------|
| `0x91`   | `0x01` |

Reply:

| fixarray | uint   | uint    |
|:---------|:-------|:--------|
| `0x92`   | `0x02` | time_ns |

### Get file

Read file from the system. LTX will start to send file content via `Data` reply.
Each `Data` reply contains maximum `1024` bytes and when all `Data` replies are
sent, LTX will echo back the request. **NOTE**: LTX won't process anything else
until `Get file` request is completed.

Request:

| fixarray | uint   | string    |
|:---------|:-------|:----------|
| `0x92`   | `0x03` | file path |

Data:

| fixarray | uint   | bytes        |
|:---------|:-------|:-------------|
| `0x92`   | `0xa0` | file content |

### Set file

Write file on target. Reply message will be identical to the request message,
except for the file content data, which is removed to speed up communication.
**NOTE**: LTX won't process anything else until `Set file` request is completed.

Request:

| fixarray | uint   | string    | bytes        |
|:---------|:-------|:----------|:-------------|
| `0x93`   | `0x04` | file path | file content |

Reply:

| fixarray | uint   | string    |
|:---------|:-------|:----------|
| `0x92`   | `0x04` | file path |

### Env

Set environment variable to a specific `slot_id` or all slots. Once message is
processed, request is echoed back. To set `Env` for all slots use `slot_id`
number `128`.

Request:

| fixarray | uint   | uint    | string | string |
|:---------|:-------|:------- |:-------|:-------|
| `0x94`   | `0x05` | slot_id | key    | value  |

### Cwd

Set current working directory for a specific `slot_id` or all slots. Once
message is processed, request is echoed back. To set `Cwd` for all slots use
`slot_id` number `128`.

Request:

| fixarray | uint   | uint    | string |
|:---------|:-------|:------- |:-------|
| `0x93`   | `0x06` | slot_id | path   |

### Exec

Execute a command inside a specific `slot_id`. Once message is processed,
request is echoed back, then `Log` messages are sent when reading command
stdout and at the end a `Result` message is sent. The `Result` execution time
will have a nano seconds time stamp taken with `CLOCK_MONOTONIC`.

Request:

| fixarray | uint   | uint    | string    |
|:---------|:-------|:------- |:----------|
| `0x93`   | `0x07` | slot_id | command   |

Log:

| fixarray | uint   | uint    | string    |
|:---------|:-------|:------- |:----------|
| `0x93`   | `0x09` | slot_id | stdout    |

Result:

| fixarray | uint   | uint    | uint    | uint    | uint      |
|:---------|:-------|:------- |:--------|:--------|:----------|
| `0x95`   | `0x08` | slot_id | exec_ns | si_code | si_status |

### Kill

Kill execution on a particular `slot_id`. Once message is processed, request is
echoed back and related `Exec` request is processed after a `SIGKILL`. So expect
to receive the last `Log` messages as well as a `Result` message.

Request:

| fixarray | uint   | uint    |
|:---------|:-------|:------- |
| `0x92`   | `0xa1` | slot_id |

### Error

All the times and error occurs inside LTX, this message is sent. This message
can literally arrive in any moment, so be sure to process error type before any
message is received from LTX.

Reply:

| fixarray | uint   | string       |
|:---------|:-------|:-------------|
| `0x92`   | `0xff` | error string |


[MessagePack]: https://github.com/msgpack/msgpack/blob/master/spec.md

# Init and cross compile

It is possible to cross compile LTX and run it as init. There is a
script to do this and create an initrd suitable for direct booting in
QEMU.

We can also cross compile the kernel and some test executables. The
only dependencies are Zig, Clang, `cpio`, `gzip` and some standard
utils like `sh`, `find` etc.

We refer to the directory containing this README as `$ltx`.

## Create the initrd tree

For example, create a directory structure as follows

```sh
$ cd $ltx/cross
$ mkdir initrds
$ mkdir initrds/arm64/bin
```

The `arm64` folder will be the root dir of your image. You can select
a different location if you wish. The only requirement is the `bin`
folder which must contain one or more test executables (added below).

## Build the initrd

First we need to cross compile LTX and a test executable.

```sh
$ cd $ltx
$ zig build -Dtarget=aarch64-linux-musl
$ cp zig-out/bin/ltx cross/initrds/arm64/init
$ cp zig-out/bin/sysinfo cross-initrds/arm64/bin/sysinfo
```

The LTX executable must be renamed to `init` and be placed in the root
of our initrd image. The `sysinfo` program just prints some
information and can be used as a smoke test.

Now we can build the image:

```sh
$ cross/mk-initrd.sh cross/initrds/arm64
```

This will output the image `cross/initrds/arm64.cpio.gz`. Any files
you add to `cross/initrds/arm64` will be available in your root file
system.

## Making a Linux image

The Linux kernel can be cross compiled with LLVM in the following way.

```sh
$ cd $linux_git_checkout
$ make LLVM=1 ARCH=arm64 defconfig
$ make LLVM=1 ARCH=arm64 menuconfig # Optional
$ make LLVM=1 ARCH=arm64 -j$(nproc)
$ mkdir $ltx/cross/kernels
$ cp arch/arm64/boot/Image.gz $ltx/cross/kernels/arm64-Image.gz
```

We need the `Image.gz` file on ARM64, other architectures use
different names. For example on x86 it is `bzImage`.

