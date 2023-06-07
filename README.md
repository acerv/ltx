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


## Messages

LTX is not intended to have a generic [MessagePack] parser. There are
several ways in which a message can be encoded. However you can assume
LTX only accepts the shortest possible encoding.

### Version

Check for LTX version.

Request:

| fixarray | fixint |
|:---------|:-------|
| `0x90`   | `0x00` |

Reply:

| fixarray | fixint | string   |
|:---------|:-------|:---------|
| `0x91`   | `0x00` | version  |

### Ping

Send ping to the service. Pong reply will have a nano seconds time stamp taken
with `CLOCK_MONOTONIC`.

Request:

| fixarray | fixint |
|:---------|:-------|
| `0x90`   | `0x01` |

Reply:

| fixarray | fixint | uint64_t |
|:---------|:-------|:---------|
| `0x91`   | `0x02` | time_ns  |

### Get file

Read file from the system. LTX will start to send file content via `Data` reply.
Each `Data` reply contains maximum `1024` bytes and when all `Data` replies are
sent, LTX will echo back the request. **NOTE**: LTX won't process anything else
until `Get file` request is completed.

Request:

| fixarray | type   | string    |
|:---------|:-------|:----------|
| `0x91`   | `0x03` | file path |

Data:

| fixarray | type   | bytes        |
|:---------|:-------|:-------------|
| `0x91`   | `0xa0` | file content |

### Set file

Write file on target. Reply message will be identical to the request message,
except for the file content data, which is removed to speed up communication.
**NOTE**: LTX won't process anything else until `Set file` request is completed.

Request:

| fixarray | type   | string    | bytes        |
|:---------|:-------|:----------|:-------------|
| `0x92`   | `0x04` | file path | file content |

Reply:

| fixarray | type   | string    |
|:---------|:-------|:----------|
| `0x91`   | `0x04` | file path |

### Env

Set environment variable to a specific `slot_id` or all slots. Once message is
processed, request is echoed back. To set `Env` for all slots use `slot_id`
number `128`.

Request:

| fixarray | fixint | fixint  | string | string |
|:---------|:-------|:------- |:-------|:-------|
| `0x93`   | `0x05` | slot_id | key    | value  |

### Cwd

Set current working directory for a specific `slot_id` or all slots. Once
message is processed, request is echoed back. To set `Cwd` for all slots use
`slot_id` number `128`.

Request:

| fixarray | fixint | fixint  | string |
|:---------|:-------|:------- |:-------|
| `0x93`   | `0x06` | slot_id | path   |

### Exec

Execute a command inside a specific `slot_id`. Once message is processed,
request is echoed back, then `Log` messages are sent when reading command
stdout and at the end a `Result` message is sent. The `Result` execution time
will have a nano seconds time stamp taken with `CLOCK_MONOTONIC`.

Request:

| fixarray | fixint | fixint  | string    |
|:---------|:-------|:------- |:----------|
| `0x92`   | `0x07` | slot_id | command   |

Log:

| fixarray | fixint | fixint  | string    |
|:---------|:-------|:------- |:----------|
| `0x92`   | `0x09` | slot_id | stdout    |

Result:

| fixarray | fixint | fixint  | fixint  | fixint    |
|:---------|:-------|:--------|:--------|:----------|
| `0x93`   | `0x08` | exec_ns | si_code | si_status |

### Kill

Kill execution on a particular `slot_id`. Once message is processed, request is
echoed back and related `Exec` request is processed after a `SIGKILL`. So expect
to receive the last `Log` messages as well as a `Result` message.

Request:

| fixarray | fixint | fixint  |
|:---------|:-------|:------- |
| `0x91`   | `0xa1` | slot_id |


[MessagePack]: https://github.com/msgpack/msgpack/blob/master/spec.md
