"""
Unittests for LTX service.
Tests created for python 3.7+
"""
import os
import time
import subprocess
import signal
import pytest
import msgpack

# keep values alligned with ltx
LTX_NONE = 0xffff
LTX_ERROR = 0xff
LTX_VERSION = 0x00
LTX_PING = 0x01
LTX_PONG = 0x02
LTX_GET_FILE = 0x03
LTX_SET_FILE = 0x04
LTX_ENV = 0x05
LTX_CWD = 0x06
LTX_EXEC = 0x07
LTX_RESULT = 0x08
LTX_LOG = 0x09
LTX_DATA = 0xa0
LTX_KILL = 0xa1
MAX_SLOTS = 128
ALL_SLOTS = MAX_SLOTS
MAX_ENVS = 16


class LTXHelper:
    """
    Helper class to send/receive message from LTX.
    """

    def __init__(self, proc) -> None:
        self._proc = proc
        self._buff = bytes()
        self._start_time = time.monotonic_ns()

    @property
    def proc(self):
        """
        LTX subprocess.
        """
        return self._proc

    def read(self):
        """
        Read some data from stdout.
        """
        return os.read(self._proc.stdout.fileno(), 1 << 21)

    def expect_exact(self, data):
        """
        Expect for an exact message when reading from stdout.
        """
        length = len(data)

        while len(self._buff) < length:
            self._buff += self.read()

        for i in range(length):
            if self._buff[i] == data[i]:
                continue

            raise ValueError(
                f"Expected {hex(data[i])}, "
                f"but got {hex(self._buff[i])} at {i} in "
                f"'{self._buff.hex(' ')}' / {self._buff}")

        self._buff = self._buff[length:]

    def expect_n_bytes(self, n):
        """
        Read n bytes from stdout.
        """
        while len(self._buff) < n:
            self._buff += self.read()

        self._buff = self._buff[n:]

    def unpack_next(self):
        """
        Unpack the next package using msgpack.
        """
        unpacker = msgpack.Unpacker()
        msg = None

        unpacker.feed(self._buff)

        while not msg:
            try:
                msg = unpacker.unpack()
            except msgpack.OutOfData:
                data = self.read()
                self._buff += data
                unpacker.feed(data)

        self._buff = self._buff[unpacker.tell():]

        return msg

    def send(self, data, check_echo=True):
        """
        Send some data to stdin.
        """
        assert os.write(self._proc.stdin.fileno(), data) == len(data)

        if check_echo:
            self.expect_exact(data)


@pytest.fixture(autouse=True, scope="session")
def build_ltx():
    """
    Automatically build ltx service.
    """
    subprocess.call("make")
    yield
    subprocess.call(["make", "clean"])


@pytest.fixture
def ltx():
    """
    LTX service communication object.
    """
    parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        "./ltx",
        cwd=parent,
        bufsize=0,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)

    yield proc

    proc.kill()


@pytest.fixture
def ltx_helper(ltx):
    """
    Helper object for LTX process.
    """
    yield LTXHelper(ltx)


def test_version(ltx_helper):
    """
    Test VERSION command.
    """
    ltx_helper.send(msgpack.packb(LTX_VERSION), check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_VERSION))
    ltx_helper.expect_exact(msgpack.packb("0.1"))


def test_ping(ltx_helper):
    """
    Test PING command.
    """
    start_t = time.monotonic_ns()

    ltx_helper.send(msgpack.packb(LTX_PING))
    ltx_helper.expect_exact(msgpack.packb(LTX_PONG))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()


def test_pong_error(ltx_helper):
    """
    Test that PONG command raises an ERROR:
    """
    ltx_helper.send(msgpack.packb(LTX_PONG), check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("PONG should not be received"))


def test_error(ltx_helper):
    """
    Test that ERROR command raises an ERROR:
    """
    ltx_helper.send(msgpack.packb(LTX_ERROR), check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("ERROR should not be received"))


def test_data_error(ltx_helper):
    """
    Test that DATA command raises an ERROR:
    """
    ltx_helper.send(msgpack.packb(LTX_DATA), check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("DATA should not be received"))


def test_get_file(ltx_helper, tmpdir):
    """
    Test GET_FILE command.
    """
    path = tmpdir / "temp.bin"
    path_str = str(path)

    path.write(b'a' * 1024 + b'b' * 1024 + b'c' * 128)

    cmd = bytes()
    cmd += msgpack.packb(LTX_GET_FILE)
    cmd += msgpack.packb(path_str)

    ltx_helper.send(cmd, check_echo=False)

    ltx_helper.expect_exact(msgpack.packb(LTX_DATA))
    ltx_helper.expect_exact(msgpack.packb(b'a' * 1024))

    ltx_helper.expect_exact(msgpack.packb(LTX_DATA))
    ltx_helper.expect_exact(msgpack.packb(b'b' * 1024))

    ltx_helper.expect_exact(msgpack.packb(LTX_DATA))
    ltx_helper.expect_exact(msgpack.packb(b'c' * 128))

    ltx_helper.expect_exact(msgpack.packb(LTX_GET_FILE))
    ltx_helper.expect_exact(msgpack.packb(path_str))


def test_set_file(ltx_helper, tmpdir):
    """
    Test SET_FILE command.
    """
    path_str = str(tmpdir / "temp.bin")
    data = b'ciao'

    cmd = bytes()
    cmd += msgpack.packb(LTX_SET_FILE)
    cmd += msgpack.packb(path_str)
    cmd += msgpack.packb(data)

    ltx_helper.send(cmd, check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_SET_FILE))
    ltx_helper.expect_exact(msgpack.packb(path_str))

    assert os.path.isfile(path_str)


def test_env_local(ltx_helper):
    """
    Test ENV command on single slot.
    """
    for i in range(0, MAX_ENVS):
        key = f"mykey{i}"
        value = f"myvalue{i}"

        cmd = bytes()
        cmd += msgpack.packb(LTX_ENV)
        cmd += msgpack.packb(i)
        cmd += msgpack.packb(key)
        cmd += msgpack.packb(value)

        ltx_helper.send(cmd)


def test_env_global(ltx_helper):
    """
    Test ENV command for all slots.
    """
    key = "mykey"
    value = "myvalue"

    cmd = bytes()
    cmd += msgpack.packb(LTX_ENV)
    cmd += msgpack.packb(ALL_SLOTS)
    cmd += msgpack.packb(key)
    cmd += msgpack.packb(value)

    ltx_helper.send(cmd)


def test_env_out_of_bound_error(ltx_helper):
    """
    Test ENV command on out-of-bound slot.
    """
    key = f"mykey"
    value = f"myvalue"

    cmd = bytes()
    cmd += msgpack.packb(LTX_ENV)
    cmd += msgpack.packb(MAX_SLOTS + 1)
    cmd += msgpack.packb(key)
    cmd += msgpack.packb(value)

    ltx_helper.send(cmd, check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("Out of bound slot ID"))


def test_env_too_many_error(ltx_helper):
    """
    Test ENV command when saturating the number of environment variables.
    """
    # saturate the amount of env variables
    for i in range(0, MAX_ENVS):
        key = f"mykey{i}"
        value = f"myvalue{i}"

        cmd = bytes()
        cmd += msgpack.packb(LTX_ENV)
        cmd += msgpack.packb(0)
        cmd += msgpack.packb(key)
        cmd += msgpack.packb(value)

        ltx_helper.send(cmd)

    # add just one more key and check for errors
    key = "mykey" + str(MAX_ENVS + 1)
    value = "myvalue" + str(MAX_ENVS + 1)

    cmd = bytes()
    cmd += msgpack.packb(LTX_ENV)
    cmd += msgpack.packb(0)
    cmd += msgpack.packb(key)
    cmd += msgpack.packb(value)

    ltx_helper.send(cmd, check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb(
        "Set too many environment variables"))


def test_cwd_local(ltx_helper, tmpdir):
    """
    Test CWD command on single slot.
    """
    for i in range(0, 128):
        cmd = bytes()
        cmd += msgpack.packb(LTX_CWD)
        cmd += msgpack.packb(i)
        cmd += msgpack.packb(str(tmpdir))

        ltx_helper.send(cmd)


def test_cwd_global(ltx_helper, tmpdir):
    """
    Test CWD command on single slot.
    """
    cmd = bytes()
    cmd += msgpack.packb(LTX_CWD)
    cmd += msgpack.packb(ALL_SLOTS)
    cmd += msgpack.packb(str(tmpdir))

    ltx_helper.send(cmd)


def test_cwd_out_of_bound_error(ltx_helper, tmpdir):
    """
    Test CWD command on out-of-bound slot.
    """
    cmd = bytes()
    cmd += msgpack.packb(LTX_CWD)
    cmd += msgpack.packb(MAX_SLOTS + 1)
    cmd += msgpack.packb(str(tmpdir))

    ltx_helper.send(cmd, check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("Out of bound slot ID"))


def test_cwd_dir_does_not_exist_error(ltx_helper):
    """
    Test CWD command with non-existing directory.
    """
    cmd = bytes()
    cmd += msgpack.packb(LTX_CWD)
    cmd += msgpack.packb(0)
    cmd += msgpack.packb("/this/dir/doesnt/exist")

    ltx_helper.send(cmd, check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("CWD directory does not exist"))


def test_exec(ltx_helper):
    """
    Test EXEC command on single slot.
    """
    slot = 0
    start_t = time.monotonic_ns()

    # run command
    cmd = bytes()
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("uname")

    ltx_helper.send(cmd)

    # read logs
    ltx_helper.expect_exact(msgpack.packb(LTX_LOG))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()
    ltx_helper.expect_exact(msgpack.packb('Linux\n'))

    # read result
    ltx_helper.expect_exact(msgpack.packb(LTX_RESULT))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(os.CLD_EXITED))
    ltx_helper.expect_exact(msgpack.packb(0))


def test_exec_out_of_bound_error(ltx_helper):
    """
    Test EXEC command on out-of-bounds slot.
    """
    cmd = bytes()
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(MAX_SLOTS + 1)
    cmd += msgpack.packb("test")

    ltx_helper.send(cmd, check_echo=False)
    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("Out of bound slot ID"))


def test_exec_reserved_error(ltx_helper):
    """
    Test EXEC command when the same slot is used two times.
    """
    slot = 0

    cmd = bytes()
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("sleep 0.5")
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("echo ciao")

    ltx_helper.send(cmd)

    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("Execution slot is reserved"))

    time.sleep(0.5)


def test_exec_env_local(ltx_helper):
    """
    Test EXEC command after setting environ variable in a single slot.
    """
    start_t = time.monotonic_ns()
    slot = 0

    cmd = bytes()
    cmd += msgpack.packb(LTX_ENV)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("MYKEY")
    cmd += msgpack.packb("MYVAL")
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("echo -n $MYKEY")

    ltx_helper.send(cmd)

    # read logs
    ltx_helper.expect_exact(msgpack.packb(LTX_LOG))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb('MYVAL'))

    # read result
    ltx_helper.expect_exact(msgpack.packb(LTX_RESULT))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(os.CLD_EXITED))
    ltx_helper.expect_exact(msgpack.packb(0))


def test_exec_env_global(ltx_helper):
    """
    Test EXEC command after setting global environ variable.
    """
    start_t = time.monotonic_ns()
    slot = 0

    cmd = bytes()
    cmd += msgpack.packb(LTX_ENV)
    cmd += msgpack.packb(ALL_SLOTS)
    cmd += msgpack.packb("MYKEY")
    cmd += msgpack.packb("MYVAL")
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("echo -n $MYKEY")

    ltx_helper.send(cmd)

    # read logs
    ltx_helper.expect_exact(msgpack.packb(LTX_LOG))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb('MYVAL'))

    # read result
    ltx_helper.expect_exact(msgpack.packb(LTX_RESULT))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(os.CLD_EXITED))
    ltx_helper.expect_exact(msgpack.packb(0))


def test_exec_cwd_local(ltx_helper, tmpdir):
    """
    Test EXEC command after setting current working directory in one slot.
    """
    start_t = time.monotonic_ns()
    slot = 0

    cmd = bytes()
    cmd += msgpack.packb(LTX_CWD)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb(str(tmpdir))
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("echo -n $PWD")

    ltx_helper.send(cmd)

    # read logs
    ltx_helper.expect_exact(msgpack.packb(LTX_LOG))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(str(tmpdir)))

    # read result
    ltx_helper.expect_exact(msgpack.packb(LTX_RESULT))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(os.CLD_EXITED))
    ltx_helper.expect_exact(msgpack.packb(0))


def test_exec_cwd_global(ltx_helper, tmpdir):
    """
    Test EXEC command after setting current working directory in one slot.
    """
    start_t = time.monotonic_ns()
    slot = 0

    cmd = bytes()
    cmd += msgpack.packb(LTX_CWD)
    cmd += msgpack.packb(ALL_SLOTS)
    cmd += msgpack.packb(str(tmpdir))
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("echo -n $PWD")

    ltx_helper.send(cmd)

    # read logs
    ltx_helper.expect_exact(msgpack.packb(LTX_LOG))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(str(tmpdir)))

    # read result
    ltx_helper.expect_exact(msgpack.packb(LTX_RESULT))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(os.CLD_EXITED))
    ltx_helper.expect_exact(msgpack.packb(0))


def test_kill(ltx_helper):
    """
    Test KILL command on single slot.
    """
    slot = 0
    start_t = time.monotonic_ns()

    # run command
    cmd = bytes()
    cmd += msgpack.packb(LTX_EXEC)
    cmd += msgpack.packb(slot)
    cmd += msgpack.packb("sleep 3")

    ltx_helper.send(cmd)

    # kill command
    cmd = bytes()
    cmd += msgpack.packb(LTX_KILL)
    cmd += msgpack.packb(slot)

    ltx_helper.send(cmd)

    # read result
    ltx_helper.expect_exact(msgpack.packb(LTX_RESULT))
    ltx_helper.expect_exact(msgpack.packb(slot))

    time_ns = ltx_helper.unpack_next()
    assert start_t < time_ns < time.monotonic_ns()

    ltx_helper.expect_exact(msgpack.packb(os.CLD_KILLED))
    ltx_helper.expect_exact(msgpack.packb(signal.SIGKILL))


def test_kill_out_of_bound_error(ltx_helper):
    """
    Test KILL command with out-of-bound slot.
    """
    cmd = bytes()
    cmd += msgpack.packb(LTX_KILL)
    cmd += msgpack.packb(MAX_SLOTS)

    ltx_helper.send(cmd, check_echo=False)

    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("Out of bound slot ID"))


def test_kill_non_exec_slot_error(ltx_helper):
    """
    Test KILL command on a non-executing slot.
    """
    cmd = bytes()
    cmd += msgpack.packb(LTX_KILL)
    cmd += msgpack.packb(0)

    ltx_helper.send(cmd, check_echo=False)

    ltx_helper.expect_exact(msgpack.packb(LTX_ERROR))
    ltx_helper.expect_exact(msgpack.packb("No command running"))
