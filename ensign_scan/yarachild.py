"""The YARA pass, in its own process.

yara-x reads a file by memory-mapping it: the kernel loads pages of the
file into memory as they are touched. If another program makes the file
shorter while YARA is reading it (Steam updating a game, say), the next
page touched no longer exists, and the kernel stops the whole process
with SIGBUS. Python can't catch that. In Ensign's own process it would end
the run on the spot, with no report.

So the scanning happens here, in a child process that lives for one
sweep. A SIGBUS (or any other crash) ends only the child: Ensign records
that the file changed during the YARA pass, and starts a new child for the
next file. It also keeps Ensign responsive, since yara-x holds Python's
interpreter lock for as long as a scan runs.

How they talk:
  * the compiled rules go in once, on the child's stdin (serialized by
    yara-x, in memory only; never written to disk);
  * each file goes over a Unix socket as its open descriptor (SCM_RIGHTS),
    the one the sweep already holds, with a short JSON request; the child
    scans /proc/self/fd/N, which is that very file, and answers in JSON.
    Messages on a SOCK_SEQPACKET socket arrive whole, one per request.

The child runs as the same user as Ensign, with the same Python and the
same import path, minus the current folder (so a planted module there
can't load).
"""
from __future__ import annotations

import io
import json
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

_MAX_HITS = 20          # per file; the first one decides
_REPLY_SIZE = 65536


class ChildFailed(Exception):
    """The child process ended or stopped answering mid-file."""


def _describe_exit(code: int | None) -> str:
    if code is not None and code < 0:
        sig = -code
        if sig == signal.SIGBUS:
            return ("the file changed while YARA was reading it (it got shorter, so the YARA "
                    "process was stopped by SIGBUS)")
        try:
            name = signal.Signals(sig).name
        except ValueError:
            name = f"signal {sig}"
        return f"the YARA process was stopped by {name}"
    return f"the YARA process ended unexpectedly (exit code {code})"


class Worker:
    """Parent side: starts the child on first use, and again after a crash."""

    def __init__(self, compiled: dict, timeout: int) -> None:
        # bucket -> serialized rules (yara-x Rules.serialize_into)
        self._payload = {}
        for bucket, rules in compiled.items():
            buf = io.BytesIO()
            rules.serialize_into(buf)
            self._payload[bucket] = buf.getvalue()
        self.timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._sock: socket.socket | None = None

    def _start(self) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        package_parent = str(Path(__file__).resolve().parent.parent)
        path = [package_parent] + [p for p in sys.path if p and p != os.getcwd()]
        code = ("import sys; sys.path[:] = " + repr(path) + "; "
                "from ensign_scan import yarachild; yarachild.child_main(" + str(child.fileno()) + ")")
        self._proc = subprocess.Popen(
            [sys.executable, "-I", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, pass_fds=[child.fileno()], close_fds=True)
        child.close()
        self._sock = parent
        header = json.dumps({"buckets": {b: len(data) for b, data in self._payload.items()},
                             "timeout": self.timeout}).encode() + b"\n"
        try:
            self._proc.stdin.write(header)
            for data in self._payload.values():
                self._proc.stdin.write(data)
            self._proc.stdin.close()
        except OSError:
            pass  # it died at once; the first request reports why

    def scan(self, fd: int, buckets: list[str]) -> list[tuple[str, int | None]]:
        """(signature name, offset) hits for the open file `fd`.
        Raises ChildFailed if the child crashed or ran out of time."""
        if self._proc is None or self._proc.poll() is not None:
            self.close()
            self._start()
        request = json.dumps({"buckets": buckets}).encode()
        self._sock.settimeout(self.timeout + 120)  # the child enforces the real limit
        try:
            socket.send_fds(self._sock, [request], [fd])
            reply = self._sock.recv(_REPLY_SIZE)
        except TimeoutError:
            self.close(kill=True)
            raise ChildFailed(f"YARA didn't finish within {self.timeout}s") from None
        except OSError:
            reply = b""
        if not reply:
            code = self._proc.wait(timeout=30) if self._proc else None
            self.close()
            raise ChildFailed(_describe_exit(code))
        answer = json.loads(reply)
        if "error" in answer:
            if answer.get("timeout"):
                raise ChildFailed(f"YARA didn't finish within {self.timeout}s (timed out)")
            raise ChildFailed(answer["error"])
        return [(name, offset) for name, offset in answer["hits"]]

    def close(self, kill: bool = False) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if self._proc is not None:
            if kill and self._proc.poll() is None:
                self._proc.kill()
            try:
                self._proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            self._proc = None


def _read_exact(stream, n: int) -> bytes:
    data = stream.read(n)
    if data is None or len(data) != n:
        raise EOFError("rules cut short")
    return data


def child_main(sock_fd: int) -> None:
    """Child side: load the rules from stdin, then answer one request per
    file until the parent closes the socket."""
    import yara_x
    stdin = sys.stdin.buffer
    header = json.loads(stdin.readline())
    rules = {b: yara_x.Rules.deserialize_from(io.BytesIO(_read_exact(stdin, n)))
             for b, n in header["buckets"].items()}
    timeout = int(header["timeout"])
    sock = socket.socket(fileno=sock_fd)
    while True:
        try:
            msg, fds, _flags, _addr = socket.recv_fds(sock, _REPLY_SIZE, 1)
        except OSError:
            return
        if not msg:
            return
        try:
            request = json.loads(msg)
            fd = fds[0]
            hits = []
            for bucket in request["buckets"]:
                scanner = yara_x.Scanner(rules[bucket])
                scanner.set_timeout(timeout)
                results = scanner.scan_file(f"/proc/self/fd/{fd}")
                for rule in results.matching_rules:
                    offsets = [m.offset for p in rule.patterns for m in p.matches]
                    name = dict(rule.metadata).get("clamav_name", rule.identifier)
                    hits.append([name, min(offsets) if offsets else None])
            reply = {"hits": hits[:_MAX_HITS]}
        except yara_x.TimeoutError:
            reply = {"error": "timed out", "timeout": True}
        except Exception as exc:
            reply = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            for extra in fds:
                os.close(extra)
        sock.send(json.dumps(reply).encode())
