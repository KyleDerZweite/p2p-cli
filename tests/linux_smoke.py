#!/usr/bin/env python3
"""Exercise real Linux terminals, isolated identities, bidirectional chat and history.

Run after cargo build: python3 tests/linux_smoke.py [path/to/p2p-cli]
Uses only Python's standard library, loopback sockets, and temporary XDG profiles.
"""
import fcntl
import os
from pathlib import Path
import pty
import select
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time

BINARY = str(Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/p2p-cli").resolve())


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Terminal:
    def __init__(self, env, args):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 220, 0, 0))
        self.process = subprocess.Popen([BINARY, *args], stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        os.close(slave)
        self.output = b""

    def read(self, duration=0.1):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], max(0, deadline-time.monotonic()))[0]:
                try:
                    chunk = os.read(self.master, 65536)
                    if not chunk:
                        break
                    self.output += chunk
                except OSError:
                    break
        return self.output

    def send(self, text):
        os.write(self.master, text.encode())

    def close(self):
        if self.process.poll() is None:
            self.send("\x03")
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.read()
        os.close(self.master)


def until(terminals, predicate, description, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for terminal in terminals:
            terminal.read()
            if terminal.process.poll() is not None:
                raise AssertionError(f"process exited during {description}: {terminal.output[-3000:]!r}")
        if predicate():
            return
    raise AssertionError(f"timeout: {description}\n" + "\n".join(repr(t.output[-4000:]) for t in terminals))


def profile(root):
    env = os.environ.copy()
    env.pop("DB_KEY", None)
    for name, child in [("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache")]:
        path = root / child
        path.mkdir(parents=True)
        env[name] = str(path)
    env["TERM"] = "xterm-256color"
    return env


def messages(root):
    paths = list((root / "data").rglob("messages.db"))
    if not paths:
        return []
    with sqlite3.connect(paths[0]) as database:
        return database.execute("SELECT content, is_outgoing FROM messages ORDER BY id").fetchall()


def run():
    with tempfile.TemporaryDirectory(prefix="p2p-linux-smoke-") as directory:
        root = Path(directory)
        roots = [root / "alice", root / "bob"]
        envs = [profile(path) for path in roots]
        ports = [port(), port()]
        while ports[0] == ports[1]:
            ports[1] = port()
        invitation = subprocess.check_output([BINARY, "--invite", "-p", str(ports[0]), "--address", f"127.0.0.1:{ports[0]}"], env=envs[0], text=True).strip()
        assert invitation.startswith("p2p-cli:v1:"), invitation
        for cycle in range(2):
            terminals = []
            try:
                alice = Terminal(envs[0], ["-p", str(ports[0])])
                terminals.append(alice)
                until(terminals, lambda: b"Listening" in alice.output or b"Online" in alice.output, "listener ready")
                bob = Terminal(envs[1], ["-p", str(ports[1]), "--connect", invitation])
                terminals.append(bob)
                until(terminals, lambda: b"Accept" in alice.output, "incoming approval")
                alice.send("a")
                until(terminals, lambda: b"Connected" in bob.output, "client connected")
                if cycle:
                    until(terminals, lambda: b"smoke-alice-0" in alice.output and b"smoke-bob-0" in bob.output, "history restored after restart")
                alice.send(f"smoke-alice-{cycle}\r")
                until(terminals, lambda: f"smoke-alice-{cycle}".encode() in bob.output, "Alice to Bob")
                bob.send(f"smoke-bob-{cycle}\r")
                until(terminals, lambda: f"smoke-bob-{cycle}".encode() in alice.output, "Bob to Alice")
            finally:
                for terminal in terminals:
                    terminal.close()
        for path in roots:
            rows = messages(path)
            assert len(rows) == 4, (path, len(rows))
            assert sum(row[1] for row in rows) == 2, rows
            assert all("smoke-" not in row[0] for row in rows), "chat stored in plaintext"
        print("PASS: independent profiles, invitation approval, bidirectional chat, restart/reconnect, encrypted history")


if __name__ == "__main__":
    run()
