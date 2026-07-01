"""Daemon lifecycle: framing I/O, error paths, and socket bind/reclaim races."""

import json
import os
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from agent_input_sanitizer.secrets import daemon as S


def _drain(sock: socket.socket) -> object:
    header = b""
    while len(header) < 4:
        header += sock.recv(4 - len(header))
    (length,) = struct.unpack(">I", header)
    buf = b""
    while len(buf) < length:
        buf += sock.recv(length - len(buf))
    return json.loads(buf.decode("utf-8"))


# ─── _write_frame / _serve_one over a socketpair ─────────────────────────────


def test_write_frame_round_trips():
    a, b = socket.socketpair()
    try:
        S._write_frame(a, {"hello": "world"})
        assert _drain(b) == {"hello": "world"}
    finally:
        a.close()
        b.close()


def test_serve_one_non_dict_request_closes_silently():
    a, b = socket.socketpair()
    try:
        body = json.dumps([1, 2, 3]).encode("utf-8")  # a list, not a dict
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)  # must return without writing a response
        a.settimeout(1)
        assert a.recv(4) == b""  # peer closed, no frame written
    finally:
        a.close()


def test_serve_one_engine_failure_writes_error(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("detection blew up")

    monkeypatch.setattr(S, "handle_request", _boom)
    a, b = socket.socketpair()
    try:
        body = json.dumps({"text": "key: AKIAIOSFODNN7EXAMPLE"}).encode("utf-8")
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)
        assert _drain(a) == {"error": "redaction failed"}
    finally:
        a.close()


def test_serve_one_malformed_json_body_closes():
    a, b = socket.socketpair()
    try:
        body = b"{not valid json"
        a.sendall(struct.pack(">I", len(body)) + body)
        S._serve_one(b)  # ValueError swallowed, connection closed
        a.settimeout(1)
        assert a.recv(4) == b""
    finally:
        a.close()


# ─── _bind_or_exit / _reclaim_stale_socket ───────────────────────────────────


def test_reclaim_stale_socket_removes_dead_file(tmp_path):
    socket_path = str(tmp_path / "s.sock")
    # A stale socket FILE with nobody listening: a leftover bind, then closed.
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(socket_path)
    dead.close()  # file remains on disk, but no listener
    assert Path(socket_path).exists()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert S._bind_or_exit(sock, socket_path) is True
    finally:
        sock.close()


def test_bind_or_exit_returns_false_when_live_daemon_owns_path(tmp_path):
    socket_path = str(tmp_path / "s.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not Path(socket_path).exists() and time.time() < deadline:
        time.sleep(0.02)
    assert Path(socket_path).exists()
    try:
        # A second daemon trying the same live path must exit quietly (False).
        second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert S._bind_or_exit(second, socket_path) is False
        finally:
            second.close()
        # And a full second serve() likewise returns without taking over.
        S.serve(socket_path, threading.Event())  # returns because path is live
    finally:
        stop.set()
        thread.join(timeout=5)


def test_bind_or_exit_reraises_non_addrinuse(tmp_path):
    # A bind error that is NOT EADDRINUSE (here ENOENT: the parent directory does
    # not exist) must propagate, not be swallowed as a stale-socket case.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    missing = str(tmp_path / "no_such_dir" / "s.sock")
    try:
        with pytest.raises(OSError):
            S._bind_or_exit(sock, missing)
    finally:
        sock.close()


# ─── main() ──────────────────────────────────────────────────────────────────


def test_main_usage_error_on_wrong_argc():
    with pytest.raises(SystemExit):
        S.main([])
    with pytest.raises(SystemExit):
        S.main(["a", "b"])


def test_main_serves_until_stopped(tmp_path, monkeypatch):
    socket_path = str(tmp_path / "s.sock")
    called = {}

    def _fake_serve(path):
        called["path"] = path

    monkeypatch.setattr(S, "serve", _fake_serve)
    S.main([socket_path])
    assert called["path"] == socket_path


def test_serve_creates_socket_dir_with_mode(tmp_path):
    nested = tmp_path / "sub" / "dir"
    socket_path = str(nested / "s.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not Path(socket_path).exists() and time.time() < deadline:
        time.sleep(0.02)
    try:
        assert Path(socket_path).exists()
        assert oct(os.stat(nested).st_mode)[-3:] == "700"
    finally:
        stop.set()
        thread.join(timeout=5)
