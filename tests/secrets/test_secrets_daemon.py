"""Daemon tests: wire framing (fake connection) and a live-socket round-trip."""

import json
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from agent_input_sanitizer.secrets import daemon as S


# ─── Framing (_read_frame) over a fake connection ────────────────────────────


class _FakeConn:
    def __init__(self, data: bytes):
        self._data = bytes(data)
        self._pos = 0

    def recv(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


def _frame(length: int, body: bytes) -> bytes:
    return struct.pack(">I", length) + body


def test_read_frame_closed_connection_returns_none():
    assert S._read_frame(_FakeConn(b"")) is None


def test_read_frame_short_body_returns_none():
    assert S._read_frame(_FakeConn(_frame(10, b"abc"))) is None


def test_read_frame_wellformed_returns_exact_object():
    body = json.dumps({"text": "hi", "map": True}).encode("utf-8")
    assert S._read_frame(_FakeConn(_frame(len(body), body))) == {
        "text": "hi",
        "map": True,
    }


def test_read_frame_at_cap_boundary_is_accepted(monkeypatch):
    monkeypatch.setattr(S, "FRAME_CAP", 8)
    body = b"[1,2,34]"
    assert len(body) == S.FRAME_CAP
    assert S._read_frame(_FakeConn(_frame(8, body))) == [1, 2, 34]


def test_read_frame_over_cap_is_rejected_before_body(monkeypatch):
    monkeypatch.setattr(S, "FRAME_CAP", 8)
    assert S._read_frame(_FakeConn(_frame(9, b"123456789"))) is None


# ─── Per-request config from the wire frame ──────────────────────────────────


def test_request_config_filters_non_str_env_secrets():
    config = S._request_config(
        {
            "env_secrets": {"GOOD": "value", "BAD": 123, "ALSO": None},
            "web_ingress": True,
        }
    )
    assert config.provider_vars == {"GOOD": "value"}
    assert config.web_ingress is True


def test_request_config_missing_env_secrets_is_empty():
    config = S._request_config({"text": "x"})
    assert config.provider_vars == {}
    assert config.web_ingress is False


# ─── Live socket round-trip ──────────────────────────────────────────────────


def _client_request(socket_path: str, request: dict) -> object:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    try:
        body = json.dumps(request).encode("utf-8")
        sock.sendall(struct.pack(">I", len(body)) + body)
        header = sock.recv(4)
        (length,) = struct.unpack(">I", header)
        buf = b""
        while len(buf) < length:
            buf += sock.recv(length - len(buf))
        return json.loads(buf.decode("utf-8"))
    finally:
        sock.close()


@pytest.fixture
def daemon(tmp_path):
    socket_path = str(tmp_path / "redactor.sock")
    stop = threading.Event()
    thread = threading.Thread(target=S.serve, args=(socket_path, stop), daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not Path(socket_path).exists() and time.time() < deadline:
        time.sleep(0.02)
    assert Path(socket_path).exists(), "daemon did not bind its socket"
    yield socket_path
    stop.set()
    thread.join(timeout=5)


def test_daemon_plain_redaction(daemon):
    resp = _client_request(daemon, {"text": "key: AKIAIOSFODNN7EXAMPLE", "map": False})
    assert resp["text"] == "key: [REDACTED: AWS Access Key]"
    assert "AWS Access Key" in resp["found"]


def test_daemon_nothing_to_redact_returns_null(daemon):
    assert _client_request(daemon, {"text": "just prose", "map": False}) is None


def test_daemon_map_mode_round_trip(daemon):
    text = "password: SuperSecretP4ssword123456\n"
    resp = _client_request(daemon, {"text": text, "map": True})
    out, last = [], 0
    for p in resp["pairs"]:
        out.append(resp["text"][last : p["start"]])
        out.append(p["original"])
        last = p["start"] + len(p["placeholder"])
    out.append(resp["text"][last:])
    assert "".join(out) == text


def test_daemon_env_secret_redaction(daemon):
    value = "qZ7vK2mNp9rT4wX1cY6bA8dF3gH5jL0e"
    resp = _client_request(
        daemon,
        {"text": f"leaked {value}", "map": False, "env_secrets": {"VENICE_KEY": value}},
    )
    assert value not in resp["text"]
    assert "VENICE_KEY" in resp["found"]


def test_daemon_web_ingress_flag(daemon):
    text = "next_token: abcdefghij1234567890XYZ"
    local = _client_request(daemon, {"text": text, "map": False})
    web = _client_request(daemon, {"text": text, "map": False, "web_ingress": True})
    assert local is None  # benign cursor kept for local output
    assert web is not None and "[REDACTED" in web["text"]


def test_daemon_survives_malformed_frame_then_serves(daemon):
    # A garbage (non-JSON) frame closes only that connection; the next succeeds.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(daemon)
    body = b"not json at all"
    sock.sendall(struct.pack(">I", len(body)) + body)
    sock.close()
    resp = _client_request(daemon, {"text": "key: AKIAIOSFODNN7EXAMPLE", "map": False})
    assert "AWS Access Key" in resp["found"]
