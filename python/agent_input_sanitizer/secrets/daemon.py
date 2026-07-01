"""Long-lived redaction daemon over a Unix socket.

Spawning a fresh interpreter and reloading the detect-secrets plugin set for
every secret-shaped payload is slow enough to time out under load. This daemon
pays that cost ONCE — :func:`~agent_input_sanitizer.secrets.configure_plugins` at
startup — then serves each request as just a scan, so a transient stall fails
only that one call and the next succeeds.

Wire protocol (both directions): a 4-byte big-endian unsigned length prefix then
that many bytes of UTF-8 JSON. Request: ``{"text", "map", "web_ingress",
"env_secrets"}``. Response: exactly what a one-shot
:func:`~agent_input_sanitizer.secrets.handle_request` returns — the response object, or
JSON ``null`` for the "nothing to redact" case, or ``{"error"}`` when the daemon
could not vet the input. ``env_secrets`` is ``name -> value`` supplied per
request (the socket may be shared across sessions, so the daemon must redact the
REQUESTER's keys, not its own environment).
"""

import contextlib
import errno
import fcntl
import json
import os
import socket
import struct
import threading

from . import RedactorConfig, configure_plugins, handle_request
from .engine import redact_configured

# Refuse absurd frames rather than buffer unbounded; the magnitude is arbitrary
# (the cap *boundary* is what matters).
FRAME_CAP = 16 * 1024 * 1024


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly ``n`` bytes, or None if the peer closed/reset mid-frame."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(conn: socket.socket) -> object | None:
    """Decode one length-prefixed JSON frame, or None on a closed, short, or
    over-cap connection (the caller fails that one request closed)."""
    header = _recv_exact(conn, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length > FRAME_CAP:
        return None
    body = _recv_exact(conn, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def _write_frame(conn: socket.socket, obj: object) -> None:
    body = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body)


def _request_config(req: dict) -> RedactorConfig:
    """Build a per-request config from the wire frame. ``env_secrets`` is filtered
    to str→str (the socket may live in a shared tmpdir, so a request is not fully
    trusted — a non-str value would crash the env-bound length check). The daemon
    always uses the full detector set (high_confidence is a startup-scan concern,
    not a per-request one) and the shared invisible charset."""
    env_secrets = req.get("env_secrets")
    provider_vars = (
        {k: v for k, v in env_secrets.items() if isinstance(v, str)}
        if isinstance(env_secrets, dict)
        else {}
    )
    return RedactorConfig(
        provider_vars=provider_vars,
        web_ingress=bool(req.get("web_ingress", False)),
    )


def _serve_one(conn: socket.socket) -> None:
    """Handle one connection: read a request frame, write the response frame. Any
    per-connection fault closes only this connection — a malformed frame or a
    dropped client must never take the daemon down."""
    try:
        req = _read_frame(conn)
        if not isinstance(req, dict):
            return  # no/garbage request frame: just close this connection
        try:
            result = handle_request(
                str(req.get("text", "")),
                bool(req.get("map", False)),
                _request_config(req),
                redact_configured,
            )
        except Exception:  # noqa: BLE001
            # A genuine detection failure for THIS request: signal the client so it
            # fails THAT call closed, but keep the daemon alive.
            _write_frame(conn, {"error": "redaction failed"})
            return
        _write_frame(conn, result)
    except (OSError, ValueError):
        # ValueError: malformed JSON body. OSError: socket reset mid-frame. Both
        # are this client's problem; drop the connection and keep serving.
        pass
    finally:
        conn.close()


def _bind_or_exit(sock: socket.socket, socket_path: str) -> bool:
    """Bind ``sock`` at ``socket_path``; the bind is the cross-process mutex that
    makes a respawn idempotent. Return False (caller exits quietly) when a LIVE
    daemon already owns the path; clear a STALE socket file and rebind otherwise."""
    try:
        sock.bind(socket_path)
    except OSError as exc:
        if exc.errno != errno.EADDRINUSE:
            raise
    else:
        return True
    # The path is occupied. "Is it stale? then unlink and rebind" is a check-then-act
    # that two daemons racing to reclaim the SAME stale path can interleave; serialize
    # that critical section on a sibling lock file.
    lock_path = socket_path + ".lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        return _reclaim_stale_socket(sock, socket_path)
    finally:
        os.close(lock_fd)


def _reclaim_stale_socket(sock: socket.socket, socket_path: str) -> bool:
    """Under the reclaim lock: probe the occupied ``socket_path``. Return False if a
    LIVE daemon answers (we lost the race); otherwise clear the stale file and rebind."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(socket_path)
    except OSError:
        pass  # nobody listening: a stale socket file
    else:
        return False  # a live daemon answered; we lost the race
    finally:
        probe.close()
    os.unlink(socket_path)
    sock.bind(socket_path)
    return True


def serve(socket_path: str, stop: threading.Event | None = None) -> None:
    """Serve redactions over the Unix socket at ``socket_path`` until ``stop`` is
    set (or forever).

    Configures the detect-secrets plugin set ONCE and primes the mapping cache
    with a warm-up scan BEFORE binding, so a bound socket implies a ready daemon.
    ``stop`` is a graceful-shutdown seam for tests; production passes none.
    """
    os.makedirs(os.path.dirname(socket_path) or ".", mode=0o700, exist_ok=True)
    with configure_plugins():
        redact_configured(
            "warm up the detect-secrets mapping cache", None, RedactorConfig()
        )
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if not _bind_or_exit(sock, socket_path):
            sock.close()
            return
        try:
            os.chmod(socket_path, 0o600)
            sock.listen(64)
            sock.settimeout(0.5)
            while not (stop is not None and stop.is_set()):
                try:
                    conn, _ = sock.accept()
                except TimeoutError:
                    continue
                _serve_one(conn)
        finally:
            sock.close()
            with contextlib.suppress(OSError):
                os.unlink(socket_path)


def main(argv: list[str] | None = None) -> None:
    """CLI: ``agent-secret-redactor-daemon <socket-path>``."""
    import sys

    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        raise SystemExit("usage: agent-secret-redactor-daemon <socket-path>")
    serve(args[0])
