"""
rbw-qr-pinentry — Custom pinentry for rbw that unlocks via a phone QR scan.

When rbw-agent requests a PIN (GETPIN), this program:
  1. Starts a temporary HTTP server on 127.0.0.1:18765
  2. Generates a high-entropy one-time token
  3. Prints a large ASCII QR code encoding a public HTTPS URL
     (see RBW_QR_PUBLIC_BASE_URL) for /s/<token>
  4. Serves a mobile-friendly password form at /s/<token>
  5. Accepts the master password via POST (token-validated, 90s TTL, single-use)
  6. Returns it to rbw-agent via the Assuan protocol:  D <password>\\nOK
  7. Destroys the token and shuts down the server

Configure with:
  rbw config set pinentry $(command -v rbw-qr-pinentry)
  export RBW_QR_PUBLIC_BASE_URL=https://your-public-hostname.example
"""

from __future__ import annotations

import argparse
import html
import http.server
import io
import json
import os
import secrets
import signal
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
from typing import Optional

from rbw_qr_pinentry import __version__

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOST = "127.0.0.1"
PORT = 18765
TOKEN_TTL_SECONDS = 90
# Max incorrect master-password submissions before a new QR is required.
# Matches rbw's typical 3 re-prompts per unlock/login.
MAX_PASSWORD_FAILURES = 3
# Overall unlock-session lifetime across retries (seconds).
SESSION_MAX_AGE_SECONDS = TOKEN_TTL_SECONDS * MAX_PASSWORD_FAILURES + 60


def _public_base_url() -> str:
    """
    Public HTTPS origin used in the QR code (tunnel hostname).

    Set via environment, e.g.::

        export RBW_QR_PUBLIC_BASE_URL=https://pinentry.example.com

    No personal/default production domain is hard-coded.
    """
    raw = (
        os.environ.get("RBW_QR_PUBLIC_BASE_URL")
        or os.environ.get("RBW_QR_PINENTRY_PUBLIC_URL")
        or "https://pinentry.example.com"
    ).strip()
    return raw.rstrip("/")


PUBLIC_BASE_URL = _public_base_url()

# Assuan / gpg-error codes used by rbw (see doy/rbw pinentry.rs)
ERR_CANCELLED = 83886179  # GPG_ERR_SOURCE_PINENTRY | GPG_ERR_CANCELED
ERR_TIMEOUT = 83886383  # GPG_ERR_SOURCE_PINENTRY | GPG_ERR_TIMEOUT
ERR_GENERAL = 83886179

VERSION = __version__

DEFAULT_HINT = (
    "Password is incorrect. Check Caps Lock, keyboard layout, "
    "and try again carefully."
)


def _state_dir() -> str:
    base = os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("TMPDIR") or "/tmp"
    path = os.path.join(base, f"rbw-qr-pinentry-{os.getuid()}")
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _state_path() -> str:
    return os.path.join(_state_dir(), "session.json")


def _password_cache_path() -> str:
    return os.path.join(_state_dir(), "password.cache")


# How long a just-entered master password may be reused without a new QR.
# rbw unlock runs Login then Unlock as two agent calls; the second often asks
# for the same master password again after the first already succeeded.
PASSWORD_CACHE_TTL_SECONDS = 45


def save_password_cache(password: str) -> None:
    path = _password_cache_path()
    tmp = path + ".tmp"
    payload = {"password": password, "saved_at": time.time()}
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass


def load_password_cache() -> Optional[str]:
    path = _password_cache_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        saved_at = float(data.get("saved_at") or 0)
        password = data.get("password")
        if not password or not isinstance(password, str):
            return None
        if time.time() - saved_at > PASSWORD_CACHE_TTL_SECONDS:
            clear_password_cache()
            return None
        return password
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def clear_password_cache() -> None:
    path = _password_cache_path()
    try:
        # Best-effort wipe
        if os.path.isfile(path):
            with open(path, "r+", encoding="utf-8") as fh:
                data = fh.read()
                fh.seek(0)
                fh.write("\0" * len(data))
                fh.truncate()
            os.unlink(path)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass


def is_master_password_prompt(prompt: str, desc: str) -> bool:
    """
    True only for master-password style prompts.

    Must be False for 2FA/TOTP (Authenticator App, Email Code, Yubikey, …)
    so we never feed the master password into rbw as a TOTP code.
    """
    combined = f"{prompt}\n{desc}".lower()
    deny_markers = (
        "authenticator",
        "totp",
        "verification code",
        "6 digit",
        "6-digit",
        "yubikey",
        "email code",
        "two factor",
        "two-factor",
        "2fa",
        "client__id",
        "client__secret",
        "api key",
        "pin you received",
    )
    if any(m in combined for m in deny_markers):
        return False
    allow_markers = (
        "master password",
        "password",
        "unlock",
        "log in",
        "login",
    )
    return any(m in combined for m in allow_markers)


def is_totp_or_2fa_prompt(prompt: str, desc: str) -> bool:
    combined = f"{prompt}\n{desc}".lower()
    markers = (
        "authenticator",
        "totp",
        "verification code",
        "6 digit",
        "6-digit",
        "yubikey",
        "email code",
        "two factor",
        "two-factor",
        "2fa",
        "pin you received",
    )
    return any(m in combined for m in markers)


# ---------------------------------------------------------------------------
# Assuan helpers
# ---------------------------------------------------------------------------


def assuan_unescape(text: str) -> str:
    """Percent-decode Assuan parameters (%0A, %0D, %25, …)."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "%" and i + 2 < n:
            try:
                out.append(chr(int(text[i + 1 : i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(text[i])
        i += 1
    return "".join(out)


def assuan_escape(data: bytes) -> bytes:
    """Percent-encode Assuan data payloads (%, CR, LF)."""
    out = bytearray()
    for b in data:
        if b in (0x25, 0x0A, 0x0D):  # % \n \r
            out.extend(f"%{b:02X}".encode("ascii"))
        else:
            out.append(b)
    return bytes(out)


def assuan_ok(msg: str = "") -> None:
    if msg:
        sys.stdout.buffer.write(f"OK {msg}\n".encode("utf-8"))
    else:
        sys.stdout.buffer.write(b"OK\n")
    sys.stdout.buffer.flush()


def assuan_err(code: int, msg: str = "") -> None:
    if msg:
        sys.stdout.buffer.write(f"ERR {code} {msg}\n".encode("utf-8"))
    else:
        sys.stdout.buffer.write(f"ERR {code}\n".encode("utf-8"))
    sys.stdout.buffer.flush()


def assuan_data(payload: bytes) -> None:
    sys.stdout.buffer.write(b"D ")
    sys.stdout.buffer.write(assuan_escape(payload))
    sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


def assuan_status(keyword: str, *args: str) -> None:
    line = "S " + " ".join((keyword,) + args) + "\n"
    sys.stdout.buffer.write(line.encode("utf-8"))
    sys.stdout.buffer.flush()


# ---------------------------------------------------------------------------
# TTY / QR display (must never touch Assuan stdout)
# ---------------------------------------------------------------------------


class TtyWriter:
    """
    Write human-visible output to the controlling TTY and always mirror to
    stderr (so messages still appear if the agent has no TTY — check
    ``~/.local/share/rbw/agent.err``).
    """

    def __init__(self, ttyname: Optional[str] = None) -> None:
        self._fp = None
        candidates = []
        if ttyname:
            candidates.append(ttyname)
        candidates.extend(["/dev/tty", "/dev/console"])
        for path in candidates:
            try:
                self._fp = open(path, "w", encoding="utf-8", errors="replace")
                break
            except OSError:
                continue
        if self._fp is None:
            self._fp = sys.stderr

    def write(self, text: str) -> None:
        try:
            self._fp.write(text)
            self._fp.flush()
        except OSError:
            pass
        # Always mirror to stderr for agent logs / headless sessions
        if self._fp is not sys.stderr:
            try:
                sys.stderr.write(text)
                sys.stderr.flush()
            except OSError:
                pass

    def close(self) -> None:
        if self._fp is not None and self._fp not in (sys.stderr, sys.stdout):
            try:
                self._fp.close()
            except OSError:
                pass


def render_qr_ascii(url: str) -> str:
    """Return a large ASCII QR code for *url*, or a fallback text block."""
    try:
        import qrcode
    except ImportError:
        return (
            "\n[qrcode package not installed — scan unavailable]\n"
            f"Open this URL on your phone:\n  {url}\n"
            "Install with:  pip install 'rbw-qr-pinentry'\n"
        )

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=1,
    )
    qr.add_data(url)
    qr.make(fit=True)

    buf = io.StringIO()
    # invert=True often scans better in dark terminals
    try:
        qr.print_ascii(out=buf, invert=True)
    except TypeError:
        qr.print_ascii(out=buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Persistent unlock session (survives pinentry process restarts on retry)
# ---------------------------------------------------------------------------


class PersistentUnlockState:
    """
    Disk-backed unlock session shared across rbw's pinentry re-invocations.

    rbw spawns a new pinentry process for each attempt and passes SETERROR when
    the previous master password was wrong. We reuse the same QR/token for up to
    MAX_PASSWORD_FAILURES failures, then mint a new token (new QR scan required).

    After master password is submitted, rbw may start a *new* pinentry for 2FA.
    We keep ``previous_token`` so the phone (still polling the old URL) receives
    status=continue and can redirect to the new form without a second scan.

    phase:
      waiting   — form open, accepting input
      submitted — secret handed to rbw; phone should poll for retry/continue/success
      retry     — wrong secret; form should show hint and accept again
      success   — optional terminal marker
    """

    HANDOFF_TTL_SECONDS = 120

    def __init__(self) -> None:
        self.token: Optional[str] = None
        self.created_at: float = 0.0  # wall clock
        self.failures: int = 0
        self.hint: str = ""
        self.accepting: bool = True
        self.phase: str = "waiting"
        self.submitted_at: float = 0.0
        self.kind: str = "password"  # password | totp | other
        self.previous_token: Optional[str] = None
        self.handoff_until: float = 0.0

    @classmethod
    def load(cls) -> "PersistentUnlockState":
        path = _state_path()
        state = cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return state
        if not isinstance(data, dict):
            return state
        state.token = data.get("token") or None
        try:
            state.created_at = float(data.get("created_at") or 0)
        except (TypeError, ValueError):
            state.created_at = 0.0
        try:
            state.failures = int(data.get("failures") or 0)
        except (TypeError, ValueError):
            state.failures = 0
        try:
            state.submitted_at = float(data.get("submitted_at") or 0)
        except (TypeError, ValueError):
            state.submitted_at = 0.0
        try:
            state.handoff_until = float(data.get("handoff_until") or 0)
        except (TypeError, ValueError):
            state.handoff_until = 0.0
        state.hint = str(data.get("hint") or "")
        state.accepting = bool(data.get("accepting", True))
        state.kind = str(data.get("kind") or "password")
        if state.kind not in ("password", "totp", "other"):
            state.kind = "password"
        state.previous_token = data.get("previous_token") or None
        phase = str(data.get("phase") or "waiting")
        if phase not in ("waiting", "submitted", "retry", "success"):
            phase = "waiting"
        state.phase = phase
        return state

    def save(self) -> None:
        path = _state_path()
        tmp = path + ".tmp"
        payload = {
            "token": self.token,
            "created_at": self.created_at,
            "failures": self.failures,
            "hint": self.hint,
            "accepting": self.accepting,
            "phase": self.phase,
            "submitted_at": self.submitted_at,
            "kind": self.kind,
            "previous_token": self.previous_token,
            "handoff_until": self.handoff_until,
        }
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass

    def clear(self) -> None:
        self.token = None
        self.created_at = 0.0
        self.failures = 0
        self.hint = ""
        self.accepting = True
        self.phase = "waiting"
        self.submitted_at = 0.0
        self.kind = "password"
        self.previous_token = None
        self.handoff_until = 0.0
        path = _state_path()
        try:
            os.unlink(path)
        except OSError:
            pass

    def is_fresh(self) -> bool:
        if not self.token or self.created_at <= 0:
            return False
        return (time.time() - self.created_at) <= SESSION_MAX_AGE_SECONDS

    def matches_token(self, token: str) -> bool:
        return bool(
            self.token
            and token
            and secrets.compare_digest(self.token, token)
        )

    def matches_previous_token(self, token: str) -> bool:
        return bool(
            self.previous_token
            and token
            and secrets.compare_digest(self.previous_token, token)
            and time.time() <= self.handoff_until
        )

    def public_status(self, token: str) -> dict:
        """JSON-serializable status for the phone polling page."""
        base = {
            "hint": self.hint,
            "failures": self.failures,
            "accepting": self.accepting,
            "max_failures": MAX_PASSWORD_FAILURES,
            "kind": self.kind,
        }
        if self.matches_token(token):
            return {
                **base,
                "status": self.phase,
            }
        # Phone still polling the *previous* master-password URL after rbw
        # started a new pinentry (typically 2FA). Redirect to the new form.
        if self.matches_previous_token(token) and self.token:
            return {
                **base,
                "status": "continue",
                "next_path": f"/s/{self.token}",
                "hint": self.hint
                or (
                    "Enter your authenticator code"
                    if self.kind == "totp"
                    else "Continue the next unlock step"
                ),
                "accepting": True,
            }
        return {
            "status": "gone",
            "hint": "",
            "failures": 0,
            "accepting": False,
            "max_failures": MAX_PASSWORD_FAILURES,
            "kind": self.kind,
        }

    def begin_attempt(
        self, seterror: str, kind: str = "password"
    ) -> tuple[str, bool, str]:
        """
        Prepare state for one GETPIN.

        Returns (token, is_new_qr, ui_hint).
        is_new_qr True means a brand-new QR must be shown (scan required).
        """
        is_retry = bool(seterror and seterror.strip())
        if kind not in ("password", "totp", "other"):
            kind = "password"

        if not is_retry:
            # Fresh prompt — mint a new token. If the prior session just submitted
            # a secret (master password), keep a handoff so the phone can follow
            # to this new form (e.g. TOTP after password).
            prev_token = self.token
            prev_phase = self.phase
            handoff = bool(
                prev_token
                and prev_phase in ("submitted", "success")
                and (
                    time.time() - (self.submitted_at or self.created_at or 0)
                    < self.HANDOFF_TTL_SECONDS
                )
            )

            self.token = secrets.token_urlsafe(32)
            self.created_at = time.time()
            self.failures = 0
            self.hint = ""
            self.accepting = True
            self.phase = "waiting"
            self.submitted_at = 0.0
            self.kind = kind
            if handoff:
                self.previous_token = prev_token
                self.handoff_until = time.time() + self.HANDOFF_TTL_SECONDS
            else:
                self.previous_token = None
                self.handoff_until = 0.0
            self.save()
            return self.token, True, ""

        # Incorrect secret on previous attempt (rbw SETERROR) — same token.
        hint = seterror.strip() or DEFAULT_HINT
        self.hint = hint
        self.kind = kind

        if self.is_fresh() and self.failures < MAX_PASSWORD_FAILURES:
            self.failures += 1
            self.accepting = True
            self.phase = "retry"
            self.save()
            return self.token or "", False, hint

        # Max failures / expired → new token, but still hand off from old URL.
        prev_token = self.token
        self.token = secrets.token_urlsafe(32)
        self.created_at = time.time()
        self.failures = 0
        self.hint = hint
        self.accepting = True
        self.phase = "retry"
        if prev_token:
            self.previous_token = prev_token
            self.handoff_until = time.time() + self.HANDOFF_TTL_SECONDS
        self.save()
        return self.token, True, hint

    def mark_password_submitted(self) -> None:
        # One submission per GETPIN; keep token for a possible SETERROR retry.
        self.accepting = False
        self.phase = "submitted"
        self.submitted_at = time.time()
        self.save()

    def mark_success(self) -> None:
        """Password delivered to rbw; phone should show success if no retry follows."""
        self.accepting = False
        self.phase = "success"
        self.save()

    def mark_terminal_failure(self) -> None:
        """Timeout / cancel — drop the session so the next unlock needs a new QR."""
        self.clear()


# ---------------------------------------------------------------------------
# In-memory session (one GETPIN HTTP wait)
# ---------------------------------------------------------------------------


class UnlockSession:
    """Holds the active token and received password for one GETPIN wait."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.token: Optional[str] = None
        self.created_at: float = 0.0  # monotonic
        self.password: Optional[str] = None
        self.done = threading.Event()
        self.cancelled = False
        self.expired = False
        self.error_message: Optional[str] = None
        self.failures: int = 0
        self.hint: str = ""
        self.is_new_qr: bool = True

    def start(
        self,
        token: Optional[str] = None,
        failures: int = 0,
        hint: str = "",
        is_new_qr: bool = True,
    ) -> str:
        with self.lock:
            self.token = token or secrets.token_urlsafe(32)
            self.created_at = time.monotonic()
            self.password = None
            self.done.clear()
            self.cancelled = False
            self.expired = False
            self.error_message = None
            self.failures = failures
            self.hint = hint
            self.is_new_qr = is_new_qr
            return self.token

    def is_valid_token(self, token: str) -> bool:
        with self.lock:
            if self.token is None or not secrets.compare_digest(self.token, token):
                return False
            if time.monotonic() - self.created_at > TOKEN_TTL_SECONDS:
                self.expired = True
                return False
            return True

    def submit_password(self, token: str, password: str) -> tuple[bool, str]:
        """Validate token and accept password. Returns (ok, error_message)."""
        with self.lock:
            if self.token is None:
                return False, "No active unlock session."
            if not secrets.compare_digest(self.token, token):
                return False, "Invalid or unknown token."
            if time.monotonic() - self.created_at > TOKEN_TTL_SECONDS:
                self.expired = True
                self.token = None
                self.done.set()
                return False, "Token expired. Please try again from the terminal."
            if self.password is not None:
                return False, "This attempt already submitted a password."
            self.password = password
            # Keep token string for logging/state; reject further POSTs this round.
            self.done.set()
            return True, ""

    def cancel(self) -> None:
        with self.lock:
            self.cancelled = True
            self.token = None
            self.password = None
            self.done.set()

    def mark_expired(self) -> None:
        with self.lock:
            self.expired = True
            self.token = None
            self.password = None
            self.done.set()

    def destroy(self) -> None:
        with self.lock:
            self.token = None
            self.password = None
            self.done.set()

    def take_password(self) -> Optional[str]:
        with self.lock:
            pw = self.password
            self.password = None
            return pw


# ---------------------------------------------------------------------------
# Mobile HTML pages
# ---------------------------------------------------------------------------

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #0f1419;
  --card: #1a2332;
  --text: #e7ecf3;
  --muted: #8b9bb4;
  --accent: #3b82f6;
  --accent-hover: #2563eb;
  --danger: #ef4444;
  --ok: #22c55e;
  --border: #2d3a4f;
  --input-bg: #0b1220;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f4f6fa;
    --card: #ffffff;
    --text: #0f172a;
    --muted: #64748b;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --border: #e2e8f0;
    --input-bg: #f8fafc;
  }
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--text);
  min-height: 100%;
}
body {
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; padding: 1.25rem;
}
.card {
  width: 100%; max-width: 420px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 1.75rem 1.5rem 1.5rem;
  box-shadow: 0 12px 40px rgba(0,0,0,.25);
}
h1 {
  font-size: 1.35rem; margin: 0 0 .35rem; font-weight: 650;
}
.sub {
  color: var(--muted); font-size: .95rem; margin: 0 0 1.4rem; line-height: 1.45;
}
label {
  display: block; font-size: .9rem; font-weight: 600; margin-bottom: .45rem;
}
input[type=password], input[type=text] {
  width: 100%;
  font-size: 1.15rem;
  padding: .95rem 1rem;
  border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--input-bg);
  color: var(--text);
  outline: none;
  -webkit-appearance: none;
}
input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(59,130,246,.25);
}
button {
  width: 100%;
  margin-top: 1rem;
  padding: 1rem;
  font-size: 1.05rem;
  font-weight: 650;
  border: none;
  border-radius: 12px;
  background: var(--accent);
  color: #fff;
  cursor: pointer;
}
button:hover { background: var(--accent-hover); }
button:active { transform: scale(.99); }
.msg {
  margin-top: 1rem; padding: .85rem 1rem; border-radius: 10px;
  font-size: .95rem; line-height: 1.4;
}
.msg.ok { background: rgba(34,197,94,.12); color: var(--ok); border: 1px solid rgba(34,197,94,.35); }
.msg.err { background: rgba(239,68,68,.12); color: var(--danger); border: 1px solid rgba(239,68,68,.35); }
.footer {
  margin-top: 1.25rem; text-align: center; color: var(--muted); font-size: .8rem;
}
"""


def page_shell(title: str, body: str) -> bytes:
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>{html.escape(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="card">
    {body}
  </div>
</body>
</html>
"""
    return doc.encode("utf-8")


def form_page(
    token: str,
    error: Optional[str] = None,
    desc: str = "",
    failures: int = 0,
    hint: str = "",
    prompt: str = "",
) -> bytes:
    err_html = ""
    # Prefer explicit form error, then unlock hint from a previous wrong password.
    banner = error or hint
    if banner:
        err_html = f'<div class="msg err">{html.escape(banner)}</div>'

    remaining = max(0, MAX_PASSWORD_FAILURES - failures)
    if failures > 0:
        attempt_html = (
            f'<p class="sub" style="margin-top:-0.6rem">'
            f"<strong>Incorrect — attempt "
            f"{html.escape(str(failures))}/{MAX_PASSWORD_FAILURES}</strong>. "
            f"{remaining} retr{'y' if remaining == 1 else 'ies'} left "
            f"before a new QR scan is required."
            f"</p>"
        )
        if not banner:
            err_html = (
                f'<div class="msg err">{html.escape(DEFAULT_HINT)}</div>'
            )
    else:
        attempt_html = ""

    totp = is_totp_or_2fa_prompt(prompt, desc)
    if totp:
        title = html.escape(prompt.strip() or "Two-factor authentication")
        default_desc = "Enter the verification code from your authenticator."
        field_label = html.escape(prompt.strip() or "Verification code")
        input_type = "text"
        inputmode = "numeric"
        autocomplete = "one-time-code"
        placeholder = "6-digit code"
        button = "Verify"
        pattern_attr = 'pattern="[0-9 ]{4,12}" inputmode="numeric"'
    else:
        title = "Unlock rbw"
        default_desc = "Enter your Bitwarden master password to unlock rbw."
        field_label = "Master password"
        input_type = "password"
        inputmode = "text"
        autocomplete = "current-password"
        placeholder = "Master password"
        button = "Unlock"
        pattern_attr = ""

    desc_html = html.escape(desc) if desc else default_desc
    body = f"""
    <h1>{title}</h1>
    <p class="sub">{desc_html}</p>
    {attempt_html}
    {err_html}
    <form method="POST" action="/s/{html.escape(token)}" autocomplete="{autocomplete}">
      <label for="password">{field_label}</label>
      <input id="password" name="password" type="{input_type}"
             required autofocus autocomplete="{autocomplete}"
             autocapitalize="off" autocorrect="off" spellcheck="false"
             placeholder="{html.escape(placeholder)}" {pattern_attr}>
      <button type="submit">{button}</button>
    </form>
    <p class="footer">Link expires in {TOKEN_TTL_SECONDS}s · max {MAX_PASSWORD_FAILURES} tries · do not share</p>
    """
    return page_shell(title if not totp else "2FA", body)


def pending_page(token: str, failures: int = 0, kind: str = "password") -> bytes:
    """
    Shown after password/TOTP POST. Polls /s/<token>/status and:
      - reloads form on retry (wrong secret)
      - redirects to next form on continue (e.g. password → 2FA)
      - shows success when unlock finished (no further pinentry step)

    Note: after pinentry exits, Cloudflare may return HTTP 502 HTML instead of a
    fetch() network error — treat non-JSON / non-ok as offline so the phone
    does not stick on "Verifying…".
    """
    # After master password, rbw may still start 2FA — wait longer.
    # After TOTP, that is usually the last pinentry step — succeed quickly.
    success_ms = 2500 if kind == "totp" else 12000
    body = f"""
    <h1 id="title">Checking…</h1>
    <p class="sub" id="subtitle">Sent to the terminal. This page updates automatically
    for errors or the next step (such as 2FA).</p>
    <div id="status" class="msg ok">Submitted — waiting for rbw…</div>
    <p id="detail" class="sub" style="margin-top:1rem"></p>
    <p class="footer">Keep this page open · do not share this link</p>
    <script>
    (function () {{
      var token = {json.dumps(token)};
      var kind = {json.dumps(kind)};
      var statusEl = document.getElementById('status');
      var detailEl = document.getElementById('detail');
      var titleEl = document.getElementById('title');
      var subtitleEl = document.getElementById('subtitle');
      var started = Date.now();
      var sawSubmitted = true;  // this page only appears after a successful POST
      var offlineSince = null;
      var finished = false;
      var SUCCESS_AFTER_OFFLINE_MS = {int(success_ms)};

      function setMsg(cls, text, detail) {{
        statusEl.className = 'msg ' + cls;
        statusEl.textContent = text;
        detailEl.textContent = detail || '';
      }}

      function showSuccess() {{
        if (finished) return;
        finished = true;
        titleEl.textContent = 'Done';
        subtitleEl.textContent =
          'Credentials were sent to the terminal. You can close this page.';
        setMsg('ok', 'Success — check the terminal for rbw status.',
          'If the terminal still shows an error, run rbw unlock / rbw login again.');
      }}

      function goForm() {{
        window.location.replace('/s/' + encodeURIComponent(token));
      }}

      function goNext(path) {{
        if (!path) return;
        finished = true;
        setMsg('ok', 'Next step required…', 'Opening the next form (e.g. 2FA code).');
        setTimeout(function () {{
          window.location.replace(path);
        }}, 250);
      }}

      function isRetry(j) {{
        if (!j) return false;
        if (j.status === 'retry') return true;
        if (j.accepting && j.failures > 0 && j.status !== 'submitted') return true;
        return false;
      }}

      function markOffline(msg, detail) {{
        if (!offlineSince) offlineSince = Date.now();
        var offlineFor = Date.now() - offlineSince;
        if (offlineFor >= SUCCESS_AFTER_OFFLINE_MS) {{
          showSuccess();
          return true;
        }}
        setMsg('ok', msg, detail);
        return false;
      }}

      async function tick() {{
        if (finished) return;
        var elapsed = Date.now() - started;

        // Hard deadline after TOTP: pinentry has already exited; do not wait on CF.
        if (kind === 'totp' && elapsed >= SUCCESS_AFTER_OFFLINE_MS) {{
          showSuccess();
          return;
        }}

        try {{
          var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
          var timer = ctrl ? setTimeout(function () {{ ctrl.abort(); }}, 2000) : null;
          var r = await fetch('/s/' + encodeURIComponent(token) + '/status', {{
            cache: 'no-store',
            headers: {{ 'Accept': 'application/json' }},
            signal: ctrl ? ctrl.signal : undefined
          }});
          if (timer) clearTimeout(timer);

          var j = null;
          var ct = (r.headers.get('content-type') || '');
          if (r.ok && ct.indexOf('application/json') !== -1) {{
            try {{ j = await r.json(); }} catch (e) {{ j = null; }}
          }}

          if (j && j.status === 'continue' && j.next_path) {{
            goNext(j.next_path);
            return;
          }}
          if (j && isRetry(j)) {{
            setMsg('err', 'Incorrect — reloading form…', j.hint || '');
            setTimeout(goForm, 350);
            return;
          }}
          if (j && j.status === 'success') {{
            showSuccess();
            return;
          }}
          if (j && (j.status === 'submitted' || j.status === 'waiting')) {{
            offlineSince = null;
            if (kind === 'totp') {{
              setMsg('ok', 'Verifying 2FA code on the terminal…',
                'Code was received — finishing…');
            }} else {{
              setMsg('ok', 'Checking on the terminal…',
                'If 2FA is required, this page will open the code form automatically.');
            }}
          }} else {{
            // 502/HTML/gone from tunnel after pinentry exit, or unknown payload
            if (markOffline(
              kind === 'totp' ? 'Finishing login…' : 'Waiting for terminal…',
              kind === 'totp'
                ? '2FA was sent. Completing…'
                : 'Preparing next step or finishing unlock…'
            )) return;
          }}
        }} catch (e) {{
          if (markOffline(
            kind === 'totp' ? 'Finishing login…' : 'Waiting for terminal…',
            kind === 'totp'
              ? 'Terminal received the code.'
              : 'If 2FA is required, the code form will appear shortly.'
          )) return;
        }}
        setTimeout(tick, 600);
      }}
      setTimeout(tick, 300);
    }})();
    </script>
    """
    _ = failures
    return page_shell("Checking", body)


def error_page(message: str, title: str = "Error") -> bytes:
    body = f"""
    <h1>{html.escape(title)}</h1>
    <p class="sub">{html.escape(message)}</p>
    <div class="msg err">{html.escape(message)}</div>
    <p class="footer">Return to the terminal and run <code>rbw unlock</code> again if needed.</p>
    """
    return page_shell(title, body)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


class PinentryHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler bound to a shared UnlockSession + optional description."""

    session: UnlockSession
    description: str = ""
    server_version = "rbw-qr-pinentry/" + VERSION
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("RBW_QR_PINENTRY_DEBUG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _parse_token_path(self) -> tuple[Optional[str], Optional[str]]:
        """Return (token, action) where action is None or 'status'."""
        parsed = urllib.parse.urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) == 2 and parts[0] == "s":
            return parts[1], None
        if len(parts) == 3 and parts[0] == "s" and parts[2] == "status":
            return parts[1], "status"
        return None, None

    def _form(self, token: str, error: Optional[str] = None) -> bytes:
        return form_page(
            token,
            error=error,
            desc=self.description,
            failures=self.session.failures,
            hint=self.session.hint,
            prompt=getattr(self, "prompt_label", "") or "",
        )

    def _status_payload(self, token: str) -> dict:
        # Prefer live session when it matches; always merge disk phase so the
        # phone can see "retry" as soon as the next pinentry process starts.
        disk = PersistentUnlockState.load()
        payload = disk.public_status(token)
        if self.session.is_valid_token(token):
            with self.session.lock:
                submitted = self.session.password is not None
                failures = self.session.failures
                hint = self.session.hint
            if submitted and payload.get("status") != "retry":
                payload["status"] = "submitted"
                payload["accepting"] = False
            if failures and not payload.get("failures"):
                payload["failures"] = failures
            if hint and not payload.get("hint"):
                payload["hint"] = hint
        return payload

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/health", "/healthz"):
            self._send(200, b"ok\n", "text/plain; charset=utf-8")
            return

        token, action = self._parse_token_path()
        if token is None:
            self._send(404, error_page("Not found.", "Not Found"))
            return

        if action == "status":
            payload = self._status_payload(token)
            body = json.dumps(payload).encode("utf-8")
            code = 200 if payload.get("status") != "gone" else 410
            self._send(code, body, "application/json; charset=utf-8")
            return

        # Form / pending page
        disk = PersistentUnlockState.load()
        live_ok = self.session.is_valid_token(token)
        disk_ok = disk.matches_token(token) and disk.is_fresh()

        if not live_ok and not disk_ok:
            with self.session.lock:
                expired = self.session.expired
            if expired:
                self._send(
                    410,
                    error_page(
                        "This unlock link has expired. Return to the terminal and try again.",
                        "Link expired",
                    ),
                )
            else:
                self._send(
                    403,
                    error_page(
                        "Invalid or already-used unlock link. "
                        "If you hit the retry limit, scan a new QR from the terminal.",
                        "Invalid link",
                    ),
                )
            return

        # If password already submitted this round, keep the polling page.
        if live_ok:
            with self.session.lock:
                already = self.session.password is not None
            if already:
                skind = getattr(self.session, "kind", None) or (
                    disk.kind if disk_ok else "password"
                )
                self._send(
                    200,
                    pending_page(
                        token,
                        failures=self.session.failures,
                        kind=skind,
                    ),
                )
                return

        if disk_ok and disk.phase == "submitted" and not live_ok:
            # Between pinentry processes — still show waiting UI if user refreshes.
            self._send(
                200,
                pending_page(token, failures=disk.failures, kind=disk.kind),
            )
            return

        # Prefer disk hint/failures on retry so form is correct even if session
        # was just re-bound.
        if disk_ok and disk.phase == "retry":
            self.session.failures = disk.failures
            self.session.hint = disk.hint

        self._send(200, self._form(token))

    def do_POST(self) -> None:  # noqa: N802
        token, action = self._parse_token_path()
        if token is None or action is not None:
            self._send(404, error_page("Not found.", "Not Found"))
            return

        length_hdr = self.headers.get("Content-Length", "0")
        try:
            length = int(length_hdr)
        except ValueError:
            length = 0
        if length < 0 or length > 64 * 1024:
            self._send(400, error_page("Invalid request body.", "Bad Request"))
            return

        raw = self.rfile.read(length) if length else b""
        content_type = self.headers.get("Content-Type", "")
        password = ""

        if "application/x-www-form-urlencoded" in content_type or not content_type:
            form = urllib.parse.parse_qs(
                raw.decode("utf-8", errors="replace"), keep_blank_values=True
            )
            values = (
                form.get("password") or form.get("passphrase") or form.get("pin") or []
            )
            password = values[0] if values else ""
        elif "application/json" in content_type:
            try:
                obj = json.loads(raw.decode("utf-8"))
                if isinstance(obj, dict):
                    password = str(
                        obj.get("password") or obj.get("passphrase") or ""
                    )
            except Exception:
                password = ""
        else:
            password = raw.decode("utf-8", errors="replace")

        if not password:
            self._send(
                400,
                self._form(token, error="Password is required."),
            )
            return

        ok, err = self.session.submit_password(token, password)
        if not ok:
            status = 410 if "expired" in err.lower() else 403
            self._send(status, error_page(err, "Rejected"))
            return

        # Mark disk state immediately so polls see "submitted" even before
        # handle_getpin continues.
        persist = PersistentUnlockState.load()
        if persist.matches_token(token):
            persist.mark_password_submitted()

        # Prefer live session kind; fall back to disk.
        disk_kind = PersistentUnlockState.load().kind
        kind = disk_kind or "password"
        self._send(
            200,
            pending_page(token, failures=self.session.failures, kind=kind),
        )


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()


class PinentryServer:
    """Lifecycle wrapper for the temporary HTTP server."""

    def __init__(
        self,
        session: UnlockSession,
        description: str = "",
        prompt_label: str = "",
    ) -> None:
        self.session = session
        self.description = description
        self.prompt_label = prompt_label
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = type(
            "BoundHandler",
            (PinentryHTTPRequestHandler,),
            {
                "session": self.session,
                "description": self.description,
                "prompt_label": self.prompt_label,
            },
        )
        try:
            self._httpd = ThreadingHTTPServer((HOST, PORT), handler)
        except OSError as exc:
            raise RuntimeError(
                f"Cannot bind HTTP server on {HOST}:{PORT}: {exc}"
            ) from exc

        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="rbw-qr-http",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


# ---------------------------------------------------------------------------
# Pinentry (Assuan) state machine
# ---------------------------------------------------------------------------


class Pinentry:
    def __init__(self, ttyname: Optional[str] = None, timeout: int = 0) -> None:
        self.title = "rbw"
        self.prompt = "Password:"
        self.desc = ""
        self.error = ""
        self.ok_button = "OK"
        self.cancel_button = "Cancel"
        self.notok_button = ""
        self.timeout = timeout  # Assuan SETTIMEOUT / --timeout (0 = none)
        self.ttyname = ttyname
        self.options: dict[str, str] = {}
        self._tty: Optional[TtyWriter] = None
        self._session: Optional[UnlockSession] = None
        self._server: Optional[PinentryServer] = None
        self._persist: Optional[PersistentUnlockState] = None
        self._stop_main = False

    def tty(self) -> TtyWriter:
        if self._tty is None:
            self._tty = TtyWriter(self.ttyname)
        return self._tty

    def cleanup_session(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None
        if self._session is not None:
            self._session.destroy()
            self._session = None

    def _finish_getpin(self) -> None:
        """rbw uses one-shot pinentry processes — always stop after GETPIN."""
        self._stop_main = True
        self.error = ""

    def handle_getpin(self) -> None:
        """Run the QR unlock flow and respond with D … / ERR …"""
        self.cleanup_session()
        tty = self.tty()

        # Wrong password from rbw — do not reuse a cached (incorrect) password.
        if self.error:
            clear_password_cache()

        master_pw_prompt = is_master_password_prompt(self.prompt, self.desc)
        totp_prompt = is_totp_or_2fa_prompt(self.prompt, self.desc)

        # rbw unlock = Login then Unlock (two master-password pinentry spawns).
        # Reuse cache ONLY for master-password prompts — never for TOTP/2FA.
        if not self.error and master_pw_prompt:
            cached = load_password_cache()
            if cached:
                tty.write(
                    "\n  rbw QR pinentry — reusing master password from the "
                    "previous prompt (no new QR).\n"
                    "  Completing rbw login/unlock…\n\n"
                )
                assuan_data(cached.encode("utf-8"))
                assuan_ok()
                self._finish_getpin()
                self.cleanup_session()
                return

        kind = "totp" if totp_prompt else ("password" if master_pw_prompt else "other")
        persist = PersistentUnlockState.load()
        token, is_new_qr, hint = persist.begin_attempt(self.error, kind=kind)
        self._persist = persist

        session = UnlockSession()
        session.start(
            token=token,
            failures=persist.failures,
            hint=hint or persist.hint,
            is_new_qr=is_new_qr,
        )
        session.kind = kind  # type: ignore[attr-defined]
        url = f"{_public_base_url()}/s/{token}"
        self._session = session

        if totp_prompt:
            description = (
                self.desc
                or "Enter the 6 digit verification code from your authenticator app."
            )
        else:
            description = (
                self.desc
                or "Enter your Bitwarden master password to unlock rbw."
            )

        try:
            server = PinentryServer(
                session,
                description=description,
                prompt_label=self.prompt or "",
            )
            server.start()
            self._server = server
        except RuntimeError as exc:
            assuan_err(ERR_GENERAL, str(exc).replace("\n", " "))
            self.cleanup_session()
            self._finish_getpin()
            return

        remaining = max(0, MAX_PASSWORD_FAILURES - persist.failures)

        if is_new_qr:
            qr = render_qr_ascii(url)
            if totp_prompt:
                header = (
                    "  rbw QR pinentry — scan to enter your 2FA / TOTP code"
                )
            elif persist.failures == 0 and not hint:
                header = "  rbw QR pinentry — scan with your phone to unlock"
            else:
                header = (
                    "  rbw QR pinentry — NEW QR required "
                    f"(max {MAX_PASSWORD_FAILURES} wrong passwords reached or session expired)"
                )
            banner = (
                "\n"
                "════════════════════════════════════════════════════════════\n"
                f"{header}\n"
                "════════════════════════════════════════════════════════════\n"
                f"{qr}\n"
                f"  URL: {url}\n"
                f"  Expires in {TOKEN_TTL_SECONDS}s · max {MAX_PASSWORD_FAILURES} tries\n"
                "  Waiting for input from phone…\n"
                "════════════════════════════════════════════════════════════\n\n"
            )
        else:
            # Reuse same QR/URL — user can refresh the open phone page.
            banner = (
                "\n"
                "════════════════════════════════════════════════════════════\n"
                "  rbw QR pinentry — incorrect password, please retry\n"
                "════════════════════════════════════════════════════════════\n"
                f"  !! {hint or DEFAULT_HINT}\n"
                f"  Attempt {persist.failures}/{MAX_PASSWORD_FAILURES}"
                f"  ({remaining} left before a new QR is required)\n"
                f"  Reuse the same link (no new scan needed):\n"
                f"    {url}\n"
                f"  Refresh the page on your phone if it is still open.\n"
                f"  Expires in {TOKEN_TTL_SECONDS}s\n"
                "  Waiting for password from phone…\n"
                "════════════════════════════════════════════════════════════\n\n"
            )
        tty.write(banner)

        effective_timeout = TOKEN_TTL_SECONDS
        if self.timeout and self.timeout > 0:
            effective_timeout = min(effective_timeout, self.timeout)

        finished = session.done.wait(timeout=effective_timeout)

        if not finished:
            session.mark_expired()
            tty.write("  Timed out waiting for password.\n\n")
            persist.mark_terminal_failure()
            clear_password_cache()
            self.cleanup_session()
            assuan_err(ERR_TIMEOUT, "Timeout")
            self._finish_getpin()
            return

        if session.cancelled:
            tty.write("  Unlock cancelled.\n\n")
            persist.mark_terminal_failure()
            clear_password_cache()
            self.cleanup_session()
            assuan_err(ERR_CANCELLED, "Operation cancelled")
            self._finish_getpin()
            return

        if session.expired and session.password is None:
            tty.write("  Token expired.\n\n")
            persist.mark_terminal_failure()
            clear_password_cache()
            self.cleanup_session()
            assuan_err(ERR_TIMEOUT, "Timeout")
            self._finish_getpin()
            return

        password = session.take_password()

        if password is None:
            tty.write("  No password received.\n\n")
            persist.mark_terminal_failure()
            clear_password_cache()
            self.cleanup_session()
            assuan_err(ERR_CANCELLED, "Operation cancelled")
            self._finish_getpin()
            return

        # TOTP: strip spaces (e.g. "123 456") so rbw accepts it as a number.
        if totp_prompt:
            password = "".join(password.split())

        # Hand value to rbw immediately, then keep HTTP up briefly so the
        # phone can observe phase=submitted before the server stops.
        persist.mark_password_submitted()
        # Only cache master passwords — never TOTP/API-key secrets.
        if master_pw_prompt:
            save_password_cache(password)
        else:
            clear_password_cache()

        if totp_prompt:
            tty.write("  2FA code received — verifying…\n\n")
        elif persist.failures > 0:
            tty.write(
                f"  Password received (retry {persist.failures}/{MAX_PASSWORD_FAILURES})"
                " — unlocking…\n\n"
            )
        else:
            tty.write("  Password received — unlocking…\n\n")

        assuan_data(password.encode("utf-8"))
        assuan_ok()

        # Keep HTTP up briefly so the phone can observe phase=submitted, then
        # free :18765 so a wrong-password SETERROR pinentry can bind.
        # After TOTP, rbw rarely starts another pinentry — phone will show success.
        time.sleep(0.8)
        self.cleanup_session()
        self._finish_getpin()
        password = None  # noqa: F841

    def handle_confirm(self, one_button: bool = False) -> None:
        """CONFIRM / MESSAGE — surface text on the TTY and accept."""
        tty = self.tty()
        msg = self.desc or self.title or "Confirm?"
        if one_button:
            tty.write(
                f"\n[rbw-qr-pinentry] {msg}\n"
                "(press Enter in terminal is not required — auto-acknowledged)\n"
            )
            assuan_ok()
        else:
            tty.write(
                f"\n[rbw-qr-pinentry] CONFIRM: {msg}\n(auto-confirmed)\n"
            )
            assuan_ok()
        self.error = ""

    def handle_line(self, line: str) -> bool:
        """
        Process one Assuan command line.
        Returns False if the session should exit (BYE / EOF handling).
        """
        line = line.rstrip("\r\n")
        if not line:
            return True

        if line.startswith("#"):
            return True

        parts = line.split(" ", 1)
        cmd = parts[0].upper()
        arg = assuan_unescape(parts[1]) if len(parts) > 1 else ""

        if cmd == "SETTITLE":
            self.title = arg
            assuan_ok()
        elif cmd == "SETPROMPT":
            self.prompt = arg
            assuan_ok()
        elif cmd == "SETDESC":
            self.desc = arg
            assuan_ok()
        elif cmd == "SETERROR":
            self.error = arg
            assuan_ok()
        elif cmd == "SETOK":
            self.ok_button = arg
            assuan_ok()
        elif cmd == "SETCANCEL":
            self.cancel_button = arg
            assuan_ok()
        elif cmd == "SETNOTOK":
            self.notok_button = arg
            assuan_ok()
        elif cmd == "SETTIMEOUT":
            try:
                self.timeout = int(arg.strip() or "0")
            except ValueError:
                self.timeout = 0
            assuan_ok()
        elif cmd in (
            "SETREPEAT",
            "SETQUALITYBAR",
            "SETQUALITYBAR_TT",
            "SETGENPIN",
            "SETGENPIN_TT",
            "SETKEYINFO",
        ):
            assuan_ok()
        elif cmd == "OPTION":
            if "=" in arg:
                k, v = arg.split("=", 1)
                self.options[k] = v
                if k == "ttyname":
                    self.ttyname = v
                    if self._tty is not None:
                        self._tty.close()
                        self._tty = None
            else:
                self.options[arg] = "1"
            assuan_ok()
        elif cmd == "GETPIN":
            self.handle_getpin()
        elif cmd == "CONFIRM":
            one = "--one-button" in arg or arg.strip() == "--one-button"
            self.handle_confirm(one_button=one)
        elif cmd == "MESSAGE":
            self.handle_confirm(one_button=True)
        elif cmd in ("BYE", "QUIT"):
            assuan_ok("closing connection")
            return False
        elif cmd == "RESET":
            self.title = "rbw"
            self.prompt = "Password:"
            self.desc = ""
            self.error = ""
            self.cleanup_session()
            assuan_ok()
        elif cmd == "NOP":
            assuan_ok()
        elif cmd == "GETINFO":
            what = arg.strip().lower()
            if what == "version":
                assuan_data(VERSION.encode("utf-8"))
                assuan_ok()
            elif what == "pid":
                assuan_data(str(os.getpid()).encode("utf-8"))
                assuan_ok()
            elif what == "flavor":
                assuan_data(b"rbw-qr-pinentry")
                assuan_ok()
            elif what == "ttyinfo":
                assuan_data((self.ttyname or "").encode("utf-8"))
                assuan_ok()
            else:
                assuan_err(ERR_GENERAL, f"Unknown GETINFO {what}")
        elif cmd == "END":
            assuan_ok()
        elif cmd == "HELP":
            assuan_ok(
                "Commands: SETTITLE SETPROMPT SETDESC SETERROR SETTIMEOUT "
                "OPTION GETPIN CONFIRM MESSAGE BYE RESET NOP GETINFO"
            )
        else:
            assuan_ok()

        return True

    def run(self) -> int:
        assuan_ok("Pleased to meet you")

        try:
            while not self._stop_main:
                line = sys.stdin.buffer.readline()
                if not line:
                    break
                try:
                    text = line.decode("utf-8", errors="replace")
                except Exception:
                    text = line.decode("latin-1", errors="replace")
                if not self.handle_line(text):
                    break
                # rbw always one-shots pinentry after GETPIN (stdin already closed).
                if self._stop_main:
                    break
        except KeyboardInterrupt:
            if self._session is not None:
                self._session.cancel()
            clear_password_cache()
        finally:
            self.cleanup_session()
            if self._tty is not None:
                self._tty.close()
                self._tty = None
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rbw-qr-pinentry",
        description="QR-code pinentry for rbw (Assuan protocol over stdin/stdout).",
    )
    p.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging to stderr"
    )
    p.add_argument(
        "-D",
        "--display",
        default=None,
        help="X display (ignored; accepted for pinentry compat)",
    )
    p.add_argument(
        "-T",
        "--ttyname",
        default=None,
        help="TTY device for human-visible prompts/QR",
    )
    p.add_argument(
        "-N", "--ttytype", default=None, help="TERM type (accepted for compat)"
    )
    p.add_argument(
        "-C",
        "--lc-ctype",
        default=None,
        dest="lc_ctype",
        help="LC_CTYPE (compat)",
    )
    p.add_argument(
        "-M",
        "--lc-messages",
        default=None,
        dest="lc_messages",
        help="LC_MESSAGES (compat)",
    )
    p.add_argument(
        "-o",
        "--timeout",
        type=int,
        default=0,
        help="Idle timeout seconds (0=none); QR flow hard-caps at 90s",
    )
    p.add_argument(
        "-g",
        "--no-global-grab",
        action="store_true",
        help="Accepted for pinentry compat",
    )
    p.add_argument(
        "-W", "--parent-wid", default=None, help="Accepted for pinentry compat"
    )
    p.add_argument("--version", action="store_true", help="Print version and exit")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry used by console_scripts and ``python -m rbw_qr_pinentry``."""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.version:
        print(f"rbw-qr-pinentry {VERSION}")
        return 0
    if args.debug:
        os.environ["RBW_QR_PINENTRY_DEBUG"] = "1"

    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    pinentry = Pinentry(ttyname=args.ttyname, timeout=args.timeout)
    return pinentry.run()


def cli() -> None:
    """setuptools/hatch console entrypoint (always exits with a status code)."""
    raise SystemExit(main())


if __name__ == "__main__":
    cli()
