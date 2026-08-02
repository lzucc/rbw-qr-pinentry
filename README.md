# rbw-qr-pinentry

Custom [pinentry](https://www.gnupg.org/related_software/pinentry/) for [rbw](https://github.com/doy/rbw) (Rust Bitwarden CLI) that unlocks your vault by scanning a QR code on your phone.

## How it works

When you run `rbw unlock` (or any command that needs the master password):

1. Starts a temporary HTTP server on `127.0.0.1:18765`
2. Generates a high-entropy one-time token (`secrets.token_urlsafe(32)`)
3. Prints a large ASCII QR code encoding:
   `{RBW_QR_PUBLIC_BASE_URL}/s/<token>`
4. Serves a clean, mobile-friendly password form at `/s/<token>`
5. Accepts the master password (or 2FA code) via POST
6. Returns the secret to `rbw-agent` over the Assuan protocol (`D <secret>` / `OK`)
7. Destroys the token and shuts down the HTTP server

Hard timeout: **90 seconds** per prompt. Bind address: **127.0.0.1 only** (pair with a tunnel that forwards to the machine where pinentry runs).

## Public URL (required for phone access)

The QR code must encode a hostname your phone can reach. **No personal domain is hard-coded.** Set:

```bash
export RBW_QR_PUBLIC_BASE_URL=https://pinentry.example.com
```

Put that in your shell profile, systemd user environment, or a wrapper script so `rbw-agent` inherits it when it spawns pinentry.

Example wrapper:

```bash
#!/bin/sh
export RBW_QR_PUBLIC_BASE_URL=https://pinentry.example.com
exec /path/to/venv/bin/rbw-qr-pinentry "$@"
```

Then:

```bash
rbw config set pinentry /path/to/wrapper
```

## Install (WSL / VMware Linux)

### Recommended: pipx (isolated app on PATH)

```bash
# from a git clone or copied source tree
cd /path/to/rbw-qr-pinentry
pipx install .

rbw config set pinentry "$(command -v rbw-qr-pinentry)"
```

With [uv](https://github.com/astral-sh/uv):

```bash
uv tool install .
rbw config set pinentry "$(command -v rbw-qr-pinentry)"
```

### From GitHub

```bash
pipx install git+https://github.com/lzucc/rbw-qr-pinentry.git
rbw config set pinentry "$(command -v rbw-qr-pinentry)"
```

### Editable (development)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
rbw config set pinentry "$(command -v rbw-qr-pinentry)"
```

### Verify

```bash
rbw-qr-pinentry --version
printf 'SETTITLE rbw\nSETPROMPT Password:\nSETDESC Unlock vault\nGETPIN\n' | rbw-qr-pinentry
```

## Upgrade / uninstall

```bash
pipx upgrade rbw-qr-pinentry   # or: pipx install --force .
pipx uninstall rbw-qr-pinentry
```

## Tunnel / networking

This pinentry only listens on loopback. Forward public HTTPS to the **same Linux** where `rbw unlock` runs:

```text
https://pinentry.example.com  →  http://127.0.0.1:18765
```

| Where pinentry runs | Tunnel must reach |
| --- | --- |
| WSL | That WSL instance’s `127.0.0.1:18765` |
| VMware VM | That guest’s `127.0.0.1:18765` |

## Manual Assuan smoke test

```bash
export RBW_QR_PUBLIC_BASE_URL=https://pinentry.example.com
printf 'SETTITLE rbw\nSETPROMPT Password:\nSETDESC Unlock vault\nGETPIN\n' | rbw-qr-pinentry
```

After submitting the phone form:

```text
OK Pleased to meet you
OK
OK
OK
D your-password-here
OK
```

## Build distributable artifacts

```bash
python3 -m pip install build
python3 -m build
```

## Protocol notes

Implements the pinentry Assuan subset used by rbw:

| Command | Behavior |
| --- | --- |
| `SETTITLE` / `SETPROMPT` / `SETDESC` / `SETERROR` | Stored and acknowledged with `OK` |
| `SETTIMEOUT` | Honored if shorter than the 90s QR TTL |
| `OPTION` | Accepted (e.g. `ttyname=`) |
| `GETPIN` | QR + HTTP unlock flow |
| `CONFIRM` / `MESSAGE` | Auto-acknowledged (text shown on TTY) |
| `BYE` / `RESET` / `NOP` / `GETINFO` | Standard responses |

Prompt type is inferred from `SETPROMPT` / `SETDESC` (master password vs TOTP/2FA vs other). Master-password answers may be cached briefly for rbw’s login+unlock double prompt; 2FA codes are never cached that way.

Cancel / timeout use Assuan error codes expected by rbw (`83886179` cancelled, timeout on expiry).

## Security

- Token is high-entropy, single-use, and wiped after success, cancel, or timeout
- Server lives only for one unlock request
- Listens only on `127.0.0.1` (not `0.0.0.0`)
- Form page is `no-store` / no-cache
- Password is percent-escaped on the Assuan `D` line per protocol rules

Anyone who can scan the QR (or reach the tunnel URL) during the open window can submit a secret. Treat the tunnel hostname as sensitive during unlock.

## Debug

```bash
RBW_QR_PINENTRY_DEBUG=1 rbw unlock
# or
rbw-qr-pinentry --debug
```

## Project layout

```text
pyproject.toml          # installable package metadata
src/rbw_qr_pinentry/    # library + console entrypoint
rbw-qr-pinentry         # optional source-tree launcher (dev)
```

## License

MIT
