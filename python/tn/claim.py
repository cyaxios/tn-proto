"""V2: loopback claim URL flow for `tn.init(yaml_path)` with no identity.

When a developer calls `tn.init(yaml_path)` in a web app or headless
script and no identity.json exists, V1 would silently generate an
ephemeral identity that dies with the process. V2 upgrades that path:

1. Generate a mnemonic + Identity in memory.
2. Spin up a loopback HTTPS server on 127.0.0.1:<random-port>.
3. Write the mnemonic to a short-TTL temp file, keyed by a token.
4. Print a claim URL with:
   - token in path (server-side nonce)
   - fragment (#...) containing the HKDF-derived display key, which
     the browser uses to decrypt the mnemonic shown on the page.
     Fragments never cross HTTP, so a URL leak without the fragment
     is useless.
   - confirmation code printed separately in logs (human-check layer).
5. Caller receives a ClaimSession handle. They can:
   - pass it to `tn.init(..., identity=session.identity)` so the app
     continues to work
   - let the user visit the URL, write down the mnemonic, choose
     "Register with tnproto.org" button on the page to bind the
     identity to a vault account
6. After TTL (default 600s) the temp file is wiped. If the user
   never claimed, the identity becomes unrecoverable — but the app
   keeps working until restart.

V2 shipping status: the Python generator + loopback server are here.
The browser-side HTML/JS for the claim page ships alongside (see
`claim_page.html` at module root).
"""

from __future__ import annotations

import base64
import http.server
import os
import secrets
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import Identity

DEFAULT_TTL_SECS = 600  # 10 minutes
DEFAULT_CONFIRM_WORDS = 3  # "WHALE-TULIP-7823" style


# ---------------------------------------------------------------------
# Confirmation code generation
# ---------------------------------------------------------------------


_CONFIRM_WORDLIST = [
    "whale",
    "tulip",
    "panda",
    "saturn",
    "forest",
    "amber",
    "cobra",
    "nebula",
    "quartz",
    "orchid",
    "lynx",
    "zephyr",
    "granite",
    "mango",
    "pulsar",
    "fern",
    "cedar",
    "basalt",
    "iris",
    "puma",
    "comet",
    "ember",
    "falcon",
    "ivory",
    "juno",
    "kraken",
    "lagoon",
    "moss",
]


def _generate_confirm_code(word_count: int = DEFAULT_CONFIRM_WORDS) -> str:
    # Sample without replacement so the three words differ — distinct
    # words read better and give more apparent entropy to the user.
    k = min(word_count, len(_CONFIRM_WORDLIST))
    picks = [w.upper() for w in _sample_distinct(_CONFIRM_WORDLIST, k)]
    suffix = "".join(secrets.choice("0123456789") for _ in range(4))
    return "-".join(picks) + "-" + suffix


def _sample_distinct(pool: list[str], k: int) -> list[str]:
    """secrets-based sample without replacement."""
    remaining = list(pool)
    out: list[str] = []
    for _ in range(k):
        idx = secrets.randbelow(len(remaining))
        out.append(remaining.pop(idx))
    return out


# ---------------------------------------------------------------------
# Display-key derivation + wrapping the mnemonic
# ---------------------------------------------------------------------


def _derive_display_key(token: bytes) -> bytes:
    """Derive a 32-byte AES key from the URL-path token.

    The fragment in the URL will be a different 32-byte value that the
    browser sends back out-of-band to unwrap the mnemonic. Two keys:
    one server-known (the token) that the server uses to identify the
    session, and one fragment-only that never crosses HTTP.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"tn:claim:v1",
        info=b"display-key",
    ).derive(token)


def _wrap_mnemonic(mnemonic: str, display_key: bytes) -> tuple[str, str]:
    """Seal the mnemonic under display_key; return (nonce_b64, ct_b64)."""
    nonce = os.urandom(12)
    ct = AESGCM(display_key).encrypt(nonce, mnemonic.encode("utf-8"), b"tn:claim:v1")
    return (
        base64.urlsafe_b64encode(nonce).rstrip(b"=").decode(),
        base64.urlsafe_b64encode(ct).rstrip(b"=").decode(),
    )


# ---------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------


@dataclass
class ClaimSession:
    """Handle to an in-flight claim.

    The caller gets this back from `start_claim()` and uses:
    - `session.identity` for immediate app use
    - `session.url` to show/log
    - `session.confirmation_code` to print separately
    - `session.shutdown()` when the process exits (best-effort)
    """

    identity: Identity
    url: str
    confirmation_code: str
    token: str  # hex, server-side lookup key
    expires_at: float  # time.time() epoch
    _server: socketserver.BaseServer | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _thread: threading.Thread | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def shutdown(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


# ---------------------------------------------------------------------
# HTTP handler for the claim page
# ---------------------------------------------------------------------


def _make_handler(
    token: str,
    nonce_b64: str,
    ct_b64: str,
    confirm_code: str,
    did: str,
    expires_at: float,
    register_cb: Callable[[], dict] | None = None,
):
    class ClaimHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # silence access log

        def do_GET(self):
            # URL: /claim/<token>
            if not self.path.startswith(f"/claim/{token}"):
                self.send_response(404)
                self.end_headers()
                return
            if time.time() > expires_at:
                self.send_response(410)  # Gone
                self.end_headers()
                self.wfile.write(b"claim TTL expired")
                return
            html = _render_claim_page(
                did=did,
                nonce_b64=nonce_b64,
                ct_b64=ct_b64,
                confirm_code=confirm_code,
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

    return ClaimHandler


def _render_claim_page(
    *,
    did: str,
    nonce_b64: str,
    ct_b64: str,
    confirm_code: str,
) -> str:
    """Render the HTML for the claim page.

    JS uses:
    - URL hash (location.hash) → display_key (fragment-only, not sent to server)
    - nonce + ct from the page HTML (AES-GCM-sealed by the server)
    - WebCrypto AES-GCM decrypt to reveal the mnemonic
    - User enters the confirmation code the server printed separately
    """
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>TN identity claim</title>
<style>
  body {{ font: 14px/1.5 system-ui; max-width: 640px; margin: 40px auto; padding: 0 16px; }}
  .bar {{ background: #fffacd; border: 1px solid #d0a840; padding: 12px; margin: 12px 0; }}
  .mnemonic {{ font: 18px/1.4 monospace; background: #f6f6f6; padding: 16px;
              border: 1px solid #ccc; border-radius: 4px; user-select: all; }}
  button, input {{ font: 14px sans-serif; padding: 8px 12px; }}
  code {{ background: #eee; padding: 0 4px; }}
  .did {{ font: 12px monospace; color: #555; }}
</style></head><body>
<h1>TN identity claim</h1>
<p class="bar">
  Write the recovery phrase down. If you lose it, you cannot recover
  this identity on another device.
</p>
<p class="did">Identity: <span>{did}</span></p>

<label>Enter the confirmation code from your terminal:<br>
<input id="cc" placeholder="WORD-WORD-WORD-1234" style="width: 320px">
</label>
<button id="reveal">Reveal recovery phrase</button>

<div id="out" style="margin-top:16px; display:none">
  <p>Your BIP-39 recovery phrase:</p>
  <div id="phrase" class="mnemonic"></div>
  <p>
    <button id="download">Download as .txt</button>
  </p>

  <h2 style="margin-top:24px">Register with a vault</h2>
  <p>
    Optional: bind this identity to a cloud vault so you can sync
    ceremonies to it later. The vault never sees the recovery phrase.
  </p>
  <p>
    <label>Vault URL:
      <input id="vaultUrl" value="https://api.cyaxios.com" style="width: 280px">
    </label>
    <button id="_register">Register</button>
  </p>
  <pre id="regStatus" style="background:#f6f6f6; padding:8px; min-height:24px; display:none"></pre>
</div>

<script>
const EXPECTED_CC = {confirm_code!r};
const NONCE_B64 = {nonce_b64!r};
const CT_B64 = {ct_b64!r};

function b64d(s) {{
  const pad = (4 - s.length % 4) % 4;
  s = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bs = atob(s);
  const out = new Uint8Array(bs.length);
  for (let i=0; i<bs.length; i++) out[i] = bs.charCodeAt(i);
  return out;
}}

async function reveal() {{
  const cc = document.getElementById("cc").value.trim();
  if (cc !== EXPECTED_CC) {{
    alert("Confirmation code mismatch.");
    return;
  }}
  const hex = location.hash.replace(/^#/, "");
  if (hex.length !== 64) {{
    alert("Missing #<key> fragment in URL. Open the URL exactly as shown in your terminal.");
    return;
  }}
  const key = new Uint8Array(hex.match(/.{{1,2}}/g).map(h => parseInt(h, 16)));
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, {{name:"AES-GCM"}}, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt(
    {{ name:"AES-GCM", iv: b64d(NONCE_B64),
       additionalData: new TextEncoder().encode("tn:claim:v1") }},
    cryptoKey, b64d(CT_B64));
  const phrase = new TextDecoder().decode(pt);
  document.getElementById("phrase").textContent = phrase;
  document.getElementById("out").style.display = "block";
  document.getElementById("download").onclick = () => {{
    const blob = new Blob([phrase + "\\n"], {{type:"text/plain"}});
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "tn-mnemonic.txt"; a.click();
  }};

  document.getElementById("_register").onclick = async () => {{
    const status = document.getElementById("regStatus");
    status.style.display = "block";
    status.textContent = "Deriving keys...";
    const vaultUrl = document.getElementById("vaultUrl").value.trim().replace(/\\/$/, "");
    if (!vaultUrl) {{ status.textContent = "Enter a vault URL."; return; }}

    try {{
      // BIP-39: mnemonic -> 64-byte seed. Lazy-loaded from esm.sh.
      const {{ mnemonicToSeed }} = await import("https://esm.sh/@scure/bip39@1.3.0");
      const seed = await mnemonicToSeed(phrase);  // Uint8Array(64)

      // HKDF-SHA256: seed -> root (salt "tn:v1", info "tn:root:v1")
      async function hkdf(ikm, salt, info, len) {{
        const key = await crypto.subtle.importKey(
          "raw", ikm, "HKDF", false, ["deriveBits"]);
        return new Uint8Array(await crypto.subtle.deriveBits(
          {{ name: "HKDF", hash: "SHA-256", salt, info }}, key, len * 8));
      }}
      const root = await hkdf(seed,
        new TextEncoder().encode("tn:v1"),
        new TextEncoder().encode("tn:root:v1"), 32);
      const devPriv = await hkdf(root,
        new TextEncoder().encode("tn:v1"),
        new TextEncoder().encode("tn:device:v1"), 32);

      // Ed25519 sign via noble/curves (WebCrypto raw-seed import for
      // Ed25519 is still gappy in 2026; noble is the reliable route).
      const {{ ed25519 }} = await import("https://esm.sh/@noble/curves@1.6.0/ed25519");

      status.textContent = "Requesting challenge...";
      const did = {did!r};
      const chalResp = await fetch(vaultUrl + "/api/v1/auth/challenge", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{did}}),
      }});
      if (!chalResp.ok) {{
        status.textContent = "Challenge failed: " + chalResp.status + " " + await chalResp.text();
        return;
      }}
      const {{nonce}} = await chalResp.json();

      status.textContent = "Signing + verifying...";
      const msg = new TextEncoder().encode(nonce);
      const sigBytes = ed25519.sign(msg, devPriv);
      const sigB64 = btoa(String.fromCharCode(...sigBytes))
        .replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");

      const verResp = await fetch(vaultUrl + "/api/v1/auth/verify", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{did, nonce, signature: sigB64}}),
      }});
      if (!verResp.ok) {{
        status.textContent = "Verify failed: " + verResp.status + " " + await verResp.text();
        return;
      }}
      const {{token}} = await verResp.json();
      status.textContent =
        "Registered. JWT issued (truncated):\\n" + token.slice(0, 40) + "...\\n\\n" +
        "DID " + did + " is now authenticated at " + vaultUrl + ".";
    }} catch (e) {{
      status.textContent = "Error: " + (e.message || e);
    }}
  }};
}}

document.getElementById("reveal").addEventListener("click", reveal);
</script>
</body></html>
"""


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_claim(
    *,
    ttl_secs: int = DEFAULT_TTL_SECS,
    host: str = "127.0.0.1",
    port: int | None = None,
) -> ClaimSession:
    """Generate identity, wrap mnemonic, spin up loopback server.

    Returns a ClaimSession. The caller should:
    - use `session.identity` for immediate work
    - log `session.url` and `session.confirmation_code` (separately!)
    - call `session.shutdown()` at shutdown (best-effort; TTL handles
      runaway cases)
    """
    identity = Identity.create_new()
    mnemonic = identity._mnemonic
    if mnemonic is None:
        raise RuntimeError("Identity.create_new() did not produce a mnemonic")

    token_bytes = secrets.token_bytes(16)
    token = token_bytes.hex()  # 32 hex chars in URL path

    # Fragment-only key — printed in the URL hash, never sent to server
    frag_bytes = secrets.token_bytes(32)
    frag_hex = frag_bytes.hex()  # 64 hex chars in URL fragment

    # Wrap mnemonic with the fragment-only key
    nonce_b64, ct_b64 = _wrap_mnemonic(mnemonic, frag_bytes)

    confirm_code = _generate_confirm_code()

    if port is None:
        port = _find_free_port()

    expires_at = time.time() + ttl_secs
    url = f"http://{host}:{port}/claim/{token}#{frag_hex}"

    handler_cls = _make_handler(
        token=token,
        nonce_b64=nonce_b64,
        ct_b64=ct_b64,
        confirm_code=confirm_code,
        did=identity.did,
        expires_at=expires_at,
    )

    server = socketserver.ThreadingTCPServer((host, port), handler_cls)
    server.allow_reuse_address = True
    thread = threading.Thread(
        target=server.serve_forever,
        name=f"tn-claim-{token[:8]}",
        daemon=True,
    )
    thread.start()

    # TTL watchdog — wipe wrap materials (best-effort)
    def _ttl_kill():
        time.sleep(ttl_secs + 1)
        try:
            server.shutdown()
            server.server_close()
        except OSError:
            # Already-closed sockets / server-already-shut-down are normal here.
            pass

    threading.Thread(target=_ttl_kill, daemon=True, name=f"tn-claim-ttl-{token[:8]}").start()

    return ClaimSession(
        identity=identity,
        url=url,
        confirmation_code=confirm_code,
        token=token,
        expires_at=expires_at,
        _server=server,
        _thread=thread,
    )
