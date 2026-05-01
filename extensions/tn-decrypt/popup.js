// Popup: per-keystore unlock UI + extension-wide passkey-PRF unlock.
//
// WebAuthn must be called from a page context (popup or options),
// not from the service worker. So this file owns the
// navigator.credentials.create() / .get() calls, derives the EMK
// from the PRF output, and ships the EMK bytes to background.js
// over a runtime message. The EMK never touches disk; it only lives
// in the service worker's memory until the SW unloads or the user
// clicks "Lock all".

import { bytesToB64, b64ToBytes, rand } from "./unlock.js";

const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}

// Minimal text-encoder helpers. The popup runs in a normal page so
// we don't need crypto fallbacks.
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// WebAuthn-PRF helpers
//
// We use a placeholder relying-party id ("tn-decrypt-extension") and
// the chrome-extension origin (popup.html). The popup's origin is
// the extension id — Chrome accepts that as a valid RP id for
// extension-scoped credentials. If the platform refuses it, we fall
// back to passphrase.
// ---------------------------------------------------------------------------

function rpId() {
  // For chrome-extension://<id>/popup.html the RP id is the
  // extension origin's host, which Chrome exposes as the extension
  // id. Using location.hostname gives us the right value
  // automatically without hardcoding it.
  return window.location.hostname;
}

// Wrappers that derive the raw 32 bytes for shipping to the service
// worker as base64. The SW imports the bytes as a non-extractable
// CryptoKey on its side; the raw bytes only ever exist inside this
// extension (popup → SW message hop).
async function deriveEmkRawFromPrfOutput(prfOutput) {
  const bytes = new Uint8Array(prfOutput);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return digest; // 32 bytes
}

async function deriveEmkRawFromPassphrase(passphrase, saltBytes, iterations) {
  const pk = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase),
    { name: "PBKDF2" }, false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    pk, 256,
  );
  return new Uint8Array(bits);
}

// Register a new passkey with the PRF extension. Returns
// { credential_id_b64, prf_output_bytes, prf_salt_b64, rp_id }.
// Throws if the authenticator declines or if PRF is not supported.
async function registerPrfPasskey() {
  const userId = rand(16);
  const challenge = rand(32);
  const prfSalt = rand(32);
  const myRpId = rpId();
  console.log(`[ext:unlock] registerPrfPasskey rp=${myRpId} (D-22 PRF path)`);
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: myRpId, name: "TN Decrypt" },
      user: { id: userId, name: "tn-decrypt-user", displayName: "TN Decrypt" },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },   // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      extensions: {
        prf: { eval: { first: prfSalt } },
      },
      timeout: 60000,
    },
  });
  if (!cred) throw new Error("registration cancelled");
  const ext = cred.getClientExtensionResults?.() || {};
  // Some authenticators only return PRF results on the second
  // (.get) call. We allow that path: if the .create() result didn't
  // include prf.results, do an immediate .get() with the same salt
  // to fetch them.
  let prfBytes;
  if (ext.prf && ext.prf.results && ext.prf.results.first) {
    prfBytes = new Uint8Array(ext.prf.results.first);
  } else if (ext.prf && ext.prf.enabled === true) {
    prfBytes = await getPrfOutput(cred.rawId, prfSalt);
  } else {
    throw new Error("PRF extension not supported by this authenticator");
  }
  return {
    credential_id_b64: bytesToB64(new Uint8Array(cred.rawId)),
    prf_output_bytes: prfBytes,
    prf_salt_b64: bytesToB64(prfSalt),
    rp_id: myRpId,
  };
}

// Authenticate an existing passkey and pull a PRF output.
async function getPrfOutput(credentialIdBytes, prfSaltBytes) {
  const challenge = rand(32);
  console.log("[ext:unlock] getPrfOutput: assertion request (user gesture)");
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: rpId(),
      allowCredentials: [{
        type: "public-key",
        id: credentialIdBytes,
      }],
      userVerification: "required",
      extensions: { prf: { eval: { first: prfSaltBytes } } },
      timeout: 60000,
    },
  });
  if (!assertion) throw new Error("unlock cancelled");
  const ext = assertion.getClientExtensionResults?.() || {};
  if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
    throw new Error("authenticator returned no PRF output");
  }
  return new Uint8Array(ext.prf.results.first);
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

let lastStatus = null;

async function refresh() {
  const s = await chrome.runtime.sendMessage({ type: "status" });
  lastStatus = s;
  renderExtUnlock(s);
  renderVaultPair(s);
  renderKeystores(s);
}

// ---------------------------------------------------------------------------
// Vault pair card — "Sign in with vault" + status of paired projects.
// O-9 hybrid pairing flow: opens a tab to the vault's /extension-pair
// page with the extension id in the query string. The vault decrypts
// the projects in that tab and posts the kits back via
// chrome.runtime.sendMessage(<ext_id>, ...). See background.js for the
// receiver.
// ---------------------------------------------------------------------------

// Where to open the pair flow. Localhost first (current setup); a
// future production deploy at https://tnproto.org/ is an additional
// item in this list. The popup tries the entries in order.
const VAULT_PAIR_BASE_URLS = [
  "http://localhost:8790",
  "https://tnproto.org",
];

function pairedKits(s) {
  return (s.keystores || []).filter((k) => (k.source || "vault") === "vault-paired");
}

function pairedSummary(s) {
  const paired = pairedKits(s);
  if (paired.length === 0) return null;
  // Group rows by (account_label, project_id) so the popup shows one
  // line per project.
  const byProject = new Map();
  for (const k of paired) {
    const key = `${k.account_label || ""}|${k.project_id || ""}`;
    if (!byProject.has(key)) {
      byProject.set(key, {
        account_label: k.account_label || null,
        project_id: k.project_id,
        project_label: k.project_label || k.project_id || "(unknown)",
        groups: [],
        paired_at: k.paired_at || null,
      });
    }
    byProject.get(key).groups.push(k.group || "default");
  }
  return Array.from(byProject.values());
}

async function openPairTab() {
  const extId = chrome.runtime.id;
  if (!/^[a-p]{32}$/.test(extId)) {
    console.error(`[ext:vault-pair] suspicious extension id ${extId}`);
  }
  // Use the first base URL — until we ship a way to choose, localhost
  // is the only deploy. Multi-deploy support is a wider product call.
  const base = VAULT_PAIR_BASE_URLS[0];
  const url = `${base}/extension-pair?ext_id=${encodeURIComponent(extId)}`;
  console.log(`[ext:vault-pair] opening pair tab ${url}`);
  await chrome.tabs.create({ url });
}

function renderVaultPair(s) {
  const host = $("vault-pair");
  const summary = pairedSummary(s);

  if (!summary || summary.length === 0) {
    host.innerHTML = `
      <h2>Sign in with vault</h2>
      <p>Pull every project's kits down from your tnproto.org vault account in one tap. Coexists with kits imported from disk.</p>
      <div class="row">
        <button id="btn-vault-pair">Sign in with vault</button>
      </div>
      <div id="vault-pair-msg" class="hint"></div>
    `;
    $("btn-vault-pair").addEventListener("click", openPairTab);
    return;
  }

  const totalKits = pairedKits(s).length;
  const projectLines = summary.map((p) => {
    return `<div class="pair-meta">${escapeHtml(p.project_label)} <span style="color:#888">· ${p.groups.length} group${p.groups.length === 1 ? "" : "s"}</span></div>`;
  }).join("");
  const account = summary.find((p) => p.account_label) || {};
  host.innerHTML = `
    <h2>Vault paired</h2>
    <p>${escapeHtml(account.account_label || "vault account")} · ${totalKits} kit${totalKits === 1 ? "" : "s"} from ${summary.length} project${summary.length === 1 ? "" : "s"}.</p>
    ${projectLines}
    <div class="small-actions">
      <a id="btn-vault-refresh">Refresh from vault</a>
      <a id="btn-vault-manage">Manage paired projects</a>
    </div>
    <div id="vault-pair-msg" class="hint"></div>
  `;
  $("btn-vault-refresh").addEventListener("click", openPairTab);
  $("btn-vault-manage").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });
}

function renderExtUnlock(s) {
  const host = $("ext-unlock");
  const eu = s.extension_unlock || { configured: false };

  // Local-file keystores don't need an unlock and shouldn't trigger
  // the "set up unlock" pitch. Only show that pitch when the user has
  // at least one vault-encrypted keystore that the EMK could
  // actually save them a passphrase typing on.
  const vaultKeystores = (s.keystores || []).filter((k) => (k.source || "vault") === "vault");

  if (!eu.configured) {
    if (vaultKeystores.length === 0) {
      host.classList.add("hidden");
      return;
    }
    host.classList.remove("hidden");
    host.innerHTML = `
      <h2>One-tap unlock</h2>
      <p>Set up a passkey so a single fingerprint or security-key tap unlocks every keystore.</p>
      <div class="row">
        <button id="btn-setup-prf">Set up unlock (passkey)</button>
        <button id="btn-setup-pass" class="secondary">Use passphrase instead</button>
      </div>
      <div id="setup-msg" class="hint"></div>
    `;
    $("btn-setup-prf").addEventListener("click", () => setupExtensionUnlock("prf"));
    $("btn-setup-pass").addEventListener("click", () => setupExtensionUnlock("passphrase"));
    return;
  }

  host.classList.remove("hidden");
  if (eu.session_unlocked) {
    host.innerHTML = `
      <h2>Extension unlocked</h2>
      <p>${escapeHtml(eu.kind === "prf" ? "Unlocked via passkey." : "Unlocked via passphrase.")} All bound keystores are open.</p>
      <div class="small-actions">
        <a id="btn-disable-ext">Disable one-tap unlock</a>
      </div>
    `;
    $("btn-disable-ext").addEventListener("click", disableExtensionUnlock);
    return;
  }

  if (eu.kind === "prf") {
    host.innerHTML = `
      <h2>Tap to unlock</h2>
      <p>Authenticate with your passkey to unlock all bound keystores.</p>
      <div class="row">
        <button id="btn-unlock-prf">Unlock with passkey</button>
      </div>
      <div id="unlock-msg" class="hint"></div>
      <div class="small-actions">
        <a id="btn-disable-ext">Forget this passkey</a>
      </div>
    `;
    $("btn-unlock-prf").addEventListener("click", unlockWithPasskey);
    $("btn-disable-ext").addEventListener("click", disableExtensionUnlock);
  } else {
    host.innerHTML = `
      <h2>Unlock</h2>
      <p>Enter your extension passphrase to unlock all bound keystores.</p>
      <div class="row">
        <input id="ext-pass" type="password" placeholder="extension passphrase" autocomplete="current-password" />
        <button id="btn-unlock-pass">Unlock</button>
      </div>
      <div id="unlock-msg" class="hint"></div>
      <div class="small-actions">
        <a id="btn-disable-ext">Forget this passphrase</a>
      </div>
    `;
    $("btn-unlock-pass").addEventListener("click", unlockWithPassphrase);
    $("ext-pass").addEventListener("keydown", (ev) => { if (ev.key === "Enter") unlockWithPassphrase(); });
    $("btn-disable-ext").addEventListener("click", disableExtensionUnlock);
  }
}

function renderKeystores(s) {
  const banner = $("banner");
  const host = $("keystores");

  if (!s.keystores || s.keystores.length === 0) {
    banner.className = "banner warn";
    banner.textContent = "No keystores yet. Import one from Options.";
    host.innerHTML = "";
    return;
  }

  const unlockedCount = s.keystores.filter((k) => k.unlocked).length;
  const totalKits = s.keystores.reduce((n, k) => n + (k.kit_count || 0), 0);
  if (unlockedCount === 0) {
    banner.className = "banner warn";
    banner.textContent = `${s.keystores.length} keystore${s.keystores.length === 1 ? "" : "s"} saved. Unlock to decrypt pages.`;
  } else {
    banner.className = "banner ok";
    banner.textContent = `${unlockedCount}/${s.keystores.length} unlocked — ${totalKits} kit${totalKits === 1 ? "" : "s"} ready`;
  }

  const ordered = s.order.map((id) => s.keystores.find((k) => k.id === id)).filter(Boolean);
  host.innerHTML = ordered.map((k) => {
    const source = k.source || "vault";
    let sourceBadge;
    if (source === "local-file") {
      sourceBadge = `<span class="ks-source-pill ks-source-local">On disk</span>`;
    } else if (source === "vault-paired") {
      sourceBadge = `<span class="ks-source-pill ks-source-paired">Vault paired</span>`;
    } else {
      sourceBadge = `<span class="ks-source-pill ks-source-vault">From vault</span>`;
    }
    // local-file AND vault-paired entries are plaintext bundles; they
    // share the "isLocal" UX (no passphrase prompt).
    const isLocal = source === "local-file" || source === "vault-paired";
    // Local-file keystores have nothing to lock — they're plaintext
    // on disk anyway. Still let the user remove them via Options.
    let formHtml;
    if (k.unlocked) {
      formHtml = isLocal
        ? `<div class="ks-form"><span class="ks-meta">ready</span></div>`
        : `<div class="ks-form"><button class="secondary small" data-act="lock">Lock</button></div>`;
    } else if (isLocal) {
      // Should be auto-loaded; if it isn't, show a quick "Reload"
      // button that calls the unlock path with no passphrase.
      formHtml = `<div class="ks-form"><button data-act="reload" class="small">Reload</button></div>`;
    } else {
      formHtml = `<div class="ks-form">
           <input type="password" placeholder="passphrase" autocomplete="current-password" />
           <button data-act="unlock" class="small">Unlock</button>
         </div>`;
    }
    return `
    <div class="ks-row ${k.unlocked ? "unlocked" : "locked"}" data-id="${escapeHtml(k.id)}">
      <div class="ks-head">
        <span class="ks-label">${escapeHtml(k.label)}${sourceBadge}${k.bound_to_emk ? `<span class="ks-bound-pill">bound</span>` : ""}</span>
        <span class="ks-meta">${k.unlocked ? `${k.publisher_count} pub / ${k.kit_count} kits` : (isLocal ? "loading..." : "locked")}</span>
      </div>
      ${formHtml}
    </div>`;
  }).join("");

  host.querySelectorAll(".ks-row").forEach((row) => {
    row.querySelector('[data-act="unlock"]')?.addEventListener("click", async () => {
      const id = row.dataset.id;
      const pass = row.querySelector("input").value;
      if (!pass) return;
      row.querySelector('[data-act="unlock"]').disabled = true;
      const r = await chrome.runtime.sendMessage({ type: "unlock", id, passphrase: pass });
      if (!r.ok) {
        $("banner").className = "banner err";
        $("banner").textContent = r.reason || "unlock failed";
        row.querySelector('[data-act="unlock"]').disabled = false;
        return;
      }
      await refresh();
      rescan();
    });
    row.querySelector('[data-act="reload"]')?.addEventListener("click", async () => {
      const id = row.dataset.id;
      // unlockOne treats local-file as a no-passphrase reload.
      await chrome.runtime.sendMessage({ type: "unlock", id, passphrase: "" });
      await refresh();
      rescan();
    });
    row.querySelector('[data-act="lock"]')?.addEventListener("click", async () => {
      await chrome.runtime.sendMessage({ type: "lock", id: row.dataset.id });
      await refresh();
    });
  });
}

// ---------------------------------------------------------------------------
// Set up extension-wide unlock
// ---------------------------------------------------------------------------

async function setupExtensionUnlock(kind) {
  const msg = $("setup-msg");
  msg.className = "hint";
  msg.textContent = "";

  // Collect already-unlocked keystore secrets via the user's
  // passphrases. We can only bind keystores the user knows the
  // passphrase for right now. The simplest UX: prompt once for an
  // optional list. But to keep this popup simple, we just bind
  // nothing here, and rely on the unlockOne() codepath in
  // background.js to lazily bind each keystore the next time the
  // user enters its passphrase. So the first session after setup
  // still costs one prompt per keystore; from there, it's one tap.
  const keystore_secrets = {};

  try {
    if (kind === "prf") {
      msg.textContent = "Follow the prompt from your authenticator...";
      let reg;
      try {
        reg = await registerPrfPasskey();
      } catch (e) {
        msg.className = "err";
        msg.textContent = `Passkey setup failed: ${e.message}. Falling back to passphrase.`;
        return setupExtensionUnlock("passphrase");
      }
      const emkRaw = await deriveEmkRawFromPrfOutput(reg.prf_output_bytes);
      const r = await chrome.runtime.sendMessage({
        type: "setupExtensionUnlock",
        kind: "prf",
        emk_raw_b64: bytesToB64(emkRaw),
        prf: {
          credential_id_b64: reg.credential_id_b64,
          prf_salt_b64: reg.prf_salt_b64,
          rp_id: reg.rp_id,
        },
        keystore_secrets,
      });
      if (!r.ok) throw new Error(r.reason || "setup failed");
      msg.className = "ok";
      msg.textContent = `Passkey unlock ready. Bound ${r.bound} keystore${r.bound === 1 ? "" : "s"}.`;
    } else {
      const pass = prompt("Choose an extension passphrase (8+ chars). You'll type this each time you open the popup.");
      if (!pass) return;
      if (pass.length < 8) {
        msg.className = "err";
        msg.textContent = "Passphrase must be 8+ characters.";
        return;
      }
      const salt = rand(16);
      const iterations = 260000;
      const emkRaw = await deriveEmkRawFromPassphrase(pass, salt, iterations);
      const r = await chrome.runtime.sendMessage({
        type: "setupExtensionUnlock",
        kind: "passphrase",
        emk_raw_b64: bytesToB64(emkRaw),
        pass: {
          kdf_salt_b64: bytesToB64(salt),
          kdf_iterations: iterations,
        },
        keystore_secrets,
      });
      if (!r.ok) throw new Error(r.reason || "setup failed");
      msg.className = "ok";
      msg.textContent = `Passphrase unlock ready. Bound ${r.bound} keystore${r.bound === 1 ? "" : "s"}.`;
    }
    await refresh();
  } catch (e) {
    msg.className = "err";
    msg.textContent = e.message || String(e);
  }
}

// ---------------------------------------------------------------------------
// Unlock with passkey / passphrase
// ---------------------------------------------------------------------------

async function unlockWithPasskey() {
  const msg = $("unlock-msg");
  msg.className = "hint";
  msg.textContent = "Tap your authenticator...";
  try {
    const meta = await chrome.runtime.sendMessage({ type: "getExtensionUnlockMeta" });
    if (!meta.ok || !meta.configured || meta.kind !== "prf") throw new Error("not configured");
    const credId = b64ToBytes(meta.credential_id_b64);
    const prfSalt = b64ToBytes(meta.prf_salt_b64);
    const prfOutput = await getPrfOutput(credId, prfSalt);
    const emkRaw = await deriveEmkRawFromPrfOutput(prfOutput);
    const r = await chrome.runtime.sendMessage({
      type: "unlockExtension",
      emk_raw_b64: bytesToB64(emkRaw),
    });
    if (!r.ok) throw new Error(r.reason || "unlock failed");
    msg.className = "ok";
    msg.textContent = `Unlocked ${r.unlocked} keystore${r.unlocked === 1 ? "" : "s"}.`;
    await refresh();
    rescan();
  } catch (e) {
    console.error(`[ext:unlock] unlockWithPasskey: ${e?.name || "Error"} ${e?.message || ""}`);
    msg.className = "err";
    msg.textContent = e.message || String(e);
  }
}

async function unlockWithPassphrase() {
  const msg = $("unlock-msg");
  msg.className = "hint";
  msg.textContent = "";
  const pass = $("ext-pass").value;
  if (!pass) return;
  try {
    const meta = await chrome.runtime.sendMessage({ type: "getExtensionUnlockMeta" });
    if (!meta.ok || !meta.configured || meta.kind !== "passphrase") throw new Error("not configured");
    const salt = b64ToBytes(meta.kdf_salt_b64);
    const iterations = meta.kdf_iterations;
    const emkRaw = await deriveEmkRawFromPassphrase(pass, salt, iterations);
    const r = await chrome.runtime.sendMessage({
      type: "unlockExtension",
      emk_raw_b64: bytesToB64(emkRaw),
    });
    if (!r.ok) throw new Error(r.reason || "wrong passphrase");
    msg.className = "ok";
    msg.textContent = `Unlocked ${r.unlocked} keystore${r.unlocked === 1 ? "" : "s"}.`;
    await refresh();
    rescan();
  } catch (e) {
    console.error(`[ext:unlock] unlockWithPassphrase: ${e?.name || "Error"} ${e?.message || ""}`);
    msg.className = "err";
    msg.textContent = e.message || String(e);
  }
}

async function disableExtensionUnlock() {
  if (!confirm("Forget the extension-wide unlock? You'll need each keystore's passphrase again.")) return;
  await chrome.runtime.sendMessage({ type: "disableExtensionUnlock" });
  await refresh();
}

// ---------------------------------------------------------------------------
// Page actions
// ---------------------------------------------------------------------------

async function rescan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) chrome.tabs.sendMessage(tab.id, { type: "rescan" }).catch(() => {});
}

$("btn-rescan").addEventListener("click", rescan);
$("btn-lock-all").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "lockAll" });
  await refresh();
});

// ---------------------------------------------------------------------------
// Paste-and-decrypt card. Mirrors the dashboard widget at
// tnproto-org/static/account/decrypt.js (D-1, D-22) — this just sends
// the user's input to the SW which sweeps every loaded kit.
// ---------------------------------------------------------------------------

// Render bytes (base64) as utf-8 if the SW handed us printable utf-8,
// else fall back to a hex dump derived from plaintext_b64.
function renderPlaintext(resp) {
  if (resp.plaintext_utf8) {
    return { kind: "utf-8", text: resp.plaintext_utf8 };
  }
  const bytes = b64ToBytes(resp.plaintext_b64);
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(" ");
  return { kind: "hex", text: hex };
}

async function runPopupDecrypt() {
  const input = $("dec-input").value;
  const $err = $("dec-err");
  const $outWrap = $("dec-out-wrap");
  const $out = $("dec-out");
  const $outMeta = $("dec-out-meta");
  const $hint = $("dec-hint");
  const $btn = $("btn-decrypt");

  $err.classList.add("hidden");
  $err.textContent = "";
  $outWrap.classList.add("hidden");
  $out.textContent = "";
  $outMeta.textContent = "";
  $hint.textContent = "";

  if (!input || !input.trim()) {
    $err.classList.remove("hidden");
    $err.textContent = "paste a ciphertext first";
    return;
  }

  $btn.disabled = true;
  $hint.textContent = "decrypting...";
  console.log(`[ext:popup-decrypt] sending ${input.length} chars to SW`);
  let resp;
  try {
    resp = await chrome.runtime.sendMessage({
      type: "tn:popup-decrypt",
      ciphertext_b64: input,
    });
  } catch (e) {
    console.error(`[ext:popup-decrypt] sendMessage failed: ${e?.name || "Error"} ${e?.message || ""}`);
    $btn.disabled = false;
    $hint.textContent = "";
    $err.classList.remove("hidden");
    $err.textContent = e?.message || String(e);
    return;
  }
  $btn.disabled = false;
  $hint.textContent = "";

  if (!resp || !resp.ok) {
    const reason = (resp && resp.reason) || "unknown error";
    console.log(`[ext:popup-decrypt] failure reason=${reason}`);
    $err.classList.remove("hidden");
    $err.textContent = reason;
    return;
  }

  const rendered = renderPlaintext(resp);
  console.log(`[ext:popup-decrypt] success kind=${rendered.kind} keystore=${resp.keystore_label} group=${resp.group}`);
  $outWrap.classList.remove("hidden");
  $out.textContent = rendered.text;
  const parts = [];
  parts.push(`format: ${rendered.kind}`);
  if (resp.keystore_label) parts.push(`keystore: ${resp.keystore_label}`);
  if (resp.group) parts.push(`group: ${resp.group}`);
  if (typeof resp.dt_ms === "number") parts.push(`${resp.dt_ms}ms`);
  $outMeta.textContent = parts.join(" - ");
}

$("btn-decrypt").addEventListener("click", runPopupDecrypt);
$("dec-input").addEventListener("keydown", (ev) => {
  // Cmd/Ctrl+Enter triggers decrypt.
  if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
    ev.preventDefault();
    runPopupDecrypt();
  }
});

refresh();
