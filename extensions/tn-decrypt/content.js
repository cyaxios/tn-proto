// Content script: scan every text node for base64-ish chunks and
// ask the service worker to classify each one. The SW returns one of:
//   - { class: "decrypted", plaintext_json | plaintext_utf8, publisher_id_hex, kit_leaf, keystore_label }
//   - { class: "sealed", publisher_id_hex }  // is a btn ciphertext but we hold no kit
//   - { class: "not-tn" }                    // some other base64 blob
//
// Decrypted chunks are spliced in place as a green pill. Sealed chunks
// are spliced as a gray pill. "not-tn" is left alone.

(() => {
  if (window.__tn_decrypt_injected) return;
  window.__tn_decrypt_injected = true;

  // Content scripts run in the page's world, so anything logged here is
  // observable by the host page (which can override console). That would
  // leak how much TN content the extension found on the very page it's
  // meant to keep opaque. Keep logging OFF in the shipped build; flip to
  // true only for local debugging.
  const DEBUG = false;
  const dlog = (...a) => { if (DEBUG) console.log(...a); };
  const derr = (...a) => { if (DEBUG) console.error(...a); };

  // Any base64 chunk of 40+ chars. Covers btn ciphertexts (a couple
  // hundred bytes -> ~280+ base64 chars) without matching every short
  // hash/signature that happens to look base64. Short tokens like
  // "hmac-sha256:v1:..." contain ":" so won't match.
  const B64_CHUNK = /[A-Za-z0-9+/]{40,}={0,2}/g;

  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT"]);

  const STYLE_ID = "tn-decrypt-style";
  function injectStyle() {
    if (document.getElementById(STYLE_ID)) return;
    const s = document.createElement("style");
    s.id = STYLE_ID;
    s.textContent = `
      .tn-pill {
        display: inline-flex;
        align-items: baseline;
        gap: 4px;
        padding: 1px 8px 1px 3px;
        border-radius: 12px;
        font: 11px/1.6 system-ui, sans-serif;
        vertical-align: middle;
        max-width: 540px;
      }
      .tn-pill .tn-badge {
        color: #fff;
        font-size: 9px;
        font-weight: 700;
        letter-spacing: 0.5px;
        padding: 0 5px;
        border-radius: 6px;
        cursor: pointer;
        user-select: none;
        flex-shrink: 0;
      }
      .tn-pill .tn-badge:hover { opacity: 0.85; }
      .tn-verify {
        font-size: 10px;
        font-weight: 700;
        padding: 0 2px;
        flex-shrink: 0;
        cursor: help;
        align-self: center;
      }
      .tn-verify.ok { color: #1f7a34; }
      .tn-verify.bad { color: #b30000; }
      .tn-pill .tn-summary {
        cursor: pointer;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        flex: 1 1 auto;
        min-width: 0;
      }
      .tn-pill.decrypted {
        background: #e9f3e7;
        color: #17381e;
        border: 1px solid #bcd8b5;
      }
      .tn-pill.decrypted .tn-badge { background: #1f7a34; }
      .tn-pill.sealed {
        background: #ebebeb;
        color: #444;
        border: 1px solid #cfcfcf;
      }
      .tn-pill.sealed .tn-badge { background: #777; }
      .tn-pill.swapped {
        background: #1f1f1f;
        color: #ddd;
        border-color: #1f1f1f;
        font-family: ui-monospace, Menlo, monospace;
        align-items: flex-start;
        max-width: none;
        display: inline-flex;
      }
      .tn-pill.swapped .tn-badge { background: #555; margin-top: 2px; }
      .tn-pill.swapped .tn-summary {
        white-space: pre-wrap;
        word-break: break-all;
        overflow: visible;
        text-overflow: clip;
        font-size: 11px;
      }
      .tn-pill.expanded {
        align-items: stretch;
        flex-wrap: wrap;
        max-width: none;
      }
      .tn-pill.expanded .tn-summary {
        white-space: normal;
        flex-basis: 100%;
      }
      .tn-pill .tn-expand {
        flex-basis: 100%;
        margin-top: 4px;
        padding: 6px 8px;
        background: rgba(0,0,0,0.06);
        border-radius: 4px;
        font-family: ui-monospace, Menlo, monospace;
        font-size: 11px;
        white-space: pre-wrap;
        word-break: break-all;
      }
    `;
    (document.head || document.documentElement).appendChild(s);
  }

  function shortPub(pid) {
    if (!pid) return "";
    return pid.slice(0, 10);
  }

  // Cheap envelope-shape probe — mirrors looksLikeEnvelope() in
  // tnproto-org/static/account/log_viewer.js. Returns true when the
  // decrypted plaintext is a full TN envelope rather than a bag of
  // user kwargs. This is the signal to flip the pill from
  // "JSON.stringify the payload" to "render via Entry.toString()".
  function _isTnEnvelope(o) {
    if (!o || typeof o !== "object" || Array.isArray(o)) return false;
    return (
      typeof o.event_type === "string" &&
      (typeof o.device_identity === "string" || typeof o.did === "string") &&
      typeof o.event_id === "string" &&
      (typeof o.sequence === "number" || typeof o.sequence === "string")
    );
  }

  // Pull every top-level balanced {...} JSON object out of a text blob.
  // Handles ndjson (one object per line), pretty-printed multi-line JSON,
  // and inline objects. String contents (incl. escaped quotes/braces) are
  // skipped so braces inside a value don't confuse the depth counter.
  function _extractJsonObjects(text) {
    const objs = [];
    let depth = 0, start = -1, inStr = false, esc = false;
    for (let i = 0; i < text.length; i += 1) {
      const c = text[i];
      if (inStr) {
        if (esc) esc = false;
        else if (c === "\\") esc = true;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') { inStr = true; continue; }
      if (c === "{") { if (depth === 0) start = i; depth += 1; }
      else if (c === "}") {
        depth -= 1;
        if (depth === 0 && start >= 0) { objs.push(text.slice(start, i + 1)); start = -1; }
        else if (depth < 0) { depth = 0; start = -1; }
      }
    }
    return objs;
  }

  // Find verifiable TN envelopes in a text node (must carry row_hash +
  // signature). Returns parsed envelope objects, deduped by row_hash.
  function _envelopesInText(text, seen) {
    if (!text || text.indexOf("row_hash") === -1) return [];
    const found = [];
    for (const objStr of _extractJsonObjects(text)) {
      let env;
      try { env = JSON.parse(objStr); } catch { continue; }
      if (_isTnEnvelope(env) && typeof env.row_hash === "string" && typeof env.signature === "string") {
        if (!seen.has(env.row_hash)) { seen.add(env.row_hash); found.push(env); }
      }
    }
    return found;
  }

  // Mirror of Entry.toString() — kept inline because content scripts
  // can't `import` from the vendored Entry.js without dynamic-import
  // gymnastics. Verified byte-for-byte against the real Entry by the
  // extension tests under test/extension_logic.mjs.
  //
  // Format (matching Python's `print(entry)` and the TS Entry.toString):
  //   HH:MM:SS.mmm LEVEL  seq=N  event_type  k=v  k=v
  function _envelopeToEntryLine(env) {
    const ENVELOPE_KEYS = new Set([
      "event_type", "timestamp", "level", "message", "device_identity", "did",
      "event_id", "sequence", "run_id", "prev_hash", "row_hash", "signature",
    ]);
    const ts = env.timestamp instanceof Date
      ? env.timestamp
      : (typeof env.timestamp === "string" || typeof env.timestamp === "number"
          ? new Date(env.timestamp)
          : new Date(NaN));
    let head;
    if (isNaN(ts.getTime())) {
      const lvl = String(env.level || "").toUpperCase().padEnd(7, " ");
      head = `?              ${lvl} seq=${env.sequence}  ${env.event_type}`;
    } else {
      const hh = String(ts.getUTCHours()).padStart(2, "0");
      const mm = String(ts.getUTCMinutes()).padStart(2, "0");
      const ss = String(ts.getUTCSeconds()).padStart(2, "0");
      const ms = String(ts.getUTCMilliseconds()).padStart(3, "0");
      const lvl = String(env.level || "").toUpperCase().padEnd(7, " ");
      head = `${hh}:${mm}:${ss}.${ms} ${lvl} seq=${env.sequence}  ${env.event_type}`;
    }
    // run_id and message are envelope slots — Entry hoists them out of
    // the user fields. Mirror that here so the line matches.
    const SLOT_KEYS = new Set([...ENVELOPE_KEYS, "run_id", "message"]);
    const fieldKeys = Object.keys(env).filter((k) => !SLOT_KEYS.has(k) && !k.startsWith("_"));
    if (fieldKeys.length === 0) return head;
    const kvs = fieldKeys.map((k) => {
      const v = env[k];
      let r;
      if (typeof v === "string") {
        r = "'" + v.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
      } else if (typeof v === "boolean") {
        r = v ? "True" : "False";
      } else if (typeof v === "number" || typeof v === "bigint") {
        r = String(v);
      } else if (v === null || v === undefined) {
        r = "None";
      } else {
        try { r = JSON.stringify(v); } catch { r = String(v); }
      }
      return `${k}=${r}`;
    }).join("  ");
    return `${head}  ${kvs}`;
  }

  function prettyPlaintext(result) {
    if (result.plaintext_json && typeof result.plaintext_json === "object") {
      // Auto-detect: if the decrypted plaintext is itself a full TN
      // envelope (has event_type / did / sequence / event_id), render
      // via the Entry.toString() shape rather than dumping the raw
      // JSON. Caller can still see the JSON via the "RAW" toggle on
      // the pill — this just makes the default detail view human-
      // scannable.
      if (_isTnEnvelope(result.plaintext_json)) {
        return _envelopeToEntryLine(result.plaintext_json);
      }
      return JSON.stringify(result.plaintext_json, null, 2);
    }
    if (result.plaintext_utf8) return result.plaintext_utf8;
    return "(binary)";
  }

  // Build a short inline summary like "amount=99.5, customer=Alice".
  // Falls back to count of fields if the values don't format cleanly.
  function summaryLine(result) {
    const j = result.plaintext_json;
    if (j && typeof j === "object") {
      // Same auto-detect as prettyPlaintext: an envelope-shaped
      // plaintext gets the headline `event_type seq=N` summary, not
      // the alphabetised k=v dump that's tuned for user-payload kwargs.
      if (_isTnEnvelope(j)) {
        return `${j.event_type} seq=${j.sequence}`;
      }
      const parts = [];
      for (const [k, v] of Object.entries(j).sort(([a], [b]) => a.localeCompare(b))) {
        let s;
        if (v === null || v === undefined) s = "null";
        else if (typeof v === "string") s = v.length > 40 ? v.slice(0, 37) + "..." : v;
        else s = String(v);
        parts.push(`${k}=${s}`);
        if (parts.join(", ").length > 160) { parts.push("..."); break; }
      }
      return parts.join(", ");
    }
    if (result.plaintext_utf8) {
      const s = result.plaintext_utf8;
      return s.length > 80 ? s.slice(0, 77) + "..." : s;
    }
    return "(binary)";
  }

  function makePill(result, matchText, verdict) {
    const pill = document.createElement("span");
    pill.className = "tn-pill " + (result.class === "decrypted" ? "decrypted" : "sealed");

    // The TN badge is its own click target. Clicking it swaps the pill
    // between the decrypted view and the original ciphertext view, so a
    // reader can flip back to what the vendor actually sees without
    // losing their place. The summary area keeps the expand-on-click
    // behavior for the full detail panel.
    const badge = document.createElement("span");
    badge.className = "tn-badge";
    badge.textContent = "TN";
    const summary = document.createElement("span");
    summary.className = "tn-summary";

    // "showing" toggles between "decrypted" (default) and "original".
    let showing = "decrypted";

    function renderSummary() {
      if (showing === "original") {
        // Show the raw ciphertext in full, wrapped so the reader sees
        // every byte the vendor page would expose without this
        // extension. Inline styles beat the single-line defaults.
        summary.textContent = matchText;
        badge.textContent = "RAW";
        pill.classList.add("swapped");
        pill.style.maxWidth = "none";
        pill.style.alignItems = "flex-start";
        summary.style.whiteSpace = "pre-wrap";
        summary.style.wordBreak = "break-all";
        summary.style.overflow = "visible";
        summary.style.textOverflow = "clip";
        summary.style.fontFamily = "ui-monospace, Menlo, monospace";
        badge.title = "Click to show the decrypted view";
      } else {
        badge.textContent = "TN";
        if (result.class === "decrypted") {
          const from = result.keystore_label ? `${result.keystore_label} \u2014 ` : "";
          summary.textContent = `${from}${summaryLine(result)}`;
          pill.title = `Decrypted by kit leaf ${result.kit_leaf} for publisher ${shortPub(result.publisher_id_hex)}...`;
          badge.title = "Click to see the original ciphertext the page would show without this extension";
        } else {
          summary.textContent = `sealed \u2014 publisher ${shortPub(result.publisher_id_hex)}...`;
          pill.title = "This is a TN ciphertext, but you do not hold a kit for its publisher.";
          badge.title = "Click to see the original ciphertext";
        }
        pill.classList.remove("swapped");
        pill.style.maxWidth = "";
        pill.style.alignItems = "";
        summary.style.whiteSpace = "";
        summary.style.wordBreak = "";
        summary.style.overflow = "";
        summary.style.textOverflow = "";
        summary.style.fontFamily = "";
      }
    }
    renderSummary();

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      showing = showing === "decrypted" ? "original" : "decrypted";
      // If the detail panel was open, refresh it too.
      const existingExpand = pill.querySelector(".tn-expand");
      if (existingExpand) {
        existingExpand.remove();
        pill.classList.remove("expanded");
      }
      renderSummary();
    });

    summary.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (pill.classList.contains("expanded")) {
        pill.classList.remove("expanded");
        const ex = pill.querySelector(".tn-expand");
        if (ex) ex.remove();
      } else {
        pill.classList.add("expanded");
        const ex = document.createElement("div");
        ex.className = "tn-expand";
        if (showing === "original") {
          ex.textContent = matchText;
        } else if (result.class === "decrypted") {
          ex.textContent = prettyPlaintext(result);
        } else {
          ex.textContent =
            `publisher_id: ${result.publisher_id_hex}\n\n` +
            `original ciphertext:\n${matchText}`;
        }
        pill.appendChild(ex);
      }
    });

    pill.appendChild(badge);
    if (verdict) {
      const vb = document.createElement("span");
      // index_ok === false is a genuine inconsistency (a lying search token);
      // null just means "couldn't check" (sealed row / rotated key) and must
      // not downgrade the ✓.
      const good = verdict.hash_ok && verdict.sig_ok && verdict.index_ok !== false;
      vb.className = "tn-verify " + (good ? "ok" : "bad");
      vb.textContent = good ? "✓" : "⚠"; // ✓ / ⚠
      if (good) {
        let t = `Verified — signed by ${shortPub(verdict.publisher_did)}…, row_hash intact`;
        t += verdict.index_ok === true
          ? ", search index consistent with the decrypted values"
          : " (search index not checked — sealed row or rotated key)";
        vb.title = t;
      } else {
        const reasons = [];
        if (!verdict.sig_ok) reasons.push("bad signature");
        if (!verdict.hash_ok) reasons.push("row_hash mismatch (tampered)");
        if (verdict.index_ok === false) {
          reasons.push(`search index does not match the value for: ${(verdict.index_bad_fields || []).join(", ")}`);
        }
        if (verdict.error) reasons.push(verdict.error);
        vb.title = `Verification FAILED — ${reasons.join("; ")}`;
      }
      pill.appendChild(vb);
    }
    pill.appendChild(summary);
    return pill;
  }

  // Split a text node around matches and replace each match with a pill.
  function spliceNode(node, text, matches) {
    const anyPill = matches.some((m) => m.result.class === "decrypted" || m.result.class === "sealed");
    if (!anyPill) return false;
    const frag = document.createDocumentFragment();
    let cursor = 0;
    for (const m of matches) {
      if (m.index > cursor) frag.appendChild(document.createTextNode(text.slice(cursor, m.index)));
      if (m.result.class === "decrypted" || m.result.class === "sealed") {
        frag.appendChild(makePill(m.result, m.match, m.verdict));
      } else {
        frag.appendChild(document.createTextNode(m.match));
      }
      cursor = m.index + m.match.length;
    }
    if (cursor < text.length) frag.appendChild(document.createTextNode(text.slice(cursor)));
    node.parentNode.replaceChild(frag, node);
    return true;
  }

  function* textNodesUnder(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        let p = node.parentElement;
        while (p) {
          if (SKIP_TAGS.has(p.tagName)) return NodeFilter.FILTER_REJECT;
          if (p.classList && (p.classList.contains("tn-pill") || p.classList.contains("tn-expand"))) {
            return NodeFilter.FILTER_REJECT;
          }
          p = p.parentElement;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    let n;
    while ((n = walker.nextNode())) yield n;
  }

  let scanInFlight = false;
  let scanQueued = false;

  async function scan(root) {
    if (scanInFlight) { scanQueued = true; return; }
    scanInFlight = true;
    const t0 = Date.now();
    try {
      injectStyle();
      const st = await chrome.runtime.sendMessage({ type: "status" }).catch((e) => {
        derr(`[ext:scan] status query failed: ${e?.name || "Error"} ${e?.message || ""}`);
        return null;
      });
      if (!st || !st.unlocked) return;

      const work = [];
      const envelopes = [];
      const seenEnv = new Set();
      for (const node of textNodesUnder(root || document.body)) {
        const text = node.nodeValue;
        if (!text) continue;
        for (const env of _envelopesInText(text, seenEnv)) envelopes.push(env);
        B64_CHUNK.lastIndex = 0;
        const matches = [];
        let mm;
        while ((mm = B64_CHUNK.exec(text)) !== null) {
          matches.push({ match: mm[0], index: mm.index });
        }
        if (matches.length === 0) continue;
        work.push({ node, text, matches });
      }
      if (work.length === 0) return;

      const flat = work.flatMap((w) => w.matches.map((m) => m.match));
      dlog(`[ext:scan] candidates=${flat.length} text-nodes=${work.length}`);
      const res = await chrome.runtime.sendMessage({ type: "classifyBatch", candidates: flat });
      if (!res || !res.ok) {
        derr(`[ext:scan] classifyBatch failed: ${res && res.reason ? res.reason : "no response"}`);
        return;
      }

      // Verify any full envelopes found in the page (integrity +
      // authenticity). Independent of decryption — a sealed row you hold no
      // kit for still gets a ✓/⚠. Map each verdict onto every ciphertext it
      // covers so makePill can look it up by the matched chunk.
      const verdictByCt = new Map();
      if (envelopes.length) {
        const vr = await chrome.runtime.sendMessage({ type: "verifyBatch", envelopes }).catch(() => null);
        if (vr && vr.ok) {
          for (const r of vr.results) {
            for (const ct of r.ciphertexts || []) verdictByCt.set(ct, r);
          }
        }
      }

      let i = 0;
      let pillsSwapped = 0;
      for (const w of work) {
        const merged = w.matches.map((m) => ({ ...m, result: res.results[i++], verdict: verdictByCt.get(m.match) }));
        if (spliceNode(w.node, w.text, merged)) pillsSwapped += merged.filter((m) => m.result.class === "decrypted" || m.result.class === "sealed").length;
      }
      dlog(`[ext:scan] done pills=${pillsSwapped} dt=${Date.now() - t0}ms`);
    } finally {
      scanInFlight = false;
      if (scanQueued) { scanQueued = false; setTimeout(() => scan(), 250); }
    }
  }

  setTimeout(() => scan(), 400);

  let mutTimer = null;
  const observer = new MutationObserver(() => {
    if (mutTimer) clearTimeout(mutTimer);
    mutTimer = setTimeout(() => scan(), 400);
  });
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true,
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "rescan") scan();
  });
})();
