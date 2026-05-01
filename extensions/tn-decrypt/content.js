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

  function prettyPlaintext(result) {
    if (result.plaintext_json && typeof result.plaintext_json === "object") {
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

  function makePill(result, matchText) {
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
        frag.appendChild(makePill(m.result, m.match));
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
        console.error(`[ext:scan] status query failed: ${e?.name || "Error"} ${e?.message || ""}`);
        return null;
      });
      if (!st || !st.unlocked) return;

      const work = [];
      for (const node of textNodesUnder(root || document.body)) {
        const text = node.nodeValue;
        if (!text) continue;
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
      console.log(`[ext:scan] candidates=${flat.length} text-nodes=${work.length}`);
      const res = await chrome.runtime.sendMessage({ type: "classifyBatch", candidates: flat });
      if (!res || !res.ok) {
        console.error(`[ext:scan] classifyBatch failed: ${res && res.reason ? res.reason : "no response"}`);
        return;
      }

      let i = 0;
      let pillsSwapped = 0;
      for (const w of work) {
        const merged = w.matches.map((m) => ({ ...m, result: res.results[i++] }));
        if (spliceNode(w.node, w.text, merged)) pillsSwapped += merged.filter((m) => m.result.class === "decrypted" || m.result.class === "sealed").length;
      }
      console.log(`[ext:scan] done pills=${pillsSwapped} dt=${Date.now() - t0}ms`);
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
