const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
}
function b64(bytes) { const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes); let s=""; for (const b of a) s += String.fromCharCode(b); return btoa(s); }

// ---------------------------------------------------------------------------
// File -> bundle
// ---------------------------------------------------------------------------

async function readZip(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  let eocd = -1;
  for (let i = buffer.byteLength - 22; i >= Math.max(0, buffer.byteLength - 65558); i -= 1) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("Not a zip (no EOCD)");
  const cdEntries = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  const entries = new Map();
  let p = cdOffset;
  for (let i = 0; i < cdEntries; i += 1) {
    if (view.getUint32(p, true) !== 0x02014b50) throw new Error("Bad CD");
    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commLen = view.getUint16(p + 32, true);
    const localOffset = view.getUint32(p + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));
    entries.set(name, { method, compSize, localOffset });
    p += 46 + nameLen + extraLen + commLen;
  }
  async function read(name) {
    const e = entries.get(name);
    if (!e) return null;
    const lh = e.localOffset;
    const lhNameLen = view.getUint16(lh + 26, true);
    const lhExtraLen = view.getUint16(lh + 28, true);
    const dataStart = lh + 30 + lhNameLen + lhExtraLen;
    const comp = bytes.subarray(dataStart, dataStart + e.compSize);
    if (e.method === 0) return comp.slice();
    if (e.method === 8) {
      const ds = new DecompressionStream("deflate-raw");
      const w = ds.writable.getWriter();
      w.write(comp); w.close();
      return new Uint8Array(await new Response(ds.readable).arrayBuffer());
    }
    throw new Error("Unsupported zip method: " + e.method);
  }
  return { names: [...entries.keys()], read };
}

async function fileToBundle(file) {
  const name = (file.name || "").toLowerCase();
  const buf = await file.arrayBuffer();
  const head = new Uint8Array(buf.slice(0, 4));
  const isZip = head[0] === 0x50 && head[1] === 0x4b && (head[2] === 0x03 || head[2] === 0x05);

  if (isZip || name.endsWith(".zip") || name.endsWith(".tnpkg")) {
    const zip = await readZip(buf);

    // Read the manifest if present (new .tnpkg and legacy invitation
    // zips both ship one).
    let manifest = null;
    try {
      const mb = await zip.read("manifest.json");
      if (mb) manifest = JSON.parse(new TextDecoder().decode(mb));
    } catch {}

    // Pull every *.btn.mykit entry out of the archive. This covers
    // multi-kit .tnpkg files as well as single-kit bundles. For
    // backward compat with the old invitation format (which used
    // `kit.tnpkg` as the kit entry), fall back to that name under a
    // synthetic "default.btn.mykit" filename if no real *.btn.mykit
    // entries were found.
    const files = {};
    for (const entry of zip.names) {
      if (/(^|\/)[^/]+\.btn\.(mykit|mykit\.revoked\.\d+)$/.test(entry)) {
        const bytes = await zip.read(entry);
        if (bytes) files[entry.replace(/^.*\//, "")] = b64(new Uint8Array(bytes));
      }
    }
    if (Object.keys(files).length === 0) {
      const legacy = await zip.read("kit.tnpkg");
      if (legacy) files["default.btn.mykit"] = b64(new Uint8Array(legacy));
    }
    if (Object.keys(files).length === 0) {
      throw new Error("Archive contains no *.btn.mykit entries.");
    }

    return {
      bundle: {
        version: "keystore-v1",
        did: manifest?.did ?? null,
        ceremony_id: manifest?.ceremony_id ?? manifest?.project_name ?? null,
        origin: { kind: manifest?.kind ?? "invitation", manifest },
        files,
      },
      manifest,
    };
  }

  if (name.endsWith(".json")) {
    let parsed;
    try { parsed = JSON.parse(new TextDecoder().decode(buf)); }
    catch { throw new Error("File is not valid JSON."); }
    if (parsed.ciphertext_b64 && !parsed.files) {
      throw new Error("This is an encrypted blob, not a plaintext bundle. Decrypt it via tnproto-org's 'Coming from another device?' step first.");
    }
    if (!parsed.files || typeof parsed.files !== "object") {
      throw new Error("That JSON is not a keystore bundle (no 'files' map).");
    }
    const kitNames = Object.keys(parsed.files).filter((n) => /\.btn\.(mykit|mykit\.revoked\.\d+)$/.test(n));
    if (kitNames.length === 0) {
      throw new Error("That JSON has no reader kits inside (expected files ending in .btn.mykit).");
    }
    return { bundle: parsed, manifest: null };
  }

  if (buf.byteLength < 200) throw new Error("File is too small to be a reader kit.");
  return {
    bundle: {
      version: "keystore-v1",
      did: null, ceremony_id: null,
      origin: { kind: "raw-mykit", filename: file.name },
      files: { "default.btn.mykit": b64(new Uint8Array(buf)) },
    },
    manifest: null,
  };
}

// ---------------------------------------------------------------------------
// UI: list keystores with rename / reorder / remove
// ---------------------------------------------------------------------------

async function renderList() {
  const s = await chrome.runtime.sendMessage({ type: "status" });
  const host = $("ks-list");
  if (!s.keystores || s.keystores.length === 0) {
    host.innerHTML = `<div class="hint">No keystores yet. Add one below.</div>`;
    return;
  }
  const ordered = s.order.map((id) => s.keystores.find((k) => k.id === id)).filter(Boolean);
  host.innerHTML = `
    <table class="ks">
      <thead>
        <tr><th style="width:8%">#</th><th>Label</th><th style="width:18%">Source</th><th style="width:18%">Status</th><th style="width:36%">Actions</th></tr>
      </thead>
      <tbody>
        ${ordered.map((k, idx) => {
          const source = k.source || "vault";
          let sourceBadge;
          if (source === "local-file") {
            sourceBadge = `<span class="src-badge src-local">On disk</span>`;
          } else if (source === "vault-paired") {
            sourceBadge = `<span class="src-badge src-paired">Vault paired</span>`;
          } else {
            sourceBadge = `<span class="src-badge src-vault">From vault</span>`;
          }
          const subline = k.filename
            ? `<div class="src-filename">${escapeHtml(k.filename)}</div>`
            : (source === "vault-paired"
              ? `<div class="src-filename">${escapeHtml(k.account_label || "")}${k.account_label ? " · " : ""}${escapeHtml(k.project_label || k.project_id || "")}${k.group ? " · " + escapeHtml(k.group) : ""}</div>`
              : "");
          const isPlaintext = source === "local-file" || source === "vault-paired";
          return `
          <tr data-id="${escapeHtml(k.id)}">
            <td>${idx + 1}</td>
            <td><input type="text" class="label" value="${escapeHtml(k.label)}" /></td>
            <td>${sourceBadge}${subline}</td>
            <td>${k.unlocked ? `<span class="ok">${isPlaintext ? "ready" : "unlocked"} (${k.kit_count} kit${k.kit_count === 1 ? "" : "s"})</span>` : `<span class="warn">locked</span>`}</td>
            <td class="ks-actions">
              <button class="secondary small" data-act="up" ${idx === 0 ? "disabled" : ""}>Up</button>
              <button class="secondary small" data-act="down" ${idx === ordered.length - 1 ? "disabled" : ""}>Down</button>
              <button class="secondary small" data-act="rename">Save label</button>
              <button class="danger small" data-act="remove">Remove</button>
            </td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
  host.querySelectorAll("tr[data-id]").forEach((row) => {
    const id = row.dataset.id;
    row.querySelector('[data-act="up"]')?.addEventListener("click", () => move(id, -1));
    row.querySelector('[data-act="down"]')?.addEventListener("click", () => move(id, +1));
    row.querySelector('[data-act="rename"]')?.addEventListener("click", async () => {
      const label = row.querySelector(".label").value.trim();
      if (!label) return;
      await chrome.runtime.sendMessage({ type: "renameKeystore", id, label });
      await renderList();
    });
    row.querySelector('[data-act="remove"]')?.addEventListener("click", async () => {
      if (!confirm("Remove this keystore?")) return;
      await chrome.runtime.sendMessage({ type: "removeKeystore", id });
      await renderList();
    });
  });
}

async function move(id, delta) {
  const s = await chrome.runtime.sendMessage({ type: "status" });
  const order = [...s.order];
  const idx = order.indexOf(id);
  if (idx < 0) return;
  const target = idx + delta;
  if (target < 0 || target >= order.length) return;
  [order[idx], order[target]] = [order[target], order[idx]];
  await chrome.runtime.sendMessage({ type: "reorderKeystores", order });
  await renderList();
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

$("btn-import").addEventListener("click", async () => {
  const file = $("file").files[0];
  const label = $("label").value.trim();
  const msg = $("import-msg");
  msg.className = "hint"; msg.textContent = "";

  if (!file) { msg.className = "err"; msg.textContent = "Pick a file."; return; }

  try {
    msg.textContent = "Reading file...";
    const { bundle, manifest } = await fileToBundle(file);
    const displayLabel = label
      || (manifest && manifest.project_name)
      || file.name.replace(/\.(zip|json|mykit|tnpkg)$/i, "")
      || "Keystore";

    // Local-file imports are stored plaintext: the source file is
    // already on the user's disk. Wrapping it in passphrase-encrypted
    // chrome.storage.local would be theatre. Vault-claim bundles
    // (session 6) take a different path that still encrypts.
    const res = await chrome.runtime.sendMessage({
      type: "addLocalFileKeystore",
      label: displayLabel,
      filename: file.name,
      bundle,
    });
    if (!res.ok) throw new Error(res.reason || "save failed");

    const kitCount = (res.loaded && res.loaded.kit_count) || Object.keys(bundle.files || {}).length;
    msg.className = "ok";
    let confirm = `Loaded ${kitCount} key${kitCount === 1 ? "" : "s"} from "${file.name}". Stored as plaintext (already on your disk).`;
    if (manifest && manifest.note) confirm += `  \u2014 sender's note: "${manifest.note}"`;
    msg.textContent = confirm;
    $("file").value = ""; $("label").value = "";
    await renderList();
  } catch (e) {
    msg.className = "err";
    msg.textContent = e.message;
  }
});

$("btn-status").addEventListener("click", async () => {
  const s = await chrome.runtime.sendMessage({ type: "status" });
  $("status-pre").textContent = JSON.stringify(s, null, 2);
});

renderList();
