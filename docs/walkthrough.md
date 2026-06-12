# Walkthrough - `tn-proto` README Documentation Draft

We have created a comprehensive, inviting, and professional documentation draft for `tn-proto`'s upcoming release. To keep your active builds clean, this draft has been placed inside the artifact directory as [README_DRAFT.md](file:///C:/Users/gilsa/.gemini/antigravity/brain/93eab176-b069-4b16-b079-9e9772a78060/README_DRAFT.md).

Here is a summary of the accomplishments and key elements designed for this documentation:

---

## 🌟 Key Highlights of the Draft

### 1. Title & Modern Visual Anchors
* **Shield Badges:** Includes custom status shields for Python compatibility (explicitly highlighting support for Python **3.10 to 3.14**), TypeScript (Node/Browser/WASM), release version (`v0.6.0a1`), and the security model (non-custodial vault).
* **Clear Value Proposition:** A concise, bold elevator pitch highlighting signed, encrypted, append-only logs with identical wire formats across Python, JS, and Rust.

### 2. Streamlined Installation & Quickstarts
* Standardized installation examples using regular registries (`pip install tn-proto` and `npm install tn-proto`).
* Clean, non-complex quickstarts in both **Python** and **TypeScript** showcasing initialization, encrypted logging, and decrypted reading.

### 3. Log Sharing & Cryptographic Groups (New Section)
* Explains the access control model in an easy-to-understand way, demonstrating how users distribute **Reader Kits** tied to reader public **DIDs** (`did:key:z6Mk...`).
* Outlines how the log remains signed and verified for authenticity without exposing master keys, and how log access can be instantly revoked without re-encrypting history or disturbing other readers.

### 4. Non-Custodial Vault Backups (`vault.tn-proto.org`)
* Clear explanation of the backup boundary:
  * **What gets backed up:** Configurations and group keys.
  * **What remains local:** Application logs are strictly local and **never** synced to the vault.
  * **Security & Recovery:** Non-custodial model. Users can restore everything from a mnemonic/passphrase if local keys are lost.

### 5. File Layout Transparency (Default Locations)
* Simplified directory structure layout under `.tn/` showing the locations of configuration files, keys, and event logs.

### 6. AI Coding Agents (`tn-skills`)
* Covers the `tn-skills` plugin, which teaches an AI coding agent to route PII into the right group, avoid logging secrets, and cite the matching regulation when writing TN logs.

---

## 🛠️ Verification Done
* Verified all Markdown syntax, formatting headers, code block highlights, and structural layout tags are clean.
* Verified absolute paths to code snippets match the APIs exposed in `docs/guide/getting-started.md`.
* **Verified Live PyPI Installation (`v0.6.0a2`):**
  * Created an isolated virtual environment under `c:\codex\tn\_tmp_install_test`.
  * Installed `tn-proto==0.6.0a2` from the live PyPI index.
  * Executed `test_install.py`, which successfully imported `tn`, initialized a project, logged a test event (`test.event`), read back the decrypted entry (`{'release': '0.6.0a2', 'status': 'success'}`), and confirmed the creation of both the config (`tn.yaml`) and log files (`default.ndjson`).
* **Drafted the Wealth-Advisor Demo README (`DEMO_README_DRAFT.md`):**
  * Documented the core scenario and the Quasar/NiceGUI dashboard.
  * Detailed the three cryptographic Vantages (Advisor, Copilot Agent, and Compliance Officer).
  * Outlined how compile-time governance context is bound to records and flows across boundaries.
  * Created a step-by-step breakdown of the governance loop (Tool Request -> Governance Unseal -> Policy Decision -> Allowed Projection Constraint -> LLM Execution -> Signed Receipt).
  * Provided simple setup and launch instructions for the NiceGUI demo.
