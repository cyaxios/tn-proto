# tn-proto browser bundle (CDN-ready)

`tn-proto.browser.mjs` is a single, **self-contained** ES module of the tn-proto
SDK's browser surface. The Rust/wasm core is inlined (base64) into the file, so
there is **no separate `.wasm` to serve or pair** — drop this one file on any
static host / CDN, or `import` it directly from a URL.

## Use it

It is served from Cloudflare at a stable URL — import it straight from there:

```html
<script type="module">
  import * as tn from "https://tn-proto.org/cdn/tn-proto.browser.mjs";
  const t = await tn.Tn.init();   // wasm inits inside init(); no separate step
  // ... use the SDK
</script>
```

Runnable, in-browser docs against that exact bundle live at
<https://tn-proto.org/docs/browser/>.

Alternatively, served straight from this repo via jsDelivr (works when the
repo/tag is public):

```
https://cdn.jsdelivr.net/gh/cyaxios/tn-proto@<tag>/cdn/tn-proto.browser.mjs
```

## Regenerate

This file is built from `ts-sdk/dist/browser.mjs`. After any SDK change, refresh
it with:

```
cd ts-sdk && npm run build:cdn
```

which builds the browser bundle and copies it here. Keep it in lockstep with the
published npm version (`@cyaxios/tn-proto`).
