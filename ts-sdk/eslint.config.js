// Flat-config ESLint. Mirrors the Rust workspace's strict-by-default posture:
// CI runs `eslint --max-warnings=0`, so any new warning blocks the PR.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "test/fixtures/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        URL: "readonly",
        TextEncoder: "readonly",
        TextDecoder: "readonly",
      },
    },
    rules: {
      // Unused-but-intentional identifiers prefix with `_`.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // `any` is acceptable at boundaries (tn-wasm FFI, Python interop),
      // but should be the exception, not the rule. Warn is too weak; we
      // require explicit opt-in via comment.
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  {
    files: ["src/core/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["node:*"],
              message: "Layer 1 (src/core/) is browser-safe — no node:* imports.",
            },
          ],
          paths: [
            { name: "fs", message: "Use Layer 2 for filesystem I/O." },
            { name: "path", message: "Use Layer 2 for filesystem I/O." },
            { name: "os", message: "Use Layer 2 for OS-specific code." },
            { name: "child_process", message: "Layer 1 must not spawn processes." },
            { name: "crypto", message: "Use the wasm RNG or globalThis.crypto." },
            { name: "zlib", message: "Use a wasm-backed compressor in Layer 1, or move to Layer 2." },
          ],
        },
      ],
    },
  },
);
