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
);
