import js from "@eslint/js";
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      "eslint.config.js",
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,
  security.configs.recommended,

  {
    // Project-wide rule tuning. This is a fresh lint setup for a large,
    // pre-existing codebase -- rules that are high-value but would
    // otherwise produce a wall of pre-existing findings are downgraded
    // to "warn" so the lint step is immediately useful (and blocking on
    // genuine new problems) without requiring a separate mass-cleanup
    // change first. Tighten these over time.
    rules: {
      // `any` is used pervasively for DB row mapping and third-party
      // boundaries today; flag it for visibility without blocking CI.
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-empty-object-type": "warn",
      "no-empty": ["error", { allowEmptyCatch: true }],

      // eslint-plugin-security rules are heuristic and prone to false
      // positives (e.g. any dynamic property/path access trips
      // detect-object-injection / detect-non-literal-fs-filename), but
      // this codebase does real shell exec, dynamic file I/O, and
      // self-modification -- exactly what these rules exist to flag.
      // Keep them as warnings so real risk is visible for review
      // without making every dynamic access a hard CI failure.
      "security/detect-object-injection": "warn",
      "security/detect-non-literal-fs-filename": "warn",
      "security/detect-non-literal-regexp": "warn",
    },
  },

  {
    files: ["src/__tests__/**/*.ts", "packages/*/src/**/__tests__/**/*.ts"],
    rules: {
      // Test code intentionally does things like dynamic fs paths in
      // temp directories, non-literal regexes built from fixtures, and
      // `any` for mock/test scaffolding -- none of this is the class of
      // risk eslint-plugin-security targets in production code paths.
      "@typescript-eslint/no-explicit-any": "off",
      "security/detect-object-injection": "off",
      "security/detect-non-literal-fs-filename": "off",
      "security/detect-non-literal-regexp": "off",
    },
  },
);
