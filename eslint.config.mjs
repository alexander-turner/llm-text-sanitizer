import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Lint only the library sources; the template's automation scripts
  // (.github, .hooks, config) carry their own conventions.
  {
    ignores: [
      "coverage/**",
      "types/**",
      "node_modules/**",
      ".github/**",
      ".claude/**",
      ".hooks/**",
      "config/**",
      "tests/**",
      // Stryker copies the project into a sandbox here during a mutation run and
      // mutates the sources in place; never lint that transient mutated copy.
      ".stryker-tmp/**",
      "reports/**",
    ],
  },
  js.configs.recommended,
  {
    files: ["src/**/*.mjs", "test/**/*.mjs", "scripts/**/*.mjs"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      "consistent-return": "error",
    },
  },
);
