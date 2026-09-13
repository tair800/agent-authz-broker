import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });

const config = [
  { ignores: [".next/**", "node_modules/**", "next-env.d.ts"] },
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      // The console displays authorization outcomes; it never holds the material that produces
      // them. These globals are the usual first step towards a browser that stores or decodes a
      // token, and `src/test/boundary.test.ts` scans the source for the same thing.
      "no-restricted-globals": [
        "error",
        {
          name: "atob",
          message: "The console never decodes a token. Decisions arrive already made.",
        },
        {
          name: "localStorage",
          message: "Nothing on these screens is worth persisting in a browser.",
        },
        {
          name: "sessionStorage",
          message: "Nothing on these screens is worth persisting in a browser.",
        },
      ],
    },
  },
];

export default config;
