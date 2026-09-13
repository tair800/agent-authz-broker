/**
 * The boundary this console is obliged to keep, checked by reading its own source.
 *
 * Three claims are made in `.env.example`, in `next.config.ts` and in `src/lib/server/source.ts`,
 * and a claim about a security boundary that nothing enforces decays into a comment that used to
 * be true:
 *
 *   1. the broker's address is server-side only — `process.env` read in exactly one module, no
 *      `NEXT_PUBLIC_` variable read anywhere, no `env` block in `next.config.ts`;
 *   2. no component reaches the network itself, because nothing in this app runs in the browser
 *      beyond hydrating static markup;
 *   3. nothing here holds or displays a credential.
 *
 * A scan is a blunt instrument and it is honest about that: it proves the strings are absent, not
 * that the design is correct. It is still the check that catches the accidental reintroduction,
 * which is how this kind of thing actually regresses.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

/**
 * Taken from the working directory, not from `import.meta.url`: the test runner serves modules
 * over a non-file URL and `fileURLToPath` refuses those. Asserted rather than assumed, because a
 * scanner pointed at the wrong directory finds nothing and passes, which is the worst possible
 * outcome for a guard.
 */
const FRONTEND = process.cwd();

if (!existsSync(join(FRONTEND, "package.json"))) {
  throw new Error(`the boundary guards expect to run from frontend/, not ${FRONTEND}`);
}

const SRC = join(FRONTEND, "src");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) ? [path] : [];
  });
}

const APP_FILES = sources(SRC).filter((path) => !path.includes(join("src", "test")));

function read(path: string): string {
  return readFileSync(path, "utf8");
}

function relative(path: string): string {
  return path.slice(FRONTEND.length + 1).replace(/\\/g, "/");
}

/**
 * The predicates, named once so the guards and their positive controls run the same code.
 *
 * `readsEnvironment` looks for `process.env` rather than for the variable's name. Naming the
 * variable in prose is something this console is *supposed* to do — the failure state and the
 * provenance band both tell an operator what to set — so a guard that forbade the string would
 * push the app towards saying less than it should. What must stay rare is the *read*.
 */
const readsEnvironment = (source: string): boolean => /process\.env/.test(source);
const readsPublicVariable = (source: string): boolean => /process\.env\.NEXT_PUBLIC_/.test(source);
const isClientComponent = (source: string): boolean => /^\s*["']use client["']/m.test(source);
const mentionsCredential = (source: string): boolean =>
  /bearer|authorization:|private[_ -]?key|signing[_ -]?key|jwks|\bjwt\b/i.test(source);

function offenders(predicate: (source: string) => boolean): string[] {
  return APP_FILES.filter((path) => predicate(read(path))).map(relative);
}

describe("the scan itself", () => {
  it("is looking at the app and not at an empty directory", () => {
    expect(APP_FILES.length).toBeGreaterThan(10);
    expect(APP_FILES.map(relative)).toContain("src/lib/server/source.ts");
    expect(APP_FILES.map(relative)).toContain("src/components/matrix.tsx");
  });

  it("rejects the things it claims to reject", () => {
    // A guard nobody has watched refuse anything is a comment. These are the shapes it exists
    // to catch, fed to the same predicates the real assertions use.
    expect(readsEnvironment("const base = process.env.BROKER_API_BASE_URL;")).toBe(true);
    expect(readsEnvironment("// mentions BROKER_API_BASE_URL in prose only")).toBe(false);
    expect(readsPublicVariable("process.env.NEXT_PUBLIC_API")).toBe(true);
    expect(isClientComponent('"use client";\nexport const x = 1;')).toBe(true);
    expect(isClientComponent("// a comment about use client\n")).toBe(false);
    expect(mentionsCredential('headers: { Authorization: "Bearer " + t }')).toBe(true);
    expect(mentionsCredential("const privateKey = load();")).toBe(true);
    expect(mentionsCredential("an approval is a durable row")).toBe(false);
  });
});

describe("the server-side boundary", () => {
  it("reads the environment in exactly one module", () => {
    expect(offenders(readsEnvironment)).toEqual(["src/lib/server/source.ts"]);
  });

  it("reads no NEXT_PUBLIC_ variable, and declares no env block in next.config.ts", () => {
    expect(offenders(readsPublicVariable)).toEqual([]);
    expect(read(join(FRONTEND, "next.config.ts"))).not.toMatch(/\benv\s*:/);
  });

  it("names only BROKER_API_BASE_URL in .env.example", () => {
    const example = read(join(FRONTEND, ".env.example"));
    const declared = Array.from(example.matchAll(/^#? ?([A-Z][A-Z0-9_]*)=/gm));
    expect(declared.map((match) => match[1])).toEqual(["BROKER_API_BASE_URL"]);
  });
});

describe("the client boundary", () => {
  it("has no client components, so nothing fetches from the browser", () => {
    expect(offenders(isClientComponent)).toEqual([]);
  });

  it("keeps components out of the server module", () => {
    const reaching = APP_FILES.filter(
      (path) => path.includes(join("src", "components")) && read(path).includes("lib/server"),
    );
    expect(reaching.map(relative)).toEqual([]);
  });
});

describe("credentials", () => {
  it("never mentions a bearer token, a signing key or a private key", () => {
    expect(offenders(mentionsCredential)).toEqual([]);
  });
});
