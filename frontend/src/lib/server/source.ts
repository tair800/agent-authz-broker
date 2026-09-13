/**
 * The only module that knows where the broker is. Server-side, and it stays there.
 *
 * `BROKER_API_BASE_URL` is read here and nowhere else. It is not prefixed `NEXT_PUBLIC_`, it is not
 * in `next.config.ts`'s `env`, and its value is never put into anything rendered: a failure names
 * the *path* it was reading, never the origin. The browser talks only to this app's own origin, so
 * the broker needs no CORS entry for the console to work.
 *
 * When the variable is unset the console reads the committed fixtures instead. That is not a
 * degraded mode bolted on for tests — it is the deployed demo's normal path, so it is a first-class
 * branch here and every screen states which of the two it is showing.
 *
 * A live read that fails does **not** fall back to fixtures. Quietly substituting invented numbers
 * for a backend that is down would make this console lie about the one thing it exists to report.
 *
 * The boundary is enforced by two facts a test checks rather than by the `server-only` package:
 * no file in this app carries a `"use client"` directive, and `BROKER_API_BASE_URL` is named in
 * this file and nowhere else. See `src/test/boundary.test.ts`.
 */

import auditFixture from "@fixtures/audit.json";
import approvalsFixture from "@fixtures/approvals.json";
import chainsFixture from "@fixtures/chains.json";
import matrixFixture from "@fixtures/matrix.json";

import { ShapeError, parseApprovals, parseAudit, parseChain, parseMatrix } from "@/lib/parse";
import type { Approval, AuditEntry, Chain, DataSource, Fetched, Matrix } from "@/lib/types";

const REQUEST_TIMEOUT_MS = 5_000;

function baseUrl(): string | null {
  const raw = process.env.BROKER_API_BASE_URL?.trim();
  if (!raw) return null;
  return raw.replace(/\/+$/, "");
}

/** Which of the two paths a screen is on, resolvable without performing a read. */
export function dataSource(): DataSource {
  return baseUrl() === null ? "fixtures" : "live";
}

function failed<T>(endpoint: string, message: string, detail: string | null = null): Fetched<T> {
  return { ok: false, failure: { endpoint, message, detail } };
}

/** What a redacted origin is replaced by, so a reader can see that something was removed. */
const REDACTED = "<the configured broker address>";

/**
 * Is this a base URL `fetch` can actually use?
 *
 * Checked before the request rather than after it, because the failure Node raises for a malformed
 * base is `Failed to parse URL from <base><path>` — it quotes the address back. Catching the
 * mistake here lets the screen name the variable and say what shape it wants without ever putting
 * its value on the page.
 */
function isAbsoluteHttpUrl(candidate: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return false;
  }
  return parsed.protocol === "http:" || parsed.protocol === "https:";
}

/**
 * An error's message, with the configured origin removed.
 *
 * The origin is stripped here, at the single point where an error becomes something a screen can
 * render, rather than at each call site. Several of these messages are written by `fetch` and not
 * by this module, so the set of strings that might contain the address is not one this file can
 * enumerate — redacting centrally is what makes "a failure never names the origin" a property of
 * the code instead of a claim about the failures anyone happened to try.
 */
function reason(error: unknown): string | null {
  if (!(error instanceof Error)) return null;
  return redactOrigin(error.message);
}

function redactOrigin(message: string): string {
  const raw = process.env.BROKER_API_BASE_URL?.trim();
  if (!raw) return message;
  // Both spellings: `fetch` is handed the normalised base, but the raw value is what an operator
  // set and may differ from it by a trailing slash.
  return [raw.replace(/\/+$/, ""), raw]
    .filter((candidate) => candidate.length > 0)
    .reduce((text, candidate) => text.split(candidate).join(REDACTED), message);
}

/**
 * Read one endpoint, or the fixture that stands in for it.
 *
 * @param path The API path, which is also what a failure is reported against. Never the origin.
 * @param fixture The committed stand-in, used when no base URL is configured.
 * @param parse Shape validation, applied to both paths so a bad fixture fails as loudly as a bad
 *   response rather than rendering as blanks.
 */
async function read<T>(
  path: string,
  fixture: unknown,
  parse: (raw: unknown) => T,
): Promise<Fetched<T>> {
  const base = baseUrl();

  if (base === null) {
    try {
      return { ok: true, data: parse(fixture), source: "fixtures" };
    } catch (error) {
      return failed(
        path,
        "A committed fixture does not match the shape this console reads.",
        reason(error),
      );
    }
  }

  if (!isAbsoluteHttpUrl(base)) {
    return failed(
      path,
      "BROKER_API_BASE_URL is not an absolute http(s) URL.",
      "Set it to an origin such as http://127.0.0.1:8000 — scheme included, no path, no trailing " +
        "slash. Its value is deliberately not shown here.",
    );
  }

  let body: unknown;
  try {
    const response = await fetch(`${base}${path}`, {
      cache: "no-store",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      return failed(
        path,
        `The broker answered ${response.status}.`,
        response.status === 404
          ? "That path is not served. The console and the broker may be different versions."
          : null,
      );
    }
    body = await response.json();
  } catch (error) {
    return failed(path, "The broker could not be reached.", reason(error));
  }

  // Every failure becomes a value rather than a throw. No screen in this console can raise, which
  // is why there is no `error.tsx` and therefore no client component anywhere in the app.
  try {
    return { ok: true, data: parse(body), source: "live" };
  } catch (error) {
    const message =
      error instanceof ShapeError
        ? "The broker answered with a shape this console does not recognise."
        : "The broker's answer could not be read.";
    return failed(path, message, reason(error));
  }
}

export function fetchMatrix(): Promise<Fetched<Matrix>> {
  return read("/api/v1/matrix", matrixFixture, parseMatrix);
}

/**
 * One scenario's delegation chain.
 *
 * The fixture store is keyed by scenario id because the API serves one chain per id; an id with no
 * fixture is reported as a miss rather than rendered as an empty chain, since "no links" and "no
 * such scenario" mean very different things on that screen.
 */
export function fetchChain(scenarioId: string): Promise<Fetched<Chain>> {
  const fixtures: Record<string, unknown> = chainsFixture;
  const fixture = fixtures[scenarioId];
  const path = `/api/v1/chain/${encodeURIComponent(scenarioId)}`;
  if (dataSource() === "fixtures" && fixture === undefined) {
    return Promise.resolve(
      failed(path, `No chain is recorded for the scenario "${scenarioId}".`, null),
    );
  }
  return read(path, fixture, parseChain);
}

export function fetchApprovals(): Promise<Fetched<Approval[]>> {
  return read("/api/v1/approvals", approvalsFixture, parseApprovals);
}

export function fetchAudit(limit = 50): Promise<Fetched<AuditEntry[]>> {
  return read(`/api/v1/audit?limit=${limit}`, auditFixture, parseAudit);
}
