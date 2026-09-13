/**
 * The server-side reader, checked on the paths that only misconfiguration reaches.
 *
 * `source.ts` makes three promises that a rendered page would break loudly if they were wrong, and
 * that nothing else in the suite exercises: a failed live read never falls back to the fixtures, a
 * failure names the path and never the origin, and an unusable base URL is reported as a named
 * configuration error rather than as whatever string `fetch` happened to throw.
 *
 * The origin case is the one worth a test rather than a comment. `fetch` reports a malformed base
 * as `Failed to parse URL from <base><path>`, so the guarantee "a failure never names the origin"
 * was false for every base URL that does not parse — a class of failure a smoke test against a
 * dead port never reaches, because a *reachable-looking* address fails with "fetch failed" and
 * quotes nothing back.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchMatrix } from "@/lib/server/source";

const VARIABLE = "BROKER_API_BASE_URL";

function setBase(value: string | undefined): void {
  if (value === undefined) delete process.env[VARIABLE];
  else process.env[VARIABLE] = value;
}

afterEach(() => {
  setBase(undefined);
  vi.unstubAllGlobals();
});

/** Everything a failure puts on the page, as one string to search. */
function rendered(failure: { endpoint: string; message: string; detail: string | null }): string {
  return [failure.endpoint, failure.message, failure.detail ?? ""].join(" ");
}

describe("the fixtures path", () => {
  it("reads the committed fixtures when no base URL is set", async () => {
    setBase(undefined);
    const result = await fetchMatrix();

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.source).toBe("fixtures");
  });
});

describe("a live read that fails", () => {
  it("does not quietly fall back to the fixtures", async () => {
    setBase("http://127.0.0.1:59999");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("fetch failed")),
    );

    const result = await fetchMatrix();

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.message).toBe("The broker could not be reached.");
    expect(result.failure.endpoint).toBe("/api/v1/matrix");
  });

  it("redacts the origin out of an error message that quotes it back", async () => {
    const base = "http://broker.internal:8000";
    setBase(base);
    // The shape Node raises when the address is unusable in a way the pre-flight check cannot see.
    // Written as a message rather than asserted from a real socket so the case is deterministic.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError(`Failed to parse URL from ${base}/api/v1/matrix`)),
    );

    const result = await fetchMatrix();

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(rendered(result.failure)).not.toContain("broker.internal");
    // Positive control: the redaction ran and replaced something, rather than the assertion above
    // passing because the message was empty.
    expect(result.failure.detail).toContain("<the configured broker address>");
  });

  it("redacts an origin the operator wrote with a trailing slash", async () => {
    setBase("https://broker.internal/");
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockRejectedValue(new TypeError("connect ECONNREFUSED https://broker.internal/api/v1")),
    );

    const result = await fetchMatrix();

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(rendered(result.failure)).not.toContain("broker.internal");
  });
});

describe("an unusable base URL", () => {
  it.each(["notaurl", "ht!tp://x", "broker.internal:8000", "ftp://broker.internal"])(
    "is named as a configuration error without echoing %j",
    async (value) => {
      setBase(value);
      const attempt = vi.fn();
      vi.stubGlobal("fetch", attempt);

      const result = await fetchMatrix();

      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.failure.message).toContain(VARIABLE);
      expect(rendered(result.failure)).not.toContain(value);
      // No request is attempted against an address that cannot be parsed.
      expect(attempt).not.toHaveBeenCalled();
    },
  );
});
