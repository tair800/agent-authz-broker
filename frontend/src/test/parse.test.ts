/**
 * Shape validation, applied to the committed fixtures as well as to hypothetical bad payloads.
 *
 * The fixtures are a shipped path — the public demo renders them — so a fixture that drifts out of
 * shape is a production defect and is checked here rather than discovered by a reader.
 */

import { describe, expect, it } from "vitest";

import { ShapeError, parseApprovals, parseAudit, parseChain, parseMatrix } from "@/lib/parse";
import { approvals, audit, chain, matrix } from "@/test/fixtures";

describe("the committed fixtures", () => {
  it("match the shape the console reads", () => {
    expect(matrix.scenarios.length).toBeGreaterThan(0);
    expect(approvals.length).toBeGreaterThan(0);
    expect(audit.length).toBeGreaterThan(0);
  });

  it("carry a chain for every scenario the matrix lists", () => {
    for (const scenario of matrix.scenarios) {
      expect(() => chain(scenario.id)).not.toThrow();
    }
  });

  it("keep the matrix and the chains agreeing about which scopes survived", () => {
    const amplified = chain("scope_amplification");
    expect(amplified.effective_scopes).not.toContain(amplified.required_scope);
    expect(amplified.attenuated_away).toContain(amplified.required_scope);
  });

  it("keep the totals equal to the sum of the per-scenario effect counts", () => {
    const naive = matrix.scenarios.reduce((sum, s) => sum + s.naive.effects, 0);
    const hardened = matrix.scenarios.reduce((sum, s) => sum + s.hardened.effects, 0);
    expect(matrix.totals.naive_effects).toBe(naive);
    expect(matrix.totals.hardened_effects).toBe(hardened);
  });
});

describe("a payload that is not the agreed shape", () => {
  it("is rejected with the path that failed rather than rendered as blanks", () => {
    const broken = {
      generated_at: "now",
      resource_server_url: "https://broker.example/mcp",
      scenarios: [{ id: "x", title: "t", description: "d", naive: {}, hardened: {} }],
      totals: { naive_effects: 0, hardened_effects: 0 },
    };

    expect(() => parseMatrix(broken)).toThrowError(ShapeError);
    expect(() => parseMatrix(broken)).toThrowError(/matrix\.scenarios\[0\]\.naive\.decision/);
  });

  it("refuses a decision that is neither allowed nor denied", () => {
    const [newest] = audit;
    if (newest === undefined) throw new Error("the audit fixture is empty");

    expect(() => parseAudit([{ ...newest, decision: "maybe" }])).toThrowError(
      /expected "allowed" or "denied"/,
    );
  });

  it("refuses a chain whose links are not objects", () => {
    expect(() => parseChain({ ...chain("valid_request"), links: ["alice"] })).toThrowError(
      /chain\.links\[0\]: expected an object/,
    );
  });

  it("accepts an amount as either a string or a number, and changes neither", () => {
    const [first] = approvals;
    if (first === undefined) throw new Error("the approvals fixture is empty");

    expect(parseApprovals([{ ...first, amount: "500.00" }])[0]?.amount).toBe("500.00");
    expect(parseApprovals([{ ...first, amount: 500 }])[0]?.amount).toBe(500);
    expect(() => parseApprovals([{ ...first, amount: null }])).toThrowError(ShapeError);
  });
});
