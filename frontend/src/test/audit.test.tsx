/**
 * The audit screen renders how far each request got. The distinction worth protecting is between
 * a check that passed and a check that was never performed, because collapsing the two would hand
 * the naive baseline credit for an audience check it does not have.
 *
 * Rows are selected by what they are — a hardened audience refusal, a naive decision that produced
 * an effect — and never by id. The trail is written by the measurement run, so the ids change every
 * time; asserting on them would test the last run rather than the component.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AuditTrail } from "@/components/audit";
import { audit, auditWhere } from "@/test/fixtures";

function entry(auditId: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`tr[data-audit="${auditId}"]`);
  if (found === null) throw new Error(`no audit row "${auditId}"`);
  return found;
}

function mark(row: HTMLElement, stage: string): string | null {
  return row.querySelector(`[data-stage="${stage}"]`)?.getAttribute("data-mark") ?? null;
}

describe("the decision trail", () => {
  it("shows the hardened refusal at the stage that refused, and nothing after it", () => {
    const refusal = auditWhere(
      "a hardened refusal for audience_mismatch",
      (e) => e.policy === "hardened" && e.reason === "audience_mismatch",
    );
    render(<AuditTrail entries={audit} />);

    const row = entry(refusal.audit_id);
    expect(row).toHaveAttribute("data-policy", "hardened");
    expect(mark(row, "token")).toBe("passed");
    expect(mark(row, "audience")).toBe("refused");
    expect(mark(row, "scope")).toBe("unreached");
    expect(mark(row, "approval")).toBe("unreached");
  });

  it("marks the naive baseline's audience stage as not checked rather than as passed", () => {
    const naive = auditWhere("decided by the naive baseline", (e) => e.policy === "naive");
    render(<AuditTrail entries={audit} />);

    const row = entry(naive.audit_id);
    expect(row).toHaveAttribute("data-policy", "naive");
    expect(mark(row, "audience")).toBe("unchecked");
    expect(mark(row, "token")).toBe("passed");
  });

  it("does not call the approval stage unperformed on a row the approval stage refused", () => {
    // The naive baseline lacks an audience check; it does not lack the approval layer, which sits
    // below both policies. Rendering `approval` as "this verifier does not perform this check"
    // beside the outcome `approval_required` is a claim the audit row itself disproves.
    const refused = auditWhere(
      "a naive decision refused at the approval stage",
      (e) => e.policy === "naive" && e.reason === "approval_required",
    );
    render(<AuditTrail entries={audit} />);

    expect(mark(entry(refused.audit_id), "approval")).toBe("refused");
  });

  it("names the irreversible effect a decision produced, and says none when it produced none", () => {
    const caused = auditWhere("a decision that caused an effect", (e) => e.effect_id !== null);
    const refused = auditWhere("a decision that caused none", (e) => e.effect_id === null);
    render(<AuditTrail entries={audit} />);

    expect(entry(caused.audit_id)).toHaveTextContent(caused.effect_id as string);
    expect(entry(refused.audit_id)).toHaveTextContent("none");
  });

  it("keeps the newest decision first, in the order the broker returned", () => {
    render(<AuditTrail entries={audit} />);

    const ids = Array.from(document.querySelectorAll("tr[data-audit]")).map((r) =>
      r.getAttribute("data-audit"),
    );
    expect(ids).toEqual(audit.map((e) => e.audit_id));
  });

  it("is served newest-first, so preserving the order is the right thing to preserve", () => {
    const times = audit.map((e) => Date.parse(e.at));
    expect(times.every((t) => Number.isFinite(t))).toBe(true);
    expect([...times].sort((a, b) => b - a)).toEqual(times);
  });

  it("renders one row per decision", () => {
    render(<AuditTrail entries={audit} />);

    expect(screen.getAllByRole("row")).toHaveLength(audit.length + 1);
  });

  it("covers both policies, which is the comparison the screen exists to show", () => {
    expect(new Set(audit.map((e) => e.policy))).toEqual(new Set(["naive", "hardened"]));
  });
});
