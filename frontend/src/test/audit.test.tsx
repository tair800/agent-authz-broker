/**
 * The audit screen renders how far each request got. The distinction worth protecting is between
 * a check that passed and a check that was never performed, because collapsing the two would hand
 * the naive baseline credit for an audience check it does not have.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AuditTrail } from "@/components/audit";
import { audit } from "@/test/fixtures";

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
    render(<AuditTrail entries={audit} />);

    const row = entry("aud-00000004");
    expect(row).toHaveAttribute("data-policy", "hardened");
    expect(mark(row, "token")).toBe("passed");
    expect(mark(row, "audience")).toBe("refused");
    expect(mark(row, "scope")).toBe("unreached");
    expect(mark(row, "approval")).toBe("unreached");
  });

  it("marks the naive baseline's audience stage as not checked rather than as passed", () => {
    render(<AuditTrail entries={audit} />);

    const row = entry("aud-00000003");
    expect(row).toHaveAttribute("data-policy", "naive");
    expect(mark(row, "audience")).toBe("unchecked");
    expect(mark(row, "approval")).toBe("unchecked");
    expect(mark(row, "token")).toBe("passed");
  });

  it("names the irreversible effect a decision produced, and says none when it produced none", () => {
    render(<AuditTrail entries={audit} />);

    expect(entry("aud-00000003")).toHaveTextContent("eff-52c8ba61");
    expect(entry("aud-00000004")).toHaveTextContent("none");
  });

  it("keeps the newest decision first, in the order the broker returned", () => {
    render(<AuditTrail entries={audit} />);

    const ids = Array.from(document.querySelectorAll("tr[data-audit]")).map((r) =>
      r.getAttribute("data-audit"),
    );
    expect(ids).toEqual(audit.map((e) => e.audit_id));
    expect(ids[0]).toBe("aud-0000000c");
  });

  it("renders one row per decision", () => {
    render(<AuditTrail entries={audit} />);

    expect(screen.getAllByRole("row")).toHaveLength(audit.length + 1);
  });
});
