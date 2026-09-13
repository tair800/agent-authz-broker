/**
 * A consumed approval has to be unmistakable, because consumption is the mechanism that makes
 * replay impossible and a reader who misses it misses the point of the screen.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ApprovalsTable } from "@/components/approvals";
import { approvals } from "@/test/fixtures";

function approvalRow(id: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`tr[data-approval="${id}"]`);
  if (found === null) throw new Error(`no row for approval "${id}"`);
  return found;
}

describe("the approvals table", () => {
  it("marks a spent approval as spent, with the timestamp and what it means", () => {
    render(<ApprovalsTable approvals={approvals} />);

    const spent = approvalRow("apr-4f2a9c1e");
    expect(spent).toHaveAttribute("data-spent", "true");
    expect(spent).toHaveAttribute("data-state", "consumed");
    within(spent).getByText("Spent. This row cannot authorise a second effect.");
    within(spent).getByText("2026-09-13T09:30:04Z");
  });

  it("distinguishes not-yet-consumed from consumed rather than leaving the cell blank", () => {
    render(<ApprovalsTable approvals={approvals} />);

    const pending = approvalRow("apr-8b31d5a7");
    expect(pending).toHaveAttribute("data-spent", "false");
    within(pending).getByText("not consumed");
    expect(within(pending).queryByText(/cannot authorise a second effect/)).toBeNull();
  });

  it("shows every binding an approval is tied to", () => {
    render(<ApprovalsTable approvals={approvals} />);

    const row = approvalRow("apr-8b31d5a7");
    within(row).getByText("alice");
    within(row).getByText(/issue_credit/);
    within(row).getByText(/ACC-2/);
    within(row).getByText(/1200/);
    within(row).getByText("2026-09-13T18:45:00Z");
  });

  it("renders an expired approval without calling it consumed", () => {
    render(<ApprovalsTable approvals={approvals} />);

    const expired = approvalRow("apr-1c07e6b2");
    expect(expired).toHaveAttribute("data-state", "expired");
    expect(expired).toHaveAttribute("data-spent", "false");
  });

  it("renders one row per approval", () => {
    render(<ApprovalsTable approvals={approvals} />);

    expect(screen.getAllByRole("row")).toHaveLength(approvals.length + 1);
  });
});
