/**
 * A consumed approval has to be unmistakable, because consumption is the mechanism that makes
 * replay impossible and a reader who misses it misses the point of the screen.
 *
 * Approvals are selected by lifecycle state rather than by id. The measurement run produces all
 * three states — the valid and replay scenarios spend one, the audience and delegation scenarios
 * leave one pending, and one is minted already expired — so asking for a state is stable across
 * runs in a way that asking for an id is not.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ApprovalsTable } from "@/components/approvals";
import { approvalIn, approvals } from "@/test/fixtures";

function approvalRow(id: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`tr[data-approval="${id}"]`);
  if (found === null) throw new Error(`no row for approval "${id}"`);
  return found;
}

describe("the approvals table", () => {
  it("marks a spent approval as spent, with the timestamp and what it means", () => {
    const consumed = approvalIn("consumed");
    render(<ApprovalsTable approvals={approvals} />);

    const spent = approvalRow(consumed.approval_id);
    expect(spent).toHaveAttribute("data-spent", "true");
    expect(spent).toHaveAttribute("data-state", "consumed");
    within(spent).getByText("Spent. This row cannot authorise a second effect.");
    within(spent).getByText(consumed.consumed_at as string);
  });

  it("distinguishes not-yet-consumed from consumed rather than leaving the cell blank", () => {
    const pending = approvalIn("pending");
    render(<ApprovalsTable approvals={approvals} />);

    const row = approvalRow(pending.approval_id);
    expect(row).toHaveAttribute("data-spent", "false");
    within(row).getByText("not consumed");
    expect(within(row).queryByText(/cannot authorise a second effect/)).toBeNull();
  });

  it("shows every binding an approval is tied to", () => {
    const pending = approvalIn("pending");
    render(<ApprovalsTable approvals={approvals} />);

    const row = approvalRow(pending.approval_id);
    within(row).getByText(pending.subject);
    within(row).getByText(new RegExp(pending.tool));
    within(row).getByText(new RegExp(pending.account));
    within(row).getByText(new RegExp(String(pending.amount)));
    within(row).getByText(pending.expires_at);
  });

  it("renders an expired approval without calling it consumed", () => {
    const stale = approvalIn("expired");
    render(<ApprovalsTable approvals={approvals} />);

    const expired = approvalRow(stale.approval_id);
    expect(expired).toHaveAttribute("data-state", "expired");
    expect(expired).toHaveAttribute("data-spent", "false");
  });

  it("renders one row per approval", () => {
    render(<ApprovalsTable approvals={approvals} />);

    expect(screen.getAllByRole("row")).toHaveLength(approvals.length + 1);
  });

  it("carries all three lifecycle states, so the screen is never a single-state table", () => {
    expect(new Set(approvals.map((a) => a.state))).toEqual(
      new Set(["pending", "consumed", "expired"]),
    );
  });
});
