/**
 * The attenuation view. The thing that must survive a refactor is that a reader can see *which*
 * link lost the scope, not merely that a scope is missing from a total at the bottom.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DelegationChain, ScenarioPicker } from "@/components/chain";
import { chain, matrix } from "@/test/fixtures";

function hop(subject: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`li[data-subject="${subject}"]`);
  if (found === null) throw new Error(`no chain link for "${subject}"`);
  return found;
}

function scopeChips(within_: HTMLElement, tone: string): string[] {
  return Array.from(within_.querySelectorAll(`[data-tone="${tone}"]`)).map(
    (el) => el.getAttribute("data-scope") ?? "",
  );
}

describe("the delegation view", () => {
  it("shows the scope the leaf claimed and the chain removed", () => {
    render(<DelegationChain chain={chain("scope_amplification")} />);

    const attenuated = document.querySelector<HTMLElement>('[data-field="attenuated"]');
    expect(attenuated).not.toBeNull();
    expect(scopeChips(attenuated as HTMLElement, "attenuated")).toEqual(["credit:issue"]);

    const effective = document.querySelector<HTMLElement>('[data-field="effective"]');
    expect(scopeChips(effective as HTMLElement, "effective")).toEqual([
      "account:read",
      "account:flag",
    ]);
    expect(scopeChips(effective as HTMLElement, "effective")).not.toContain("credit:issue");
  });

  it("marks the link where the authority was lost, and only that link", () => {
    render(<DelegationChain chain={chain("scope_amplification")} />);

    expect(hop("alice")).toHaveAttribute("data-lost", "credit:issue");
    within(hop("alice")).getByText("authority lost here");

    expect(hop("agent-7")).toHaveAttribute("data-lost", "");
    expect(within(hop("agent-7")).queryByText("authority lost here")).toBeNull();
  });

  it("states the consequence rather than leaving the reader to infer it", () => {
    render(<DelegationChain chain={chain("scope_amplification")} />);

    const verdict = document.querySelector('[data-verdict="insufficient"]');
    expect(verdict).not.toBeNull();
    expect(verdict).toHaveTextContent("insufficient_effective_scope");
  });

  it("says nothing was removed when the chain took nothing away", () => {
    render(<DelegationChain chain={chain("valid_request")} />);

    screen.getByText("nothing was removed");
    expect(document.querySelector('[data-verdict="survived"]')).not.toBeNull();
    expect(document.querySelector("li[data-lost]:not([data-lost=''])")).toBeNull();
  });

  it("names a single-link token as having no delegation instead of drawing a chain", () => {
    render(<DelegationChain chain={chain("no_approval")} />);

    screen.getByText(/No delegation\./);
  });

  it("marks the selected scenario in the picker", () => {
    render(
      <ScenarioPicker scenarios={matrix.scenarios} selected="scope_amplification" />,
    );

    expect(screen.getByRole("link", { name: "scope_amplification" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(screen.getByRole("link", { name: "wrong_audience" })).not.toHaveAttribute(
      "aria-current",
    );
  });
});
