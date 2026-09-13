/**
 * The matrix screen's one job: make the divergence between the two verifiers unmissable.
 *
 * These assert the rendering, not the security property — the security property is proved in
 * `tests/test_kill_criteria.py` against PostgreSQL. What can go wrong *here* is a console that
 * quietly renders both columns the same, and that is what is checked.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SecurityMatrix } from "@/components/matrix";
import { matrix } from "@/test/fixtures";

function row(scenarioId: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`tr[data-scenario="${scenarioId}"]`);
  if (found === null) throw new Error(`no row for scenario "${scenarioId}"`);
  return found;
}

describe("the security matrix", () => {
  it("shows the naive baseline allowing a token minted for another resource server", () => {
    render(<SecurityMatrix matrix={matrix} />);

    const wrongAudience = row("wrong_audience");
    expect(wrongAudience).toHaveAttribute("data-naive-decision", "allowed");
    expect(wrongAudience).toHaveAttribute("data-hardened-decision", "denied");
    expect(wrongAudience).toHaveAttribute("data-let-through", "true");

    within(wrongAudience).getByText("audience_mismatch");
    expect(within(wrongAudience).queryAllByText("allowed")).toHaveLength(1);
  });

  it("counts the irreversible effects each verifier permitted on the diverging row", () => {
    render(<SecurityMatrix matrix={matrix} />);

    const wrongAudience = row("wrong_audience");
    const naiveEffects = within(wrongAudience).getByText("naive").nextElementSibling;
    const hardenedEffects = within(wrongAudience).getByText("hardened").nextElementSibling;

    expect(naiveEffects).toHaveTextContent("1");
    expect(hardenedEffects).toHaveTextContent("0");
  });

  it("does not mark the correctly authorised row as a breach", () => {
    render(<SecurityMatrix matrix={matrix} />);

    const valid = row("valid_request");
    expect(valid).toHaveAttribute("data-naive-decision", "allowed");
    expect(valid).toHaveAttribute("data-hardened-decision", "allowed");
    expect(valid).toHaveAttribute("data-let-through", "false");
  });

  it("publishes the totals so the comparison is one number against another", () => {
    render(<SecurityMatrix matrix={matrix} />);

    expect(document.querySelector('[data-total="naive"]')).toHaveTextContent(
      `${matrix.totals.naive_effects} irreversible effects`,
    );
    expect(document.querySelector('[data-total="hardened"]')).toHaveTextContent(
      `${matrix.totals.hardened_effects} irreversible effects`,
    );
    expect(matrix.totals.naive_effects).toBeGreaterThan(matrix.totals.hardened_effects);
  });

  it("links each scenario to its delegation chain", () => {
    render(<SecurityMatrix matrix={matrix} />);

    const link = within(row("scope_amplification")).getByRole("link");
    expect(link).toHaveAttribute("href", "/chain?scenario=scope_amplification");
  });

  it("renders every scenario the payload carries", () => {
    render(<SecurityMatrix matrix={matrix} />);

    expect(screen.getAllByRole("row")).toHaveLength(matrix.scenarios.length + 2);
  });
});
