/**
 * Loading, empty and failure.
 *
 * The empty state is the one worth a test. "No data" is a dead end in a lab console; the screen
 * has to print the command that produces data, and this fails if somebody trims it back to a
 * tasteful sentence.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Empty, Failure, Loading } from "@/components/states";

describe("the missing-data states", () => {
  it("tells the reader what to run rather than saying there is no data", () => {
    render(
      <Empty
        title="No decisions have been recorded."
        detail="The audit table is written by the server as it authorizes calls."
        run="uv run pytest -m integration"
      />,
    );

    screen.getByText("No decisions have been recorded.");
    screen.getByText("Run this, then reload:");
    screen.getByText("uv run pytest -m integration");
  });

  it("names the endpoint a failed read was reading, and never the origin", () => {
    render(
      <Failure
        failure={{
          endpoint: "/api/v1/matrix",
          message: "The broker could not be reached.",
          detail: "The operation was aborted due to timeout",
        }}
      />,
    );

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("endpoint: /api/v1/matrix");
    expect(alert).toHaveTextContent("The broker could not be reached.");
    expect(alert.textContent ?? "").not.toContain("http://");
  });

  it("says it will not substitute fixtures for a backend that answered badly", () => {
    render(
      <Failure
        failure={{
          endpoint: "/api/v1/audit?limit=50",
          message: "The broker answered 500.",
          detail: null,
        }}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(/will not quietly substitute them/);
  });

  it("announces loading politely instead of showing a blank page", () => {
    render(<Loading label="Reading the matrix…" />);

    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveTextContent("Reading the matrix…");
  });
});
