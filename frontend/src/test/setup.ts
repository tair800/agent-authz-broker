import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { createElement, type AnchorHTMLAttributes, type ReactNode } from "react";
import { afterEach, vi } from "vitest";

/**
 * `next/link` wants the App Router mounted, which a component test does not have. A plain anchor
 * keeps the `href` assertable, and the matrix rows link to the chain screen by scenario id — a
 * contract between two screens that is worth being able to check.
 */
vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    ...rest
  }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string; children: ReactNode }) =>
    createElement("a", { href, ...rest }, children),
}));

afterEach(() => {
  cleanup();
});
