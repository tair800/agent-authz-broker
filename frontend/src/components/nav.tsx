import Link from "next/link";

const SCREENS: ReadonlyArray<{ href: string; label: string; note: string }> = [
  { href: "/", label: "Matrix", note: "what each verifier let through" },
  { href: "/chain", label: "Delegation", note: "where authority was lost" },
  { href: "/approvals", label: "Approvals", note: "what a human actually agreed to" },
  { href: "/audit", label: "Audit", note: "the decision trail" },
];

/**
 * Four links, no active highlight.
 *
 * Marking the current screen needs `usePathname`, which would make this the app's only client
 * component and put a hydration boundary in a console that otherwise has none. Each screen leads
 * with its own heading, so the cost of leaving it out is close to nothing.
 */
export function Nav() {
  return (
    <header className="border-b border-edge bg-panel">
      <div className="mx-auto flex max-w-7xl flex-wrap items-baseline gap-x-6 gap-y-2 px-4 py-3">
        <span className="tabular text-ink-faint">agent-authz-broker</span>
        <nav className="flex flex-wrap items-baseline gap-x-5 gap-y-1">
          {SCREENS.map((screen) => (
            <Link
              key={screen.href}
              href={screen.href}
              className="text-ink-dim hover:text-ink"
              title={screen.note}
            >
              {screen.label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  );
}
