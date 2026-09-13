/**
 * The handful of shapes every screen is built from.
 *
 * `Scope` is the important one. Scopes are short, similar-looking strings that this whole project
 * turns on, so they are always monospaced, always chips, and always tinted by what happened to
 * them — claimed, survived, required, or attenuated away — rather than being left as plain text
 * for the reader to diff by eye.
 */

import type { DataSource } from "@/lib/types";

export type ScopeTone = "claimed" | "effective" | "required" | "attenuated";

const SCOPE_TONE: Readonly<Record<ScopeTone, string>> = {
  claimed: "border-edge bg-panel-raised text-ink-dim",
  effective: "border-held/50 bg-held-bg text-held",
  required: "border-required/50 bg-required-bg text-required",
  attenuated: "border-attenuated/60 bg-attenuated-bg text-attenuated line-through",
};

export function Scope({ name, tone = "claimed" }: { name: string; tone?: ScopeTone }) {
  return (
    <span
      data-scope={name}
      data-tone={tone}
      className={`tabular inline-block rounded border px-1.5 py-0.5 ${SCOPE_TONE[tone]}`}
    >
      {name}
    </span>
  );
}

/**
 * A set of scopes, with any member of `highlight` shown in a different tone.
 *
 * @param empty What to print when the set is empty — "none" and "nothing was removed" are not the
 *   same statement and the caller knows which it means.
 */
export function ScopeSet({
  scopes,
  tone = "claimed",
  highlight = [],
  highlightTone = "attenuated",
  empty = "none",
}: {
  scopes: readonly string[];
  tone?: ScopeTone;
  highlight?: readonly string[];
  highlightTone?: ScopeTone;
  empty?: string;
}) {
  if (scopes.length === 0) {
    return <span className="text-ink-faint">{empty}</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {scopes.map((scope) => (
        <Scope
          key={scope}
          name={scope}
          tone={highlight.includes(scope) ? highlightTone : tone}
        />
      ))}
    </span>
  );
}

export function Panel({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-md border border-edge bg-panel ${className}`}>{children}</section>
  );
}

export function Screen({
  title,
  lead,
  children,
}: {
  title: string;
  lead: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        <div className="mt-2 max-w-3xl text-ink-dim">{lead}</div>
      </div>
      {children}
    </div>
  );
}

/**
 * Where the numbers on this screen came from, stated before they are read.
 *
 * The fixtures reproduce the matrix ADR-001 predeclared; the live backend recomputes it from real
 * signed tokens and reads its effect counts out of PostgreSQL. Those are different kinds of claim
 * and a reader who cannot tell which one they are looking at has been misled by omission.
 */
export function SourceBand({ source, generatedAt }: { source: DataSource; generatedAt?: string }) {
  if (source === "fixtures") {
    return (
      <p
        data-source="fixtures"
        className="rounded-md border border-attenuated/40 bg-attenuated-bg px-3 py-2 text-attenuated"
      >
        <span className="font-semibold">A committed measurement, not a live broker.</span>{" "}
        <span className="text-ink-dim">
          <span className="tabular">BROKER_API_BASE_URL</span> is unset, so this console renders the
          matrix committed at <span className="tabular">artifacts/matrix.json</span> — written by{" "}
          <span className="tabular">python -m agent_authz_broker.demo</span>, which runs every
          scenario under both policies against real PostgreSQL and counts{" "}
          <span className="tabular">irreversible_effect</span> rows from a clean database each time.
          Every number here was measured; none was typed. Attached to a running broker, these same
          screens show that database live.
        </span>
      </p>
    );
  }
  return (
    <p
      data-source="live"
      className="rounded-md border border-edge bg-panel px-3 py-2 text-ink-dim"
    >
      <span className="font-semibold text-ink">Live from the broker.</span> Effect counts are{" "}
      <span className="tabular">select count(*) from irreversible_effect</span>, not a verifier&rsquo;s
      report about itself.
      {generatedAt ? <span className="tabular text-ink-faint"> · generated {generatedAt}</span> : null}
    </p>
  );
}
