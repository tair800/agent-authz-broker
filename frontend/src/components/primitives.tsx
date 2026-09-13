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
 * This band once said *"every number here was measured; none was typed"* on all four screens while
 * only one of the four was measured — the matrix. The audit, approvals and chain screens were
 * hand-written fixtures, and they still carried a prediction the matrix run had already retracted.
 * A banner that is true on one screen and false on three is worse than no banner: it spends the
 * reader's trust on the screens that least deserve it.
 *
 * It is true on all four now, and that is a fact about the build rather than about this wording:
 * `python -m agent_authz_broker.demo` writes `matrix.json`, `audit.json`, `approvals.json` and
 * `chains.json` from one run, and `scripts/copy-artifacts.mjs` copies all four. There is no screen
 * left whose numbers a person could edit.
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
          <span className="tabular">BROKER_API_BASE_URL</span> is unset, so all four screens render
          the artifacts committed under <span className="tabular">artifacts/</span> — written by one
          run of <span className="tabular">python -m agent_authz_broker.demo</span> against real
          PostgreSQL. It executes every scenario under both policies, counts{" "}
          <span className="tabular">irreversible_effect</span> rows from a clean database each time,
          and exports the <span className="tabular">audit_event</span> rows it wrote, the approvals
          it left behind, and each delegation chain decoded from the token that was actually
          presented. Every number here was measured; none was typed. Attached to a running broker,
          these same screens show that database live.
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
