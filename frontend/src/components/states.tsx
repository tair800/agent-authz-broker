/**
 * Loading, empty and failure, as three components every fetching screen owes.
 *
 * The empty state takes a `run` string rather than a message, because "no data" is the least useful
 * thing a lab console can say. An empty audit table means the suite has not been run against this
 * database yet, and the screen should print the command instead of making the reader go and find
 * out.
 */

import type { ApiFailure } from "@/lib/types";

export function Loading({ label }: { label: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-3 rounded-md border border-edge bg-panel px-4 py-6 text-ink-dim"
    >
      <span aria-hidden className="h-2.5 w-2.5 animate-pulse rounded-full bg-required" />
      <span>{label}</span>
    </div>
  );
}

/**
 * Nothing to show, and what to do about it.
 *
 * @param title What is empty, in the reader's terms.
 * @param detail Why it can legitimately be empty.
 * @param run The command that fills it. Shown verbatim, because a half-remembered command is a
 *   dead end.
 */
export function Empty({ title, detail, run }: { title: string; detail: string; run: string }) {
  return (
    <div className="rounded-md border border-dashed border-edge bg-panel px-4 py-8">
      <p className="font-medium text-ink">{title}</p>
      <p className="mt-1 max-w-prose text-ink-dim">{detail}</p>
      <p className="mt-3 text-ink-faint">Run this, then reload:</p>
      <pre className="tabular mt-1 overflow-x-auto rounded border border-edge bg-surface px-3 py-2 text-ink">
        <code>{run}</code>
      </pre>
    </div>
  );
}

/** A read that did not produce data. Named by the path it was reading, never by the origin. */
export function Failure({ failure }: { failure: ApiFailure }) {
  return (
    <div role="alert" className="rounded-md border border-breach/40 bg-breach-bg px-4 py-4">
      <p className="font-semibold text-breach">This screen has no data to show</p>
      <p className="mt-1 max-w-prose text-ink-dim">{failure.message}</p>
      {failure.detail ? <p className="mt-2 max-w-prose text-ink-faint">{failure.detail}</p> : null}
      <p className="tabular mt-3 text-ink-faint">endpoint: {failure.endpoint}</p>
      <p className="mt-3 max-w-prose text-ink-dim">
        Unset <span className="tabular">BROKER_API_BASE_URL</span> to read the committed fixtures
        instead. This console will not quietly substitute them for a backend that answered badly.
      </p>
    </div>
  );
}
