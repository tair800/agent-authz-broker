/**
 * The decision trail, newest first, with each decision shown as the walk it actually was.
 *
 * A refusal reason on its own tells you the answer; it does not tell you how far the request got.
 * Every row therefore renders the four checks in order — token, audience, scope chain, approval —
 * with the one that refused marked, the ones after it marked as never reached, and the ones a
 * policy does not perform marked as not checked rather than as passed.
 *
 * That last distinction is the whole comparison. The naive baseline does not pass the audience
 * check; it does not have one. The effect is deliberately not a stage: it is not something that
 * was checked, it is what was left over, and it has its own column.
 */

import type { AuditEntry } from "@/lib/types";
import { REASON_BLURB } from "@/lib/types";

const STAGES = ["token", "audience", "scope", "approval"] as const;
type Stage = (typeof STAGES)[number];

/** Which stage each refusal comes from. Mirrors `DenialReason` in `domain.py`. */
const STAGE_OF_REASON: Readonly<Record<string, Stage>> = {
  signature_invalid: "token",
  issuer_unknown: "token",
  token_expired: "token",
  token_malformed: "token",
  unknown_tool: "token",
  audience_mismatch: "audience",
  delegation_malformed: "scope",
  insufficient_effective_scope: "scope",
  approval_required: "approval",
  approval_expired: "approval",
  approval_already_consumed: "approval",
};

/**
 * The stages each policy actually performs.
 *
 * **The approval stage is performed under both.** Approval is a layer below the two policies, not
 * part of either, so the only stage the naive baseline skips is `audience` — and `scope`, which it
 * does perform, it performs on the leaf's claim rather than on the attenuated set.
 *
 * This map said `["token", "scope"]` for the naive baseline, copied from ADR-001's *prediction*
 * that the naive verifier would also fail the no-approval scenario. The measurement retracted that
 * prediction, and nothing here changed, because the hand-written audit fixture happened to contain
 * no naive row that was refused at the approval stage. When the fixture was replaced by the
 * measurement, four such rows appeared at once — each rendering `approval` as *this verifier does
 * not perform this check* directly beside the outcome `denied · approval_required`.
 *
 * A policy this console has not been told about gets every stage rendered neutrally rather than
 * guessed at; inventing a claim about an unknown verifier is the one thing this screen must not do.
 */
const PERFORMED: Readonly<Record<string, ReadonlySet<Stage>>> = {
  hardened: new Set(STAGES),
  naive: new Set<Stage>(["token", "scope", "approval"]),
};

type Mark = "passed" | "refused" | "unreached" | "unchecked" | "unknown";

const MARK_TONE: Readonly<Record<Mark, string>> = {
  passed: "border-held/40 bg-held-bg text-held",
  refused: "border-breach/50 bg-breach-bg text-breach",
  unreached: "border-edge bg-panel text-ink-faint",
  unchecked: "border-attenuated/40 bg-attenuated-bg text-attenuated",
  unknown: "border-edge bg-panel-raised text-ink-dim",
};

const MARK_TITLE: Readonly<Record<Mark, string>> = {
  passed: "checked, and it passed",
  refused: "this is where the request was refused",
  unreached: "never reached — an earlier stage refused",
  unchecked: "this verifier does not perform this check",
  unknown: "this console does not know what this verifier checks",
};

function marks(entry: AuditEntry): ReadonlyArray<{ stage: Stage; mark: Mark }> {
  const performed = PERFORMED[entry.policy];
  const stopStage = entry.reason === null ? null : STAGE_OF_REASON[entry.reason];
  const stopAt = stopStage === undefined ? -1 : stopStage === null ? null : STAGES.indexOf(stopStage);

  return STAGES.map((stage, index) => {
    if (performed === undefined) return { stage, mark: "unknown" as Mark };
    if (!performed.has(stage)) return { stage, mark: "unchecked" as Mark };
    if (stopAt === null) return { stage, mark: "passed" as Mark };
    if (stopAt === -1) return { stage, mark: "unknown" as Mark };
    if (index < stopAt) return { stage, mark: "passed" as Mark };
    if (index === stopAt) return { stage, mark: "refused" as Mark };
    return { stage, mark: "unreached" as Mark };
  });
}

function Trail({ entry }: { entry: AuditEntry }) {
  return (
    <ol className="flex flex-wrap items-center gap-1">
      {marks(entry).map(({ stage, mark }, index) => (
        <li key={stage} className="flex items-center gap-1">
          {index > 0 ? (
            <span aria-hidden className="text-ink-faint">
              ›
            </span>
          ) : null}
          <span
            data-stage={stage}
            data-mark={mark}
            title={MARK_TITLE[mark]}
            className={`tabular rounded border px-1.5 py-0.5 ${MARK_TONE[mark]}`}
          >
            {stage}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function AuditTrail({ entries }: { entries: readonly AuditEntry[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-edge bg-panel">
      <table className="w-full min-w-[64rem] border-collapse text-left">
        <caption className="sr-only">
          Every authorization decision this server recorded, newest first.
        </caption>
        <thead>
          <tr className="border-b border-edge text-ink-faint">
            <th scope="col" className="px-3 py-2 font-medium">
              When
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Caller
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Policy
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Trail
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Outcome
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Effect
            </th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr
              key={entry.audit_id}
              data-audit={entry.audit_id}
              data-policy={entry.policy}
              data-decision={entry.decision}
              className="border-b border-edge/70 align-top last:border-0"
            >
              <td className="tabular px-3 py-3 text-ink-dim">
                <div>{entry.at}</div>
                <div className="text-ink-faint">{entry.audit_id}</div>
              </td>
              <td className="tabular px-3 py-3">
                <div className="text-ink">{entry.subject}</div>
                <div className="text-ink-faint">{entry.tool}</div>
              </td>
              <td className="tabular px-3 py-3 text-ink-dim">{entry.policy}</td>
              <td className="px-3 py-3">
                <Trail entry={entry} />
                <div className="tabular mt-2 text-ink-faint">
                  effective [{entry.effective_scopes.join(", ") || "—"}] · needs{" "}
                  {entry.required_scope}
                </div>
              </td>
              <td className="px-3 py-3">
                <div className="tabular font-semibold text-ink">{entry.decision}</div>
                {entry.reason ? (
                  <>
                    <div className="tabular mt-1 text-breach">{entry.reason}</div>
                    {REASON_BLURB[entry.reason] ? (
                      <div className="mt-1 max-w-xs text-ink-faint">
                        {REASON_BLURB[entry.reason]}
                      </div>
                    ) : null}
                  </>
                ) : (
                  <div className="mt-1 text-ink-faint">no refusal</div>
                )}
              </td>
              <td className="px-3 py-3">
                {entry.effect_id ? (
                  <span className="tabular rounded border border-breach/50 bg-breach-bg px-1.5 py-0.5 text-breach">
                    {entry.effect_id}
                  </span>
                ) : (
                  <span className="text-ink-faint">none</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
