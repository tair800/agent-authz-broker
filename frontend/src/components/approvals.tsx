/**
 * Approvals, and above all which of them have been spent.
 *
 * Every column here is one of the bindings ADR-001 fixed, and each exists because without it an
 * approval authorises something nobody agreed to: without `subject` it authorises another
 * principal, without `account` another target, without `amount` another size, without `expires_at`
 * it is good forever, and without `consumed_at` it is good repeatedly.
 *
 * `consumed_at` therefore gets its own tone and its own sentence. It is the field that makes replay
 * impossible, and a reader who skims this table should come away knowing that consumption is a row
 * in a database and not a flag in a request.
 */

import type { Approval } from "@/lib/types";

const STATE_TONE: Readonly<Record<string, string>> = {
  pending: "border-required/50 bg-required-bg text-required",
  consumed: "border-spent/60 bg-spent-bg text-spent",
  expired: "border-edge bg-panel-raised text-ink-faint",
};

function StateBadge({ state }: { state: string }) {
  const tone = STATE_TONE[state] ?? "border-edge bg-panel-raised text-ink-dim";
  return (
    <span className={`tabular inline-block rounded border px-1.5 py-0.5 ${tone}`}>{state}</span>
  );
}

export function ApprovalsTable({ approvals }: { approvals: readonly Approval[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-edge bg-panel">
      <table className="w-full min-w-[52rem] border-collapse text-left">
        <caption className="sr-only">
          Human approvals on file, what each is bound to, and whether it has been spent.
        </caption>
        <thead>
          <tr className="border-b border-edge text-ink-faint">
            <th scope="col" className="px-3 py-2 font-medium">
              Approval
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Bound to
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Expires
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              Consumed
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              State
            </th>
          </tr>
        </thead>
        <tbody>
          {approvals.map((approval) => {
            const spent = approval.consumed_at !== null;
            return (
              <tr
                key={approval.approval_id}
                data-approval={approval.approval_id}
                data-state={approval.state}
                data-spent={spent ? "true" : "false"}
                className={`border-b border-edge/70 align-top last:border-0 ${
                  spent ? "bg-spent-bg/30" : ""
                }`}
              >
                <th scope="row" className="tabular px-3 py-3 text-left font-normal text-ink">
                  {approval.approval_id}
                </th>
                <td className="tabular px-3 py-3 text-ink-dim">
                  <div className="text-ink">{approval.subject}</div>
                  <div>
                    {approval.tool} · {approval.account} · {approval.amount}
                  </div>
                </td>
                <td className="tabular px-3 py-3 text-ink-dim">{approval.expires_at}</td>
                <td className="px-3 py-3">
                  {spent ? (
                    <div className="text-spent">
                      <div className="tabular">{approval.consumed_at}</div>
                      <div className="mt-1">
                        Spent. This row cannot authorise a second effect.
                      </div>
                    </div>
                  ) : (
                    <span className="text-ink-faint">not consumed</span>
                  )}
                </td>
                <td className="px-3 py-3">
                  <StateBadge state={approval.state} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
