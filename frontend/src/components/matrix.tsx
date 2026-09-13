/**
 * The security matrix. One row per scenario, one column per verifier, and the effect counts.
 *
 * The layout exists to make one comparison unmissable: on five of these six rows the naive
 * baseline says *allowed* and the hardened server says *denied*, and the difference is money that
 * moved. The naive column is therefore tinted as a breach exactly when it diverges — allowed is
 * not coloured as success anywhere on this screen, because here it usually is not one.
 */

import Link from "next/link";

import { Scope } from "@/components/primitives";
import type { Matrix, Scenario, ScenarioOutcome } from "@/lib/types";
import { REASON_BLURB } from "@/lib/types";

function letThrough(scenario: Scenario): boolean {
  return scenario.naive.decision === "allowed" && scenario.hardened.decision === "denied";
}

function Outcome({ outcome, tone }: { outcome: ScenarioOutcome; tone: "breach" | "held" | "flat" }) {
  const classes =
    tone === "breach"
      ? "border-breach/40 bg-breach-bg"
      : tone === "held"
        ? "border-held/40 bg-held-bg"
        : "border-edge bg-panel-raised";
  const word =
    tone === "breach" ? "text-breach" : tone === "held" ? "text-held" : "text-ink-dim";

  return (
    <div className={`h-full rounded border px-3 py-2 ${classes}`}>
      <p className={`font-semibold ${word}`}>{outcome.decision}</p>
      {outcome.reason ? (
        <>
          <p className="tabular mt-1 text-ink-dim">{outcome.reason}</p>
          {REASON_BLURB[outcome.reason] ? (
            <p className="mt-1 text-ink-faint">{REASON_BLURB[outcome.reason]}</p>
          ) : null}
        </>
      ) : (
        <p className="mt-1 text-ink-faint">no refusal</p>
      )}
    </div>
  );
}

function Effects({ scenario }: { scenario: Scenario }) {
  const worse = scenario.naive.effects > scenario.hardened.effects;
  return (
    <dl className="tabular space-y-1">
      <div className="flex items-baseline justify-between gap-3">
        <dt className="text-ink-faint">naive</dt>
        <dd className={worse ? "font-semibold text-breach" : "text-ink-dim"}>
          {scenario.naive.effects}
        </dd>
      </div>
      <div className="flex items-baseline justify-between gap-3">
        <dt className="text-ink-faint">hardened</dt>
        <dd className="font-semibold text-ink">{scenario.hardened.effects}</dd>
      </div>
    </dl>
  );
}

export function SecurityMatrix({ matrix }: { matrix: Matrix }) {
  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded-md border border-edge bg-panel">
        <table className="w-full min-w-[56rem] border-collapse text-left">
          <caption className="sr-only">
            Each scenario, the decision each verifier reached, and the irreversible effects each one
            permitted.
          </caption>
          <thead>
            <tr className="border-b border-edge text-ink-faint">
              <th scope="col" className="px-3 py-2 font-medium">
                Scenario
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                Naive baseline
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                Hardened
              </th>
              <th scope="col" className="w-40 px-3 py-2 font-medium">
                Irreversible effects
              </th>
            </tr>
          </thead>
          <tbody>
            {matrix.scenarios.map((scenario) => {
              const diverged = letThrough(scenario);
              return (
                <tr
                  key={scenario.id}
                  data-scenario={scenario.id}
                  data-naive-decision={scenario.naive.decision}
                  data-hardened-decision={scenario.hardened.decision}
                  data-let-through={diverged ? "true" : "false"}
                  className="border-b border-edge/70 align-top last:border-0"
                >
                  <th scope="row" className="max-w-md px-3 py-3 font-normal">
                    <Link href={`/chain?scenario=${scenario.id}`} className="hover:text-ink">
                      <span className="tabular text-ink-faint">{scenario.id}</span>
                      <span className="mt-0.5 block font-medium text-ink">{scenario.title}</span>
                    </Link>
                    <p className="mt-1 text-ink-dim">{scenario.description}</p>
                  </th>
                  <td className="px-3 py-3">
                    <Outcome outcome={scenario.naive} tone={diverged ? "breach" : "flat"} />
                  </td>
                  <td className="px-3 py-3">
                    <Outcome outcome={scenario.hardened} tone={diverged ? "held" : "flat"} />
                  </td>
                  <td className="px-3 py-3">
                    <Effects scenario={scenario} />
                  </td>
                </tr>
              );
            })}
          </tbody>
          <tfoot>
            <tr className="border-t border-edge bg-panel-raised">
              <th scope="row" className="px-3 py-3 text-left font-medium text-ink">
                Across {matrix.scenarios.length} scenarios
              </th>
              <td className="tabular px-3 py-3 text-breach" data-total="naive">
                {matrix.totals.naive_effects} irreversible effects
              </td>
              <td className="tabular px-3 py-3 text-held" data-total="hardened">
                {matrix.totals.hardened_effects} irreversible effects
              </td>
              <td className="px-3 py-3 text-ink-faint">
                every count is a row in <span className="tabular">irreversible_effect</span>
              </td>
            </tr>
          </tfoot>
        </table>
      </div>

      <p className="text-ink-dim">
        The one effect the hardened server permitted is the{" "}
        <span className="tabular">valid_request</span> row, which required{" "}
        <Scope name="credit:issue" tone="required" /> to survive the whole delegation chain and a
        matching, unexpired, unconsumed approval to exist in the server&rsquo;s own database.
      </p>
    </div>
  );
}
