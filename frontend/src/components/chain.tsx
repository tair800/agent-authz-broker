/**
 * The delegation view: root to leaf, and where in that walk authority stopped existing.
 *
 * The rule being rendered is one line — `effective = leaf ∩ act[0] ∩ … ∩ root` — and the screen's
 * job is to make a reader believe it by showing the arithmetic rather than asserting the result.
 * So each link prints what that principal *held*, a link that lacks an attenuated scope is marked
 * as the place the scope died, and the intersection is shown as a conclusion drawn underneath
 * instead of as a number that arrives from nowhere.
 */

import Link from "next/link";

import { Panel, Scope, ScopeSet } from "@/components/primitives";
import type { Chain, ChainLink } from "@/lib/types";

function RoleBadge({ role }: { role: string }) {
  return (
    <span className="tabular rounded border border-edge bg-panel-raised px-1.5 py-0.5 text-ink-faint">
      {role}
    </span>
  );
}

function Hop({
  link,
  lost,
  effective,
}: {
  link: ChainLink;
  /** Attenuated scopes this principal never held. Non-empty means authority died here. */
  lost: readonly string[];
  effective: readonly string[];
}) {
  return (
    <li
      data-subject={link.subject}
      data-lost={lost.join(" ")}
      className={`rounded-md border px-3 py-3 ${
        lost.length > 0 ? "border-attenuated/60 bg-attenuated-bg/40" : "border-edge bg-panel-raised"
      }`}
    >
      <div className="flex flex-wrap items-baseline gap-2">
        <RoleBadge role={link.role} />
        <span className="tabular font-medium text-ink">{link.subject}</span>
      </div>

      <div className="mt-2 flex flex-wrap items-baseline gap-2">
        <span className="w-14 shrink-0 text-ink-faint">holds</span>
        <ScopeSet
          scopes={link.scopes}
          tone="claimed"
          highlight={effective}
          highlightTone="effective"
          empty="no scopes"
        />
      </div>

      {lost.length > 0 ? (
        <div className="mt-2 flex flex-wrap items-baseline gap-2">
          <span className="w-14 shrink-0 text-ink-faint">lacks</span>
          <ScopeSet scopes={lost} tone="attenuated" />
          <span className="text-attenuated">authority lost here</span>
        </div>
      ) : null}
    </li>
  );
}

export function DelegationChain({ chain }: { chain: Chain }) {
  const survived = chain.effective_scopes.includes(chain.required_scope);
  const direct = chain.links.length === 1;

  return (
    <div className="space-y-4">
      {direct ? (
        <p className="text-ink-dim">
          No delegation. This token was issued directly to its subject, so the chain is one link and
          the intersection is that link&rsquo;s own scopes. The attenuation rule still runs; it just
          has nothing to take away.
        </p>
      ) : null}

      <ol className="space-y-2">
        {chain.links.map((link, index) => (
          <Hop
            key={`${link.subject}-${index}`}
            link={link}
            lost={chain.attenuated_away.filter((scope) => !link.scopes.includes(scope))}
            effective={chain.effective_scopes}
          />
        ))}
      </ol>

      <Panel className="p-4">
        <dl className="space-y-3">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <dt className="w-40 shrink-0 text-ink-faint">effective (intersected)</dt>
            <dd data-field="effective">
              <ScopeSet scopes={chain.effective_scopes} tone="effective" empty="nothing survived" />
            </dd>
          </div>
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <dt className="w-40 shrink-0 text-ink-faint">required by the tool</dt>
            <dd data-field="required">
              <Scope name={chain.required_scope} tone="required" />
            </dd>
          </div>
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <dt className="w-40 shrink-0 text-ink-faint">attenuated away</dt>
            <dd data-field="attenuated">
              <ScopeSet
                scopes={chain.attenuated_away}
                tone="attenuated"
                empty="nothing was removed"
              />
            </dd>
          </div>
        </dl>

        <p
          data-verdict={survived ? "survived" : "insufficient"}
          className={`mt-4 border-t border-edge pt-3 ${
            survived ? "text-ink-dim" : "text-attenuated"
          }`}
        >
          {survived ? (
            <>
              Authority survived the chain. If this scenario is refused, it is refused further on —
              at the audience check or at the approval check — and not here.
            </>
          ) : (
            <>
              <span className="tabular">{chain.required_scope}</span> is not in the effective set,
              so the call is refused with{" "}
              <span className="tabular">insufficient_effective_scope</span>. The leaf claimed it;
              no amount of claiming puts back a scope an ancestor never had.
            </>
          )}
        </p>
      </Panel>
    </div>
  );
}

/** The scenario picker. Plain links, so the screen stays a server component and stays bookmarkable. */
export function ScenarioPicker({
  scenarios,
  selected,
}: {
  scenarios: ReadonlyArray<{ id: string; title: string }>;
  selected: string;
}) {
  return (
    <nav aria-label="Scenario" className="flex flex-wrap gap-2">
      {scenarios.map((scenario) => {
        const active = scenario.id === selected;
        return (
          <Link
            key={scenario.id}
            href={`/chain?scenario=${scenario.id}`}
            aria-current={active ? "page" : undefined}
            title={scenario.title}
            className={`tabular rounded border px-2 py-1 ${
              active
                ? "border-required/60 bg-required-bg text-required"
                : "border-edge bg-panel text-ink-dim hover:text-ink"
            }`}
          >
            {scenario.id}
          </Link>
        );
      })}
    </nav>
  );
}
