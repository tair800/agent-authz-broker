/**
 * The committed fixtures, parsed the same way the server module parses them.
 *
 * Tests read them through `parse*` rather than casting the JSON, so a fixture that drifts out of
 * shape fails here as well as on screen. The fixtures are a shipped path — the public demo renders
 * them — so they deserve the same validation as a response from the broker.
 *
 * **Select rows with the helpers below, never by literal id.** These files are now written by
 * `python -m agent_authz_broker.demo`, so every id is minted fresh on each run. A test that says
 * `apr-4f2a9c1e` is pinned to one measurement and fails on the next — and when the fixtures were
 * hand-written, that pinning is what made re-measuring them feel expensive enough to skip.
 */

import auditFixture from "@fixtures/audit.json";
import approvalsFixture from "@fixtures/approvals.json";
import chainsFixture from "@fixtures/chains.json";
import matrixFixture from "@fixtures/matrix.json";

import { parseApprovals, parseAudit, parseChain, parseMatrix } from "@/lib/parse";
import type { Approval, AuditEntry, Chain } from "@/lib/types";

export const matrix = parseMatrix(matrixFixture);
export const approvals = parseApprovals(approvalsFixture);
export const audit = parseAudit(auditFixture);

const chains: Record<string, unknown> = chainsFixture;

export function chain(scenarioId: string): Chain {
  const raw = chains[scenarioId];
  if (raw === undefined) throw new Error(`no chain fixture for "${scenarioId}"`);
  return parseChain(raw);
}

/** The first audit row matching a predicate, or a failure naming what was looked for. */
export function auditWhere(
  what: string,
  match: (entry: AuditEntry) => boolean,
): AuditEntry {
  const found = audit.find(match);
  if (found === undefined) throw new Error(`no audit row that is ${what}`);
  return found;
}

/** The first approval in a given lifecycle state. All three states occur in every run. */
export function approvalIn(state: string): Approval {
  const found = approvals.find((a) => a.state === state);
  if (found === undefined) throw new Error(`no approval in state "${state}"`);
  return found;
}
