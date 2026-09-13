/**
 * The committed fixtures, parsed the same way the server module parses them.
 *
 * Tests read them through `parse*` rather than casting the JSON, so a fixture that drifts out of
 * shape fails here as well as on screen. The fixtures are a shipped path — the public demo renders
 * them — so they deserve the same validation as a response from the broker.
 */

import auditFixture from "@fixtures/audit.json";
import approvalsFixture from "@fixtures/approvals.json";
import chainsFixture from "@fixtures/chains.json";
import matrixFixture from "@fixtures/matrix.json";

import { parseApprovals, parseAudit, parseChain, parseMatrix } from "@/lib/parse";
import type { Chain } from "@/lib/types";

export const matrix = parseMatrix(matrixFixture);
export const approvals = parseApprovals(approvalsFixture);
export const audit = parseAudit(auditFixture);

const chains: Record<string, unknown> = chainsFixture;

export function chain(scenarioId: string): Chain {
  const raw = chains[scenarioId];
  if (raw === undefined) throw new Error(`no chain fixture for "${scenarioId}"`);
  return parseChain(raw);
}
