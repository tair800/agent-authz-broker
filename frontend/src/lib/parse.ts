/**
 * Shape validation for everything this console reads, including its own fixtures.
 *
 * The broker's whole argument is that a server should not take a caller's word for the structure
 * of what it was handed. It would be an odd console that then trusted a JSON body because of where
 * it came from, so the same discipline applies in the other direction: a payload that is not the
 * agreed shape becomes a named failure on screen rather than an `undefined` rendered as blank.
 *
 * Shape only. The vocabularies — refusal reasons, policy names, approval states — are deliberately
 * not policed here; see the note in `types.ts`.
 */

import type {
  Approval,
  AuditEntry,
  Chain,
  ChainLink,
  Decision,
  Matrix,
  Scenario,
  ScenarioOutcome,
} from "@/lib/types";

/** A payload that did not match the agreed shape, carrying the path that failed. */
export class ShapeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShapeError";
  }
}

function record(value: unknown, at: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ShapeError(`${at}: expected an object, got ${describe(value)}`);
  }
  return value as Record<string, unknown>;
}

function list(value: unknown, at: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new ShapeError(`${at}: expected an array, got ${describe(value)}`);
  }
  return value;
}

function text(value: unknown, at: string): string {
  if (typeof value !== "string") {
    throw new ShapeError(`${at}: expected a string, got ${describe(value)}`);
  }
  return value;
}

function textOrNull(value: unknown, at: string): string | null {
  return value === null || value === undefined ? null : text(value, at);
}

function count(value: unknown, at: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ShapeError(`${at}: expected a number, got ${describe(value)}`);
  }
  return value;
}

function textList(value: unknown, at: string): string[] {
  return list(value, at).map((item, i) => text(item, `${at}[${i}]`));
}

function decision(value: unknown, at: string): Decision {
  const raw = text(value, at);
  if (raw !== "allowed" && raw !== "denied") {
    throw new ShapeError(`${at}: expected "allowed" or "denied", got ${JSON.stringify(raw)}`);
  }
  return raw;
}

/**
 * An amount is passed through untouched.
 *
 * Whether the broker sends `500` or `"500.00"` is its decision to make, and re-deriving a monetary
 * value in a browser is how two systems come to disagree about one. The only transformation is
 * serialization for display.
 */
function amount(value: unknown, at: string): string | number {
  if (typeof value === "string" || typeof value === "number") return value;
  throw new ShapeError(`${at}: expected a string or a number, got ${describe(value)}`);
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return typeof value;
}

function parseOutcome(raw: unknown, at: string): ScenarioOutcome {
  const o = record(raw, at);
  return {
    decision: decision(o.decision, `${at}.decision`),
    reason: textOrNull(o.reason, `${at}.reason`),
    effects: count(o.effects, `${at}.effects`),
  };
}

function parseScenario(raw: unknown, at: string): Scenario {
  const s = record(raw, at);
  return {
    id: text(s.id, `${at}.id`),
    title: text(s.title, `${at}.title`),
    description: text(s.description, `${at}.description`),
    expected_effects: count(s.expected_effects, `${at}.expected_effects`),
    naive: parseOutcome(s.naive, `${at}.naive`),
    hardened: parseOutcome(s.hardened, `${at}.hardened`),
  };
}

export function parseMatrix(raw: unknown): Matrix {
  const m = record(raw, "matrix");
  const totals = record(m.totals, "matrix.totals");
  return {
    generated_at: text(m.generated_at, "matrix.generated_at"),
    resource_server_url: text(m.resource_server_url, "matrix.resource_server_url"),
    scenarios: list(m.scenarios, "matrix.scenarios").map((s, i) =>
      parseScenario(s, `matrix.scenarios[${i}]`),
    ),
    totals: {
      naive_effects: count(totals.naive_effects, "matrix.totals.naive_effects"),
      hardened_effects: count(totals.hardened_effects, "matrix.totals.hardened_effects"),
    },
  };
}

function parseLink(raw: unknown, at: string): ChainLink {
  const l = record(raw, at);
  return {
    subject: text(l.subject, `${at}.subject`),
    scopes: textList(l.scopes, `${at}.scopes`),
    role: text(l.role, `${at}.role`),
  };
}

export function parseChain(raw: unknown): Chain {
  const c = record(raw, "chain");
  return {
    scenario: text(c.scenario, "chain.scenario"),
    links: list(c.links, "chain.links").map((l, i) => parseLink(l, `chain.links[${i}]`)),
    effective_scopes: textList(c.effective_scopes, "chain.effective_scopes"),
    required_scope: text(c.required_scope, "chain.required_scope"),
    attenuated_away: textList(c.attenuated_away, "chain.attenuated_away"),
  };
}

export function parseApprovals(raw: unknown): Approval[] {
  return list(raw, "approvals").map((item, i) => {
    const at = `approvals[${i}]`;
    const a = record(item, at);
    return {
      approval_id: text(a.approval_id, `${at}.approval_id`),
      subject: text(a.subject, `${at}.subject`),
      tool: text(a.tool, `${at}.tool`),
      account: text(a.account, `${at}.account`),
      amount: amount(a.amount, `${at}.amount`),
      expires_at: text(a.expires_at, `${at}.expires_at`),
      consumed_at: textOrNull(a.consumed_at, `${at}.consumed_at`),
      state: text(a.state, `${at}.state`),
    };
  });
}

export function parseAudit(raw: unknown): AuditEntry[] {
  return list(raw, "audit").map((item, i) => {
    const at = `audit[${i}]`;
    const e = record(item, at);
    return {
      audit_id: text(e.audit_id, `${at}.audit_id`),
      at: text(e.at, `${at}.at`),
      subject: text(e.subject, `${at}.subject`),
      tool: text(e.tool, `${at}.tool`),
      policy: text(e.policy, `${at}.policy`),
      decision: decision(e.decision, `${at}.decision`),
      reason: textOrNull(e.reason, `${at}.reason`),
      effective_scopes: textList(e.effective_scopes, `${at}.effective_scopes`),
      required_scope: text(e.required_scope, `${at}.required_scope`),
      effect_id: textOrNull(e.effect_id, `${at}.effect_id`),
    };
  });
}
