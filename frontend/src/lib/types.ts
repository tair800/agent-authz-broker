/**
 * The shapes this console reads, and the small vocabularies it renders differently.
 *
 * Two deliberate choices here. First, the open fields — `reason`, `policy`, `state`, a scenario
 * `id` — are typed as `string` rather than as closed unions, even though the broker's own
 * `DenialReason` is a closed set in `domain.py`. A console that refuses to render a reason it has
 * not been recompiled for is a console that hides the one new refusal you most want to see. The
 * known values below drive colour and wording; anything else falls through to a neutral rendering
 * of the raw value.
 *
 * Second, `amount` is `string | number` and is never turned into a number here. The broker decides
 * what an amount is; this console shows what it was told.
 */

export type Decision = "allowed" | "denied";

export interface ScenarioOutcome {
  decision: Decision;
  reason: string | null;
  /** Rows written to `irreversible_effect`. The number that grades everything. */
  effects: number;
}

export interface Scenario {
  id: string;
  title: string;
  description: string;
  /** The predeclared baseline: signature and expiry only. */
  naive: ScenarioOutcome;
  hardened: ScenarioOutcome;
}

export interface Matrix {
  generated_at: string;
  resource_server_url: string;
  scenarios: Scenario[];
  totals: { naive_effects: number; hardened_effects: number };
}

export interface ChainLink {
  subject: string;
  /** What *this* principal held. The intersection of these is the whole attenuation rule. */
  scopes: string[];
  role: string;
}

export interface Chain {
  scenario: string;
  /** Root first, leaf last. A token issued directly to its subject has one link. */
  links: ChainLink[];
  effective_scopes: string[];
  required_scope: string;
  /** Scopes the leaf claimed that no longer survive the intersection. */
  attenuated_away: string[];
}

export interface Approval {
  approval_id: string;
  subject: string;
  tool: string;
  account: string;
  amount: string | number;
  expires_at: string;
  /** Non-null means spent. This field is the reason replay is impossible. */
  consumed_at: string | null;
  state: string;
}

export interface AuditEntry {
  audit_id: string;
  at: string;
  subject: string;
  tool: string;
  policy: string;
  decision: Decision;
  reason: string | null;
  effective_scopes: string[];
  required_scope: string;
  /** The row in `irreversible_effect` this decision produced, when it produced one. */
  effect_id: string | null;
}

/** Where the rendered data came from. Shown on every screen, because it changes what it means. */
export type DataSource = "live" | "fixtures";

export interface ApiFailure {
  endpoint: string;
  message: string;
  detail: string | null;
}

export type Fetched<T> =
  | { ok: true; data: T; source: DataSource }
  | { ok: false; failure: ApiFailure };

/**
 * Plain-language glosses for the refusals in `domain.py`'s `DenialReason`.
 *
 * The machine-readable reason is always shown next to the gloss rather than replaced by it: the
 * reason is what the audit table and the tests agree on, and a sentence somebody typed is not
 * something anyone can grep for.
 */
export const REASON_BLURB: Readonly<Record<string, string>> = {
  signature_invalid: "The signature did not verify against the authority's key set.",
  issuer_unknown: "Signed by an authority this server does not know.",
  token_expired: "Past its `exp`.",
  token_malformed: "Not a token this server could parse.",
  audience_mismatch: "Minted for a different resource server. This one is not its audience.",
  insufficient_effective_scope:
    "The scope survived by the whole delegation chain does not include what this tool needs.",
  delegation_malformed: "The `act` chain could not be read as a chain.",
  approval_required: "No matching, unexpired, unconsumed approval exists in this server's database.",
  approval_expired: "An approval was found and it is past its expiry.",
  approval_already_consumed: "That approval has already authorised its one irreversible effect.",
  unknown_tool: "No such tool.",
};
