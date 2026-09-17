"""Re-measure the security matrix and prove the committed artifacts still say what it says.

Every published number in this repository comes from `artifacts/`. Nothing regenerated those files
in CI, which a review named the weakest link in the whole evidence chain: internal consistency
is a property a hand-edited file has too. This closes it by measuring again and comparing.

**Not a byte diff.** Every run mints fresh approval, effect and audit ids and a fresh timestamp, so
`git diff --exit-code artifacts/` would fail on a correct run and teach everyone to ignore it. What
is compared is what the repository actually publishes: the totals, and per scenario the decision,
the denial reason and the effect count under both policies. Ids and times are expected to differ and
are deliberately not compared.

The three console artifacts are compared by shape rather than content for the same reason — a row
count, the set of decisions, the set of approval states, the delegation links. A chain is the one
place where content *is* stable, because it is computed from the scenario definitions.

    AAB_POSTGRES_DSN=... uv run python scripts/gate_matrix.py

Exits non-zero, naming the field, if a committed number no longer reproduces.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from pathlib import Path
from typing import Any

from agent_authz_broker.config import Settings
from agent_authz_broker.db.engine import build_engine
from agent_authz_broker.db.models import Base
from agent_authz_broker.demo.matrix import build_matrix

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"


def _matrix_shape(matrix: dict[str, Any]) -> dict[str, Any]:
    """The part of the matrix that must reproduce exactly, run after run."""
    return {
        "totals": matrix["totals"],
        "resource_server_url": matrix["resource_server_url"],
        "scenarios": [
            {
                "id": s["id"],
                "is_attack": s["is_attack"],
                "expected_effects": s["expected_effects"],
                "naive": {k: s["naive"][k] for k in ("decision", "reason", "effects")},
                "hardened": {k: s["hardened"][k] for k in ("decision", "reason", "effects")},
            }
            for s in matrix["scenarios"]
        ],
    }


def _console_shape(
    audit: list[Any], approvals: list[Any], chains: dict[str, Any]
) -> dict[str, Any]:
    """What the three console artifacts must keep saying, minus everything a run randomises."""
    return {
        "audit": {
            "rows": len(audit),
            "decisions": sorted({(r["policy"], r["decision"], r["reason"]) for r in audit}),
            "effects_by_policy": {
                policy: sum(1 for r in audit if r["policy"] == policy and r["effect_id"])
                for policy in ("naive", "hardened")
            },
            "subjects": sorted({str(r["subject"]) for r in audit}),
        },
        "approvals": {
            "rows": len(approvals),
            "states": sorted(r["state"] for r in approvals),
            "targets": sorted(
                {(r["subject"], r["tool"], r["account"], r["amount"]) for r in approvals}
            ),
        },
        # Chains are computed from the scenario definitions and the minted token, so they are
        # stable in full -- this is the one artifact compared field for field.
        "chains": chains,
    }


def _load(name: str) -> Any:
    return json.loads((ARTIFACTS / name).read_text(encoding="utf-8"))


async def _measure() -> tuple[dict[str, Any], dict[str, Any]]:
    settings = Settings()
    engine = build_engine(settings)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        return await build_matrix(
            engine,
            audience=settings.resource_server_url,
            generated_at=dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds"),
        )
    finally:
        await engine.dispose()


def _report(label: str, committed: Any, measured: Any) -> bool:
    if committed == measured:
        print(f"  {label}: reproduces")
        return True
    print(f"  {label}: DRIFTED")
    print(f"    committed: {json.dumps(committed, sort_keys=True)[:900]}")
    print(f"    measured:  {json.dumps(measured, sort_keys=True)[:900]}")
    return False


def main() -> int:
    missing = [
        n
        for n in ("matrix.json", "audit.json", "approvals.json", "chains.json")
        if not (ARTIFACTS / n).is_file()
    ]
    if missing:
        print(f"no committed artifacts to gate: {', '.join(missing)}")
        return 2

    matrix, console = asyncio.run(_measure())

    print("re-measured against real PostgreSQL; comparing with the committed artifacts")
    ok = _report("matrix", _matrix_shape(_load("matrix.json")), _matrix_shape(matrix))
    ok &= _report(
        "console",
        _console_shape(_load("audit.json"), _load("approvals.json"), _load("chains.json")),
        _console_shape(console["audit"], console["approvals"], console["chains"]),
    )

    if not ok:
        print(
            "\nA committed number no longer reproduces. Either the behaviour changed and the "
            "artifacts must be regenerated with `make matrix`, or the artifacts were edited by "
            "hand -- which is the thing this gate exists to make impossible."
        )
        return 1
    print("every published number reproduces from a fresh run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
