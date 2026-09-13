"""`python -m agent_authz_broker.demo` — measure the security matrix and write the artifact.

A module rather than an endpoint. It clears the demo database between rows, and a thing that clears
tables should be run by a person at a shell or by a deploy hook, never reached over HTTP.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
from pathlib import Path

from agent_authz_broker.config import Settings
from agent_authz_broker.db.engine import build_engine
from agent_authz_broker.db.models import Base
from agent_authz_broker.demo.matrix import build_matrix

ROOT = Path(__file__).resolve().parents[3]


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")


async def _main(out: Path) -> None:
    settings = Settings()
    engine = build_engine(settings)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        artifact, console = await build_matrix(
            engine,
            audience=settings.resource_server_url,
            generated_at=dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds"),
        )
    finally:
        await engine.dispose()

    _write(out, artifact)
    # The other three console screens, from the same run. Beside the matrix rather than inside it
    # because the console reads one file per screen and the API serves one route per screen; a
    # combined artifact would only have to be taken apart again at both ends.
    _write(out.with_name("audit.json"), console["audit"])
    _write(out.with_name("approvals.json"), console["approvals"])
    _write(out.with_name("chains.json"), console["chains"])

    totals = artifact["totals"]
    print(f"  scenarios:        {len(artifact['scenarios'])} ({totals['attacks']} of them attacks)")
    print(
        f"  naive    permitted {totals['attacks_permitted_by_naive']} attack(s), "
        f"{totals['naive_effects']} irreversible effect(s) in total"
    )
    print(
        f"  hardened permitted {totals['attacks_permitted_by_hardened']} attack(s), "
        f"{totals['hardened_effects']} irreversible effect(s) in total"
    )
    print(f"  audit:            {len(console['audit'])} row(s) across both policies")


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure the security matrix.")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "matrix.json")
    args = parser.parse_args()
    asyncio.run(_main(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
