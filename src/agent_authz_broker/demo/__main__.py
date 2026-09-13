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


async def _main(out: Path) -> None:
    settings = Settings()
    engine = build_engine(settings)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        artifact = await build_matrix(
            engine,
            audience=settings.resource_server_url,
            generated_at=dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds"),
        )
    finally:
        await engine.dispose()

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    totals = artifact["totals"]
    print(f"wrote {out}")
    print(f"  scenarios:        {len(artifact['scenarios'])} ({totals['attacks']} of them attacks)")
    print(
        f"  naive    permitted {totals['attacks_permitted_by_naive']} attack(s), "
        f"{totals['naive_effects']} irreversible effect(s) in total"
    )
    print(
        f"  hardened permitted {totals['attacks_permitted_by_hardened']} attack(s), "
        f"{totals['hardened_effects']} irreversible effect(s) in total"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure the security matrix.")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "matrix.json")
    args = parser.parse_args()
    asyncio.run(_main(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
