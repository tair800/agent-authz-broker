"""Replant every planted breach and prove the suite still catches each one.

A suite that has never failed is not evidence that a system is safe; it is evidence that nothing
has tested it. Project 3 in this portfolio shipped a guard that forbade importing a module which
did not exist — green on every run, protecting nothing, until a reviewer planted the breach it was
supposed to stop.

ADR-003 recorded that each control here was removed by hand and the right test went red. A reviewer
was right to point out that this left the claim exactly as checkable as the guard it was warning
about: a table in a document. So the removals live here instead. Each one edits a source file,
runs only the tests its ADR names for it, and requires them to **fail**. A control whose removal
changes nothing is reported as a hole, and the script exits non-zero.

Breaches 1-5 are ADR-003's. Breaches 6-8 cover the fixes for what a **second** review found -- an
unauthenticated approval endpoint, an audit trail blind to refusals made at the transport, and an
uncaught parser crash -- so the fixes are held to the same standard as the controls that were right
the first time. See ADR-004.

    make breaches      # PostgreSQL must be up: make db-up

Every file is restored in a ``finally``, and the script refuses to start against a dirty working
tree so that a crash mid-run can never be mistaken for source you wrote. If it is ever killed
between the edit and the restore, ``git checkout -- src/`` puts it back.
"""

from __future__ import annotations

import argparse
import dataclasses
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclasses.dataclass(frozen=True)
class Breach:
    """One control removed, and the tests that must notice."""

    number: int
    control: str
    file: str
    before: str
    after: str
    tests: tuple[str, ...]
    """Node ids. Narrow on purpose: a breach that fails the whole suite proves less than one that
    fails the specific test ADR-003 claims is watching for it."""


AUTHZ = "src/agent_authz_broker/authz.py"
APPROVALS = "src/agent_authz_broker/approvals.py"
MCP = "src/agent_authz_broker/mcp_server.py"
APP = "src/agent_authz_broker/app.py"
TOKENS = "src/agent_authz_broker/tokens.py"
KILL = "tests/test_kill_criteria.py"
SURFACE = "tests/test_mcp_surface.py"
BOUNDARIES = "tests/test_authority_boundaries.py"
PREDECL = "tests/test_predeclaration.py"
RATELIMIT_TESTS = "tests/test_rate_limit.py"
RATELIMIT = "src/agent_authz_broker/ratelimit.py"

BREACHES: tuple[Breach, ...] = (
    Breach(
        number=1,
        control="HARDENED checks the token's audience",
        file=AUTHZ,
        before='HARDENED = Policy(name="hardened", check_audience=True, attenuate_chain=True)',
        after='HARDENED = Policy(name="hardened", check_audience=False, attenuate_chain=True)',
        tests=(
            f"{KILL}::test_A_valid_token_for_another_resource_server_is_refused",
            f"{SURFACE}::test_the_verifier_refuses_a_token_minted_for_another_resource_server",
        ),
    ),
    Breach(
        number=2,
        control="effective_scopes intersects the whole chain",
        file=AUTHZ,
        before="    if not attenuate:\n        return claims.scopes\n    granted = claims.scopes",
        after="    if True:\n        return claims.scopes\n    granted = claims.scopes",
        tests=(
            f"{KILL}::test_B_delegated_token_cannot_gain_a_scope_an_ancestor_lacked",
            f"{KILL}::test_B_multi_hop_attenuation_takes_the_intersection_of_every_link",
        ),
    ),
    Breach(
        number=3,
        control="consume_approval spends an approval at most once",
        file=APPROVALS,
        before=(
            "        .where(Approval.approval_id == approval_id, Approval.consumed_at.is_(None))"
        ),
        after="        .where(Approval.approval_id == approval_id)",
        tests=(f"{KILL}::test_D_two_concurrent_calls_on_one_approval_produce_exactly_one_effect",),
    ),
    Breach(
        number=4,
        control="the approval lookup is bound to the account",
        file=APPROVALS,
        before="                Approval.account == account,\n",
        after="",
        tests=(
            f"{KILL}::test_C_an_approval_that_does_not_match_is_not_an_approval[other_account]",
        ),
    ),
    Breach(
        number=5,
        control="the admin reset is not an MCP tool",
        file=MCP,
        before='    @server.tool(title="Ping")',
        after=(
            '    @server.tool(title="Admin reset")\n'
            "    def admin_reset() -> str:\n"
            '        """Planted by scripts/plant_breaches.py. Never commit this."""\n'
            '        return "reset"\n'
            "\n"
            '    @server.tool(title="Ping")'
        ),
        tests=(
            f"{SURFACE}::test_the_advertised_tool_list_is_exactly_the_six",
            f"{SURFACE}::test_no_reset_shaped_tool_is_reachable_over_mcp",
        ),
    ),
    # 6-8 come from the second review, which found two of these open rather than merely untested.
    # They are planted the same way so that the fixes are held to the same standard as the
    # controls that were right the first time.
    Breach(
        number=6,
        control="granting an approval needs a credential no agent holds",
        file=APP,
        before="dependencies=[Depends(_require_approver_token)],",
        after="",
        tests=(
            f"{BOUNDARIES}::test_no_approval_can_be_granted_when_no_approver_credential_is_configured",
            f"{BOUNDARIES}::test_an_agents_own_bearer_token_cannot_grant_it_an_approval",
        ),
    ),
    Breach(
        number=7,
        control="a refusal at the transport is written to the audit trail",
        file=MCP,
        before="        if self._engine is None:",
        after="        if True:  # noqa: SIM103",
        tests=(
            f"{BOUNDARIES}::test_a_token_minted_for_another_resource_server_is_audited_at_the_transport",
            f"{BOUNDARIES}::test_a_garbage_bearer_string_is_audited_rather_than_dropped",
        ),
    ),
    Breach(
        number=8,
        control="an unparsable token is refused rather than raised out of verify_token",
        file=TOKENS,
        before="    except (jwt.PyJWTError, RecursionError, ValueError):",
        after="    except jwt.PyJWTError:",
        tests=(
            f"{BOUNDARIES}::test_the_parse_refuses_rather_than_raising_even_with_the_size_cap_lifted",
        ),
    ),
    # 9 and 10 come from the final review, which found that the guard protecting the kill test was
    # itself the mistake it warns about: three checks over the file's *text*, all of which stayed
    # green under `pytest.mark.skip` while zero kill tests ran.
    Breach(
        number=9,
        control="a disabled kill test stops the whole session",
        file=KILL,
        before="pytestmark = [pytest.mark.integration, pytest.mark.asyncio]",
        after=(
            'pytestmark = [pytest.mark.skip(reason="planted"), '
            "pytest.mark.integration, pytest.mark.asyncio]"
        ),
        # The kill file itself, because conftest's hook only fires on a run that collects it, and
        # UsageError at collection needs no database.
        tests=(KILL,),
    ),
    Breach(
        number=10,
        control="every predeclared scenario reads its effect count from the database",
        file=KILL,
        before="    assert await lab.effect_count() == 1\n",
        after="",
        tests=(
            f"{PREDECL}::test_effect_counts_are_read_from_the_database_not_from_a_return_value",
        ),
    ),
    # 11 covers the rate limiter, which is secondary to the security claim but still has to be
    # shown to work rather than asserted. Read-then-write is the plausible wrong implementation --
    # it looks correct and leaks under exactly the concurrency the bound is quoted for.
    Breach(
        number=11,
        control="the rate-limit claim is atomic, so the bound holds under concurrency",
        file=RATELIMIT,
        before='            set_={"count": RateLimitCounter.count + 1},',
        after='            set_={"count": RateLimitCounter.count},',
        tests=(
            f"{RATELIMIT_TESTS}::test_above_the_limit_the_call_is_denied_and_writes_no_effect",
            f"{RATELIMIT_TESTS}::test_concurrent_calls_cannot_exceed_the_documented_bound",
        ),
    ),
)


GIT = shutil.which("git") or "git"


def _dirty() -> list[str]:
    # The suppressions below are justified once, here: both argv lists are literals defined in
    # this file plus the node ids in BREACHES. Nothing reaches them from an argument, an
    # environment variable or a file, and no shell is involved.
    result = subprocess.run(  # noqa: S603
        [GIT, "status", "--porcelain", "--", "src", "tests"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _pytest(tests: tuple[str, ...]) -> int:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "-p", "no:randomly", *tests],
        cwd=ROOT,
        check=False,
    ).returncode


def _read(path: Path) -> str:
    """Read without translating line endings, so writing the same string back is a no-op.

    The first version used ``read_text``/``write_text``. On Windows that reads CRLF as \n and
    writes \n back as CRLF, so restoring an LF-checked-out file rewrote every line of it. The run
    reported five breaches caught and then a dirty tree — which is the only reason this is a
    comment about a fixed bug rather than a few thousand spurious line changes in a commit.
    """
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def _write(path: Path, content: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(content)


def _as_written(anchor: str, content: str) -> str:
    """The anchor with this file's line ending, so a CRLF checkout matches too."""
    return anchor.replace("\n", "\r\n") if "\r\n" in content else anchor


def _run(breach: Breach) -> bool:
    """Plant one breach, run its tests, restore. True if the tests caught it."""
    path = ROOT / breach.file
    original = _read(path)
    before = _as_written(breach.before, original)
    occurrences = original.count(before)
    if occurrences != 1:
        print(
            f"  breach {breach.number}: cannot plant — its anchor appears {occurrences} times in "
            f"{breach.file}. The source moved; fix this script rather than the count.",
        )
        return False

    try:
        _write(path, original.replace(before, _as_written(breach.after, original)))
        code = _pytest(breach.tests)
    finally:
        _write(path, original)

    caught = code != 0
    verdict = "CAUGHT (its tests failed, as required)" if caught else "NOT CAUGHT"
    print(f"  breach {breach.number}: {verdict}")
    return caught


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", type=int, default=None, help="plant just this breach number")
    args = parser.parse_args()

    dirty = _dirty()
    if dirty:
        print("Refusing to run against a dirty tree — commit or stash first:")
        for line in dirty:
            print(f"  {line}")
        return 2

    selected = [b for b in BREACHES if args.only is None or b.number == args.only]
    if not selected:
        print(f"no breach numbered {args.only}")
        return 2

    holes: list[Breach] = []
    for breach in selected:
        print(f"\nbreach {breach.number}: removing — {breach.control}")
        if not _run(breach):
            holes.append(breach)

    after = _dirty()
    if after:
        print("\nA file was not restored. Run: git checkout -- src/ tests/")
        for line in after:
            print(f"  {line}")
        return 2

    print()
    if holes:
        for breach in holes:
            print(
                f"HOLE: removing '{breach.control}' changed nothing. "
                f"{'; '.join(breach.tests)} still passed."
            )
        print(f"{len(holes)} of {len(selected)} controls are not load-bearing.")
        return 1

    print(
        f"{len(selected)} of {len(selected)} controls are load-bearing: "
        "each removal was caught by the tests its ADR names."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
