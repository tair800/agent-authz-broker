"""The guard that stops the kill test from being predeclared and then quietly never run.

`test_kill_criteria.py` was committed before the implementation existed, so it opens with an
`importorskip`. That skip is a pre-registration device with a short life: the moment the package is
importable it has done its job, and from then on it is indistinguishable from a suite that silently
does nothing.

Project 3 shipped a guard that forbade importing a module that did not exist. It passed every run
and protected nothing until a reviewer planted the breach it was supposed to stop. The lesson
generalises: **a check that cannot fail is not a check**, and a skip nobody notices is the same
failure wearing different clothes. This test is the alarm.

**And this file was itself that mistake, one review later.** Every assertion here reads the kill
test as *text*. A reviewer pointed out that banning the literal string ``importorskip`` bans one
spelling of one mechanism: adding ``pytest.mark.skip`` to the module left all three assertions
green while zero kill tests ran. Reproduced exactly — the text guard reported ``3 passed``.

The real guard is now ``pytest_collection_modifyitems`` in ``conftest.py``, which asks pytest what
it is **about to run** instead of guessing from source. This file is the second line: it catches
the ways a scenario can vanish that collection cannot see — a deleted test, an assertion that stops
reading the database. Both are planted as breach 9 and breach 10.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KILL_TEST = ROOT / "tests" / "test_kill_criteria.py"

#: The scenarios ADR-001 fixed before implementation. Declared once; both guards below read it.
_SCENARIOS = (
    "test_A_valid_token_for_another_resource_server_is_refused",
    "test_B_delegated_token_cannot_gain_a_scope_an_ancestor_lacked",
    "test_B_multi_hop_attenuation_takes_the_intersection_of_every_link",
    "test_C_irreversible_tool_without_an_approval_does_nothing",
    "test_C_an_approval_that_does_not_match_is_not_an_approval",
    "test_D_two_concurrent_calls_on_one_approval_produce_exactly_one_effect",
    "test_E_the_correct_request_succeeds_exactly_once",
)


def _package_exists() -> bool:
    return importlib.util.find_spec("agent_authz_broker.authz") is not None


def test_the_kill_test_file_is_present_and_names_every_predeclared_scenario() -> None:
    """ADR-001 fixes five scenarios. If one disappears from the file, the build fails.

    Matching on the test names rather than counting them: a count is satisfied by renaming, and the
    point is that scenario D — one approval, one effect — is still being asked.
    """
    source = KILL_TEST.read_text(encoding="utf-8")
    missing = [name for name in _SCENARIOS if name not in source]
    assert not missing, (
        "the predeclared kill test lost a scenario ADR-001 fixed before implementation: "
        + ", ".join(missing)
    )


def test_the_predeclaration_skip_does_not_outlive_the_package() -> None:
    """Once `agent_authz_broker.authz` imports, the kill test must actually run."""
    if not _package_exists():
        pytest.skip("the package does not exist yet; the kill test is still predeclared")

    source = KILL_TEST.read_text(encoding="utf-8")
    # Every spelling, not the one that happened to be used. `conftest.py`'s collection hook is
    # what actually enforces this — these strings catch the mechanism before it is even collected,
    # and catch a `pytest.skip()` inside a body, which carries no marker for the hook to see.
    banned = ["importorskip", "mark.skip", "skipif", "pytest.skip("]
    found = [needle for needle in banned if needle in source]
    assert not found, (
        "agent_authz_broker.authz is importable, so nothing in the kill test may disable itself. "
        f"Found: {', '.join(found)}. From here on a skip means the suite that proves the central "
        "security claim is not running."
    )


def test_effect_counts_are_read_from_the_database_not_from_a_return_value() -> None:
    """ADR-001: 'a component that grades itself is not evidence.'

    The kill test must assert on `effect_count()`, which reads `irreversible_effect`. A suite that
    asserted on what the call returned would pass against a server that reported success and wrote
    nothing — or, far worse, one that reported refusal and wrote anyway.

    Checked per scenario rather than by counting occurrences across the file. The count was
    ``>= 7`` against a file containing 8, so one database read could be deleted with the guard
    still green — and a count is satisfied by seven reads in one test and none in the others.
    """
    tree = ast.parse(KILL_TEST.read_text(encoding="utf-8"))
    bodies = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    silent = []
    for name in _SCENARIOS:
        node = bodies.get(name)
        if node is None:
            continue  # absence is the previous test's business, not this one's.
        reads = [
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Attribute) and child.attr == "effect_count"
        ]
        if not reads:
            silent.append(name)
    assert not silent, (
        "these predeclared scenarios no longer read the effect count from the database, so they "
        "grade the system on what it reported about itself: " + ", ".join(silent)
    )
