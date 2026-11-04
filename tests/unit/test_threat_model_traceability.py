"""Milestone 1: machine-check the threat model's traceability.

"Done when" for M1 is: every security requirement has an ID and a planned test.
This test parses the tables in docs/threat-model.md (each table is preceded by an
HTML marker such as ``<!-- table:threats -->``) and checks that threats, risks,
requirements and goals are complete and consistent with each other.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parents[2] / "docs" / "threat-model.md"

STRIDE = {"S", "T", "R", "I", "D", "E"}
ATTACKERS = {"A1", "A2", "A3", "A4"}
TREATMENTS = {"Mitigate", "Accept"}
STATUSES = {"Planned", "Proposed", "Done"}

Row = dict[str, str]


def _table(text: str, name: str) -> list[Row]:
    """Return the rows of the Markdown table that follows ``<!-- table:name -->``."""
    marker = f"<!-- table:{name} -->"
    assert marker in text, f"missing table marker {marker}"
    lines = text.split(marker, 1)[1].lstrip("\n").splitlines()
    table_lines: list[str] = []
    for line in lines:
        if not line.startswith("|"):
            break
        table_lines.append(line)
    assert len(table_lines) >= 3, f"table {name} is empty"

    def cells(line: str) -> list[str]:
        return [c.strip() for c in line.strip().strip("|").split("|")]

    header = cells(table_lines[0])
    rows = [dict(zip(header, cells(line), strict=True)) for line in table_lines[2:]]
    return rows


def _ids(field: str, prefix: str) -> list[str]:
    return re.findall(rf"\b{prefix}-\d+\b", field)


@pytest.fixture(scope="module")
def doc() -> str:
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def threats(doc: str) -> list[Row]:
    return _table(doc, "threats")


@pytest.fixture(scope="module")
def risks(doc: str) -> list[Row]:
    return _table(doc, "risks")


@pytest.fixture(scope="module")
def requirements(doc: str) -> list[Row]:
    return _table(doc, "requirements")


@pytest.fixture(scope="module")
def goals(doc: str) -> list[Row]:
    return _table(doc, "goals")


def _assert_sequential(ids: list[str], prefix: str, width: int) -> None:
    expected = [f"{prefix}-{i:0{width}d}" for i in range(1, len(ids) + 1)]
    assert ids == expected, f"{prefix} IDs must be unique and numbered without gaps"


def test_threat_ids_are_sequential(threats: list[Row]) -> None:
    _assert_sequential([t["ID"] for t in threats], "T", 2)


def test_requirement_ids_are_sequential(requirements: list[Row]) -> None:
    _assert_sequential([r["ID"] for r in requirements], "SR", 1)


def test_threats_use_valid_stride_and_attackers(threats: list[Row]) -> None:
    for t in threats:
        cats = {c.strip() for c in t["STRIDE"].split(",")}
        assert cats and cats <= STRIDE, t["ID"]
        attackers = set(re.findall(r"\bA\d+\b", t["Attacker"]))
        assert attackers and attackers <= ATTACKERS, t["ID"]
        assert t["Threat"], t["ID"]


def test_all_stride_categories_and_attackers_are_covered(threats: list[Row]) -> None:
    seen_stride = {c.strip() for t in threats for c in t["STRIDE"].split(",")}
    seen_attackers = {a for t in threats for a in re.findall(r"\bA[1-4]\b", t["Attacker"])}
    assert seen_stride == STRIDE
    assert seen_attackers == ATTACKERS


def test_every_threat_has_exactly_one_risk_entry(threats: list[Row], risks: list[Row]) -> None:
    assert sorted(r["Threat"] for r in risks) == sorted(t["ID"] for t in threats)


def test_risk_scores_are_consistent(risks: list[Row]) -> None:
    for r in risks:
        lik, imp, score = int(r["L"]), int(r["I"]), int(r["Score"])
        rl, ri, rscore = int(r["Res. L"]), int(r["Res. I"]), int(r["Res. score"])
        assert all(1 <= v <= 5 for v in (lik, imp, rl, ri)), r["Threat"]
        assert score == lik * imp, r["Threat"]
        assert rscore == rl * ri, r["Threat"]
        assert rscore <= score, f"{r['Threat']}: residual risk above inherent risk"


def test_risk_treatment_is_justified(risks: list[Row], requirements: list[Row]) -> None:
    known = {r["ID"] for r in requirements}
    for r in risks:
        assert r["Treatment"] in TREATMENTS, r["Threat"]
        srs = _ids(r["Mitigations"], "SR")
        assert set(srs) <= known, f"{r['Threat']} references unknown SR"
        if r["Treatment"] == "Mitigate":
            assert srs, f"{r['Threat']} is mitigated but names no SR"
        else:
            assert len(r["Notes"]) > 20, f"{r['Threat']} accepted without rationale"


def test_every_requirement_has_threats_milestone_and_planned_test(
    requirements: list[Row], threats: list[Row]
) -> None:
    known = {t["ID"] for t in threats}
    for sr in requirements:
        tids = _ids(sr["Threats"], "T")
        assert tids, f"{sr['ID']} traces to no threat"
        assert set(tids) <= known, f"{sr['ID']} references unknown threat"
        assert re.fullmatch(r"M(\d|1[0-2])(, ?M(\d|1[0-2]))*", sr["Milestone"]), sr["ID"]
        assert len(sr["Planned verification"]) > 10, f"{sr['ID']} has no planned test"
        assert sr["Requirement"], sr["ID"]
        assert sr["Status"].split()[0] in STATUSES, sr["ID"]


def test_threat_and_requirement_links_agree(risks: list[Row], requirements: list[Row]) -> None:
    from_register = {(r["Threat"], sr) for r in risks for sr in _ids(r["Mitigations"], "SR")}
    from_requirements = {(t, sr["ID"]) for sr in requirements for t in _ids(sr["Threats"], "T")}
    assert from_register - from_requirements == set(), "register links missing in SR table"
    assert from_requirements - from_register == set(), "SR table links missing in register"


def test_every_goal_is_covered(goals: list[Row], requirements: list[Row]) -> None:
    known = {r["ID"] for r in requirements}
    assert len(goals) >= 9
    for g in goals:
        srs = _ids(g["Requirements"], "SR")
        assert srs, f"{g['ID']} has no requirement"
        assert set(srs) <= known, g["ID"]
