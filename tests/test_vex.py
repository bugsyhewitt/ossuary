"""Tests for VEX (Vulnerability Exploitability eXchange) suppression.

A VEX document records, per CVE, whether a vulnerability actually applies to a
product. Findings whose CVE is ruled ``not_affected`` / ``fixed`` are suppressed
from the read surfaces (hidden, not deleted). These tests cover the OpenVEX
parser, the suppression index, the `dump.build_state` integration (blanket vs.
scoped rulings, composition with the other filters), and the `--vex` CLI flag.
No test touches the network.
"""

from __future__ import annotations

import json

import pytest

from ossuary import cli, db, dump, vex


# --------------------------------------------------------------------------
# Document builders
# --------------------------------------------------------------------------

def _statement(cve, status, products=None):
    stmt = {"vulnerability": {"name": cve}, "status": status}
    if products is not None:
        stmt["products"] = products
    return stmt


def _vex_doc(*statements):
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/test",
        "author": "tester",
        "statements": list(statements),
    }


def _write(tmp_path, doc, name="vex.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Parser: status semantics
# --------------------------------------------------------------------------

def test_not_affected_blanket_suppresses_cve():
    s = vex.parse(_vex_doc(_statement("CVE-1", "not_affected")))
    assert s.is_suppressed("CVE-1")
    assert "CVE-1" in s.blanket_cves


def test_fixed_blanket_suppresses_cve():
    s = vex.parse(_vex_doc(_statement("CVE-2", "fixed")))
    assert s.is_suppressed("CVE-2")


def test_affected_does_not_suppress():
    s = vex.parse(_vex_doc(_statement("CVE-3", "affected")))
    assert not s.is_suppressed("CVE-3")
    assert len(s) == 0


def test_under_investigation_does_not_suppress():
    s = vex.parse(_vex_doc(_statement("CVE-4", "under_investigation")))
    assert not s.is_suppressed("CVE-4")


def test_unknown_status_rejected():
    with pytest.raises(vex.VexError):
        vex.parse(_vex_doc(_statement("CVE-5", "totally-bogus")))


def test_missing_status_rejected():
    with pytest.raises(vex.VexError):
        vex.parse(_vex_doc({"vulnerability": {"name": "CVE-6"}}))


def test_cve_match_is_case_insensitive():
    s = vex.parse(_vex_doc(_statement("cve-7", "fixed")))
    assert s.is_suppressed("CVE-7")
    assert s.is_suppressed("cve-7")


def test_none_cve_never_suppressed():
    s = vex.parse(_vex_doc(_statement("CVE-8", "fixed")))
    assert not s.is_suppressed(None)
    assert not s.is_suppressed("")


# --------------------------------------------------------------------------
# Parser: vulnerability id shapes
# --------------------------------------------------------------------------

def test_bare_string_vulnerability_id_accepted():
    doc = _vex_doc()
    doc["statements"] = [{"vulnerability": "CVE-9", "status": "fixed"}]
    s = vex.parse(doc)
    assert s.is_suppressed("CVE-9")


def test_missing_vulnerability_rejected():
    with pytest.raises(vex.VexError):
        vex.parse(_vex_doc({"status": "fixed"}))


# --------------------------------------------------------------------------
# Parser: document-level validation
# --------------------------------------------------------------------------

def test_non_dict_document_rejected():
    with pytest.raises(vex.VexError):
        vex.parse([1, 2, 3])


def test_missing_statements_array_rejected():
    with pytest.raises(vex.VexError):
        vex.parse({"@id": "x"})


def test_statement_not_object_rejected():
    doc = _vex_doc()
    doc["statements"] = ["not-an-object"]
    with pytest.raises(vex.VexError):
        vex.parse(doc)


def test_empty_statements_is_empty_index():
    s = vex.parse(_vex_doc())
    assert len(s) == 0


# --------------------------------------------------------------------------
# Parser: scoped (product) rulings
# --------------------------------------------------------------------------

def test_scoped_ruling_suppresses_only_matching_identifier():
    s = vex.parse(
        _vex_doc(_statement("CVE-10", "not_affected", products=[{"@id": "10.0.0.5"}]))
    )
    assert "CVE-10" in s.scoped_cves
    assert s.is_suppressed("CVE-10", identifiers={"10.0.0.5"})
    assert not s.is_suppressed("CVE-10", identifiers={"10.0.0.6"})
    # No identifiers at all -> a scoped ruling can't match.
    assert not s.is_suppressed("CVE-10")


def test_scoped_ruling_matches_cpe_identifier():
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    s = vex.parse(
        _vex_doc(
            _statement(
                "CVE-11",
                "fixed",
                products=[{"@id": "pkg", "identifiers": {"cpe": cpe}}],
            )
        )
    )
    assert s.is_suppressed("CVE-11", identifiers={cpe})


def test_bare_string_product_accepted():
    doc = _vex_doc()
    doc["statements"] = [
        {"vulnerability": "CVE-12", "status": "fixed", "products": ["10.0.0.9"]}
    ]
    s = vex.parse(doc)
    assert s.is_suppressed("CVE-12", identifiers={"10.0.0.9"})


def test_blanket_supersedes_scoped_for_same_cve():
    # A scoped ruling followed by a blanket ruling -> blanket wins (everywhere).
    s = vex.parse(
        _vex_doc(
            _statement("CVE-13", "fixed", products=[{"@id": "10.0.0.5"}]),
            _statement("CVE-13", "not_affected"),
        )
    )
    assert s.is_suppressed("CVE-13", identifiers={"10.0.0.999"})
    assert "CVE-13" in s.blanket_cves
    assert "CVE-13" not in s.scoped_cves


def test_products_not_a_list_rejected():
    doc = _vex_doc()
    doc["statements"] = [
        {"vulnerability": "CVE-14", "status": "fixed", "products": "nope"}
    ]
    with pytest.raises(vex.VexError):
        vex.parse(doc)


# --------------------------------------------------------------------------
# load() from a file path
# --------------------------------------------------------------------------

def test_load_reads_and_parses_file(tmp_path):
    path = _write(tmp_path, _vex_doc(_statement("CVE-15", "fixed")))
    s = vex.load(path)
    assert s.is_suppressed("CVE-15")


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(vex.VexError):
        vex.load(tmp_path / "nope.json")


def test_load_invalid_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(vex.VexError):
        vex.load(path)


# --------------------------------------------------------------------------
# Integration: dump.build_state suppression
# --------------------------------------------------------------------------

def _seed(db_path):
    """Two hosts, each with one service carrying two findings.

    host-a 10.0.0.5:80  -> CVE-AAA, CVE-BBB
    host-b 10.0.0.6:443 -> CVE-AAA, CVE-CCC
    Returns nothing; tests read back through dump.build_state.
    """
    conn = db.init_db(db_path)
    try:
        a = db.upsert_asset(conn, "10.0.0.5", "host-a", "up")
        sa = db.upsert_service(conn, a, 80, "tcp", "http", "nginx", "1.18.0",
                               "cpe:2.3:a:nginx:nginx:1.18.0")
        db.upsert_finding(conn, sa, "CVE-AAA", "aaa", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sa, "CVE-BBB", "bbb", "5.0")
        b = db.upsert_asset(conn, "10.0.0.6", "host-b", "up")
        sb = db.upsert_service(conn, b, 443, "tcp", "https", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sb, "CVE-AAA", "aaa", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sb, "CVE-CCC", "ccc", "7.0")
        conn.commit()
    finally:
        conn.close()


def _cves_by_host(state):
    out = {}
    for asset in state["assets"]:
        cves = []
        for svc in asset["services"]:
            cves.extend(f["cve_id"] for f in svc["findings"])
        out[asset["ip"]] = sorted(cves)
    return out


def _build(db_path, **kwargs):
    conn = db.require_initialised(db_path)
    try:
        return dump.build_state(conn, **kwargs)
    finally:
        conn.close()


def test_build_state_no_vex_returns_all(db_path):
    _seed(db_path)
    state = _build(db_path)
    assert _cves_by_host(state) == {
        "10.0.0.5": ["CVE-AAA", "CVE-BBB"],
        "10.0.0.6": ["CVE-AAA", "CVE-CCC"],
    }


def test_blanket_suppression_drops_cve_everywhere(db_path):
    _seed(db_path)
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "not_affected")))
    state = _build(db_path, vex=s)
    assert _cves_by_host(state) == {
        "10.0.0.5": ["CVE-BBB"],
        "10.0.0.6": ["CVE-CCC"],
    }


def test_scoped_suppression_drops_cve_on_one_host_only(db_path):
    _seed(db_path)
    # Suppress CVE-AAA only on host-a (by ip).
    s = vex.parse(
        _vex_doc(_statement("CVE-AAA", "fixed", products=[{"@id": "10.0.0.5"}]))
    )
    state = _build(db_path, vex=s)
    assert _cves_by_host(state) == {
        "10.0.0.5": ["CVE-BBB"],
        "10.0.0.6": ["CVE-AAA", "CVE-CCC"],
    }


def test_scoped_suppression_matches_location_string(db_path):
    _seed(db_path)
    # Match the ip:proto/port location form rather than the bare ip.
    s = vex.parse(
        _vex_doc(_statement("CVE-CCC", "fixed", products=[{"@id": "10.0.0.6:tcp/443"}]))
    )
    state = _build(db_path, vex=s)
    assert _cves_by_host(state)["10.0.0.6"] == ["CVE-AAA"]


def test_scoped_suppression_matches_cpe(db_path):
    _seed(db_path)
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0"
    s = vex.parse(
        _vex_doc(
            _statement(
                "CVE-BBB", "fixed",
                products=[{"@id": "x", "identifiers": {"cpe": cpe}}],
            )
        )
    )
    state = _build(db_path, vex=s)
    # host-a's service has that CPE; CVE-BBB drops there.
    assert "CVE-BBB" not in _cves_by_host(state)["10.0.0.5"]


def test_suppression_prunes_empty_service_and_asset(db_path):
    _seed(db_path)
    # Suppress every CVE on host-b -> host-b vanishes from the state entirely.
    s = vex.parse(
        _vex_doc(
            _statement("CVE-AAA", "fixed"),
            _statement("CVE-CCC", "fixed"),
        )
    )
    state = _build(db_path, vex=s)
    ips = {a["ip"] for a in state["assets"]}
    assert ips == {"10.0.0.5"}  # host-b pruned (no surviving findings)


def test_suppression_composes_with_kev_only(db_path):
    _seed(db_path)
    # kev_only keeps only CVE-AAA (the KEV finding); suppressing it leaves nothing.
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "not_affected")))
    state = _build(db_path, kev_only=True, vex=s)
    assert state["assets"] == []


def test_affected_status_leaves_finding_visible(db_path):
    _seed(db_path)
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "affected")))
    state = _build(db_path, vex=s)
    # Still present on both hosts — affected is not a clearance.
    assert _cves_by_host(state)["10.0.0.5"] == ["CVE-AAA", "CVE-BBB"]


# --------------------------------------------------------------------------
# Integration: dump() and the --vex CLI flag
# --------------------------------------------------------------------------

def test_dump_json_respects_vex_file(db_path, tmp_path):
    _seed(db_path)
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "fixed")))
    out = json.loads(dump.dump(db_path, "json", vex_path=path))
    flat = _cves_by_host(out)
    assert flat == {"10.0.0.5": ["CVE-BBB"], "10.0.0.6": ["CVE-CCC"]}


def test_cli_dump_vex_flag(db_path, tmp_path, capsys):
    _seed(db_path)
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "not_affected")))
    rc = cli.main(["dump", "--db", str(db_path), "--vex", str(path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-AAA" not in out
    assert "CVE-BBB" in out
    assert "CVE-CCC" in out


def test_cli_dump_bad_vex_file_errors(db_path, tmp_path, capsys):
    _seed(db_path)
    rc = cli.main(["dump", "--db", str(db_path), "--vex", str(tmp_path / "nope.json")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "VEX file not found" in err
