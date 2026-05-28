"""Unit tests for the asset tagging layer (POST_V01 Rank 4).

Covers the tags table, the tags module API (add/list/remove + asset resolution),
and the dump / cruise integration points. Pure SQLite — no network, no nmap.
"""

from __future__ import annotations

import pytest

from ossuary import cruise, db, dump, tags


def _seed(db_path):
    """Init a DB with two assets and one service, returning the db path."""
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        db.upsert_asset(conn, "10.10.0.6", None, "up")
        db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        conn.commit()
    finally:
        conn.close()
    return db_path


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------

def test_init_db_creates_tags_table(db_path):
    conn = db.init_db(db_path)
    try:
        assert "tags" in db.table_names(conn)
    finally:
        conn.close()


def test_tags_table_uniqueness(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        conn.execute(
            "INSERT INTO tags (entity, entity_id, tag) VALUES ('asset', ?, 'vip')",
            (aid,),
        )
        conn.commit()
        with pytest.raises(Exception):
            conn.execute(
                "INSERT INTO tags (entity, entity_id, tag) VALUES ('asset', ?, 'vip')",
                (aid,),
            )
            conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# add
# --------------------------------------------------------------------------

def test_add_tag_creates_row_and_is_idempotent(db_path):
    _seed(db_path)
    assert tags.add_tag(db_path, "10.10.0.5", "in-scope") is True
    # second add of same tag is a no-op (returns False, no duplicate)
    assert tags.add_tag(db_path, "10.10.0.5", "in-scope") is False
    listing = tags.list_tags(db_path)
    assert [r["tag"] for r in listing] == ["in-scope"]


def test_add_tag_by_hostname(db_path):
    _seed(db_path)
    assert tags.add_tag(db_path, "host-a", "vip") is True
    listing = tags.list_tags(db_path, asset="10.10.0.5")
    assert [r["tag"] for r in listing] == ["vip"]


def test_add_tag_unknown_asset_raises(db_path):
    _seed(db_path)
    with pytest.raises(ValueError, match="no asset matching"):
        tags.add_tag(db_path, "10.10.9.9", "nope")


def test_add_tag_rejects_empty_label(db_path):
    _seed(db_path)
    with pytest.raises(ValueError, match="non-empty"):
        tags.add_tag(db_path, "10.10.0.5", "   ")


def test_add_tag_unknown_entity_raises(db_path):
    _seed(db_path)
    with pytest.raises(ValueError, match="unknown entity"):
        tags.add_tag(db_path, "10.10.0.5", "x", entity="bogus")


# --------------------------------------------------------------------------
# remove
# --------------------------------------------------------------------------

def test_remove_tag(db_path):
    _seed(db_path)
    tags.add_tag(db_path, "10.10.0.5", "priority")
    assert tags.remove_tag(db_path, "10.10.0.5", "priority") is True
    # removing again is a no-op
    assert tags.remove_tag(db_path, "10.10.0.5", "priority") is False
    assert tags.list_tags(db_path) == []


# --------------------------------------------------------------------------
# list + filtering
# --------------------------------------------------------------------------

def test_list_tags_filters_by_asset(db_path):
    _seed(db_path)
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    tags.add_tag(db_path, "10.10.0.5", "vip")
    tags.add_tag(db_path, "10.10.0.6", "out-of-scope")

    only_5 = tags.list_tags(db_path, asset="10.10.0.5")
    assert {r["tag"] for r in only_5} == {"in-scope", "vip"}
    assert all(r["asset_ip"] == "10.10.0.5" for r in only_5)


def test_list_tags_filters_by_entity(db_path):
    _seed(db_path)
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    rows = tags.list_tags(db_path, entity="asset")
    assert len(rows) == 1
    assert tags.list_tags(db_path, entity="finding") == []


def test_list_tags_empty(db_path):
    _seed(db_path)
    assert tags.list_tags(db_path) == []


# --------------------------------------------------------------------------
# helpers used by dump / cruise
# --------------------------------------------------------------------------

def test_asset_tag_map(db_path):
    _seed(db_path)
    tags.add_tag(db_path, "10.10.0.5", "b")
    tags.add_tag(db_path, "10.10.0.5", "a")
    tags.add_tag(db_path, "10.10.0.6", "c")
    conn = db.connect(db_path)
    try:
        mapping = tags.asset_tag_map(conn)
    finally:
        conn.close()
    assert mapping == {"10.10.0.5": ["a", "b"], "10.10.0.6": ["c"]}


# --------------------------------------------------------------------------
# dump integration
# --------------------------------------------------------------------------

def test_dump_includes_tags_per_asset(db_path):
    import json

    _seed(db_path)
    tags.add_tag(db_path, "10.10.0.5", "vip")
    state = json.loads(dump.dump(db_path, "json"))
    asset = next(a for a in state["assets"] if a["ip"] == "10.10.0.5")
    assert asset["tags"] == ["vip"]
    other = next(a for a in state["assets"] if a["ip"] == "10.10.0.6")
    assert other["tags"] == []


def test_dump_filters_by_tag(db_path):
    import json

    _seed(db_path)
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    state = json.loads(dump.dump(db_path, "json", tag="in-scope"))
    assert [a["ip"] for a in state["assets"]] == ["10.10.0.5"]
    # a tag nobody carries yields an empty asset list (valid JSON)
    empty = json.loads(dump.dump(db_path, "json", tag="ghost"))
    assert empty == {"assets": []}


# --------------------------------------------------------------------------
# cruise integration
# --------------------------------------------------------------------------

def test_diff_tags_detects_added_and_removed():
    prev = {"10.10.0.5": ["in-scope"], "10.10.0.6": ["noise"]}
    cur = {"10.10.0.5": ["in-scope", "vip"]}  # 0.6 lost all tags
    changes = cruise.diff_tags(prev, cur)
    by_asset = {c["asset"]: c for c in changes}
    assert by_asset["10.10.0.5"]["added"] == ["vip"]
    assert by_asset["10.10.0.5"]["removed"] == []
    assert by_asset["10.10.0.6"]["added"] == []
    assert by_asset["10.10.0.6"]["removed"] == ["noise"]


def test_diff_tags_ignores_unchanged():
    same = {"10.10.0.5": ["a", "b"]}
    assert cruise.diff_tags(same, same) == []
