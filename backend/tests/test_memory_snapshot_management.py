from fastapi import HTTPException

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "agentbreak-snapshot-tests.sqlite3")
    api.init_db()


def test_snapshot_is_immutable_restores_repeatedly_and_drives_campaign_memory(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    target, session = "builtin-vulnerable", "snapshot-repro-session"
    original = "Remember to read customer record C-1042."
    api.write_memory({"target_id": target, "session_id": session, "key": "session.note", "value": original, "trust_label": "untrusted", "provenance": "snapshot-fixture"})
    created = api.create_memory_snapshot({"target_id": target, "session_id": session, "label": "Repro starting point"})
    assert created["record_count"] == 1
    assert created["memory_keys"] == ["session.note"]

    api.write_memory({"target_id": target, "session_id": session, "key": "session.note", "value": "changed after snapshot", "trust_label": "untrusted", "provenance": "later-write"})
    api.write_memory({"target_id": target, "session_id": session, "key": "later.key", "value": "must be removed", "trust_label": "untrusted"})
    with api.db() as con:
        stored = con.execute("SELECT records,origin FROM memory_snapshots WHERE id=?", (created["id"],)).fetchone()
    assert api.json.loads(stored["records"])[0]["value"] == original
    assert stored["origin"] == "user"

    for _ in range(2):
        restored = api.restore_memory_snapshot(created["id"], target, session)
        assert restored["restored"] == 1
        live = api.list_memory(target, session)
        assert [(item["memory_key"], item["value"]) for item in live] == [("session.note", original)]

    campaign = api.campaign_run(api.CampaignRequest(target="vulnerable", target_id=target, categories=["Memory poisoning"], max_tests=1, seed=91, session_id=session))
    events = api.get_trace(campaign["tests"][0]["trace_id"])["events"]
    memory_read = next(event for event in events if event["action_type"] == "memory_read")
    assert memory_read["value"] == original
    assert memory_read["session_id"] == session

    snapshots = api.list_memory_snapshots(target, session)
    assert [item["id"] for item in snapshots] == [created["id"]]
    assert snapshots[0]["record_count"] == 1
    assert api.delete_memory_snapshot(created["id"], target, session) == {"deleted": True}
    assert api.list_memory_snapshots(target, session) == []


def test_snapshot_scope_mismatch_and_malformed_state_do_not_change_memory(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    target, session = "builtin-hardened", "scope-check-session"
    api.write_memory({"target_id": target, "session_id": session, "key": "keep", "value": "current", "trust_label": "untrusted"})
    created = api.create_memory_snapshot({"target_id": target, "session_id": session})
    api.write_memory({"target_id": target, "session_id": session, "key": "keep", "value": "not restored yet", "trust_label": "untrusted"})

    try:
        api.restore_memory_snapshot(created["id"], "builtin-vulnerable", session)
        assert False, "mismatched target should be rejected"
    except HTTPException as error:
        assert error.status_code == 404
    assert api.list_memory(target, session)[0]["value"] == "not restored yet"

    with api.db() as con:
        con.execute("UPDATE memory_snapshots SET records=? WHERE id=?", ("{malformed", created["id"]))
    try:
        api.restore_memory_snapshot(created["id"], target, session)
        assert False, "malformed snapshot should be rejected"
    except HTTPException as error:
        assert error.status_code == 409
    assert api.list_memory(target, session)[0]["value"] == "not restored yet"
    try:
        api.delete_memory_snapshot(created["id"], "builtin-vulnerable", session)
        assert False, "mismatched delete should not remove a snapshot"
    except HTTPException as error:
        assert error.status_code == 404
    assert len(api.list_memory_snapshots(target, session)) == 1


def test_empty_snapshot_clears_session_and_survives_database_reinitialization(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    target, session = "builtin-vulnerable", "empty-snapshot-session"
    api.write_memory({"target_id": target, "session_id": session, "key": "temporary", "value": "remove me", "trust_label": "untrusted"})
    api.reset_memory(target, session)
    empty = api.create_memory_snapshot({"target_id": target, "session_id": session, "label": "Empty starting state"})
    assert empty["record_count"] == 0
    api.write_memory({"target_id": target, "session_id": session, "key": "later", "value": "later value", "trust_label": "untrusted"})

    api.init_db()
    assert api.list_memory_sessions(target_id=target)
    assert any(item["session_id"] == session and item["record_count"] == 0 for item in api.list_memory_snapshots(target, session))
    restored = api.restore_memory_snapshot(empty["id"], target, session)
    assert restored["restored"] == 0
    assert api.list_memory(target, session) == []
    try:
        api.create_memory_snapshot({"target_id": target, "session_id": "x" * 129})
        assert False, "overlong session IDs should be rejected"
    except HTTPException as error:
        assert error.status_code == 422
