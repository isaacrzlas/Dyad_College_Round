import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "agentbreak-phase2.sqlite3")
    api.init_db()


def test_seeded_targets_and_regressions_are_ready(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    targets = api.list_targets()
    assert {t["id"] for t in targets} >= {"builtin-vulnerable", "builtin-hardened"}
    suite = api.regression_run()
    assert suite["executed"] >= 15
    assert suite["failed"] == 0


def test_campaign_persists_adaptive_tree_and_memory_versions(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    result = api.campaign_run(api.CampaignRequest(target="vulnerable", categories=["Memory poisoning"], max_tests=4, seed=13, session_id="test-session"))
    tree = api.campaign_tree(result["id"])
    assert tree["nodes"]
    assert any(n["generation_method"] == "signal-guided-adaptive" for n in tree["nodes"])
    memory = api.list_memory("builtin-vulnerable", "test-session")
    assert memory and memory[0]["trust_label"] == "untrusted"
    history = api.memory_history("builtin-vulnerable", "test-session")
    assert history
    assert any(e["action_type"] == "memory_snapshot" for e in api.get_trace(result["tests"][0]["trace_id"])["events"])
    hardened = api.campaign_run(api.CampaignRequest(target="hardened", target_id="builtin-hardened", categories=["Memory poisoning"], max_tests=2, seed=14, session_id="hardened-session"))
    assert hardened["counts"]["blocked"] == hardened["test_count"]
    assert api.list_memory("builtin-hardened", "hardened-session") == []


def test_frozen_recorded_replay_preserves_source_cases(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    baseline = api.campaign_run(api.CampaignRequest(target="vulnerable", max_tests=6, seed=22))
    data = api.run_replay({"source_campaign_id":baseline["id"], "target_id":"builtin-hardened", "mode":"recorded"})
    assert data["summary"]["source_count"] == data["summary"]["executed"]
    assert data["summary"]["blocked"] > 0
    assert api.replay_detail(data["id"])["cases"]


def test_defense_validation_uses_same_frozen_attack_corpus(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    result = api.validate_defense()
    metrics = result["metrics"]
    assert metrics["frozen_corpus_size"] == metrics["attack_executed"]
    assert metrics["regression_executed"] >= 15
    replay = api.replay_detail(metrics["replay_id"])
    assert len(replay["cases"]) == metrics["frozen_corpus_size"]


def test_target_validation_audit_and_memory_snapshot_restore(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    manifest = {"schema_version":1,"mode":"hardened","tools":[{"name":"send_email","enabled":True,"risk":"high","roles":[],"permission":"email:send","scope":"*"}],"policy":{}}
    target = api.create_target(api.TargetInput(name="Misconfigured test", adapter="simulator", manifest=manifest))
    audit = api.run_target_audit(target["id"])
    assert audit["finding_count"] >= 3
    api.write_memory({"target_id":target["id"],"session_id":"s1","key":"note","value":"before","trust_label":"untrusted"})
    snapshot = api.create_memory_snapshot({"target_id":target["id"],"session_id":"s1"})
    api.write_memory({"target_id":target["id"],"session_id":"s1","key":"note","value":"after","trust_label":"untrusted"})
    restored = api.restore_memory_snapshot(snapshot["id"])
    assert restored["restored"] == 1
    records = api.list_memory(target["id"], "s1")
    assert records[0]["value"] == "before"
