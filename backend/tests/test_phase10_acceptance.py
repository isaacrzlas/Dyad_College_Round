import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent_adapter
import app as api
from fastapi.testclient import TestClient


def test_credential_free_guided_demo_and_complete_validation_replay_exports(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "phase10-demo.sqlite3")
    api.init_db()
    monkeypatch.setattr(agent_adapter, "_config", {
        "endpoint": "", "model": "", "api_key": "",
        "baseline_prompt": agent_adapter.DEFAULT_BASELINE_PROMPT,
        "hardened_prompt": agent_adapter.DEFAULT_HARDENED_PROMPT,
    })
    with TestClient(api.app) as client:
        campaign_response = client.post("/api/campaigns/run", json={
            "target": "vulnerable",
            "categories": ["Indirect prompt injection", "Memory poisoning", "Unauthorized tool execution"],
            "max_tests": 6,
            "seed": 1701,
        })
        assert campaign_response.status_code == 200
        demo_campaign = campaign_response.json()
        assert demo_campaign["test_count"] > 0
        assert client.get("/api/settings").json()["model_adapter"]["configured"] is False

        validation_response = client.post("/api/defense/validate", json={})
        assert validation_response.status_code == 200
        validation = validation_response.json()
        metrics = validation["metrics"]
        assert metrics["attack_corpus_id"]
        assert metrics["baseline_attack_success"]["eligible_cases"] > 0
        assert metrics["hardened_attack_success"]["eligible_cases"] > 0
        assert metrics["defense_improvement_pp"] == api.calculate_defense_improvement(
            metrics["baseline_attack_success"], metrics["hardened_attack_success"]
        )
        assert validation["regressions"]["hardened"]["tests"]
        assert any(item.get("kind") == "benign" for item in validation["regressions"]["hardened"]["tests"])

        validation_export_response = client.get(f"/api/validations/{validation['id']}/export")
        assert validation_export_response.status_code == 200
        validation_report = validation_export_response.json()
        assert validation_report["schema_version"] == 1
        assert validation_report["frozen_attack_corpus"]["id"] == metrics["attack_corpus_id"]
        assert len(validation_report["frozen_attack_corpus"]["source_candidates"]) == metrics["corpus_counts"]["source_count"]
        assert len(validation_report["frozen_attack_corpus"]["outcomes"]) == metrics["corpus_counts"]["source_count"]
        discovery_nodes = validation_report["adaptive_discoveries"]["nodes"]
        discovery_ids = {node["id"] for node in discovery_nodes}
        corpus_source_ids = {candidate["source_node_id"] for candidate in validation_report["frozen_attack_corpus"]["source_candidates"]}
        assert corpus_source_ids <= discovery_ids
        assert all(candidate["source_status"] for candidate in validation_report["frozen_attack_corpus"]["source_candidates"])
        assert any(node["depth"] > 0 for node in discovery_nodes), "the validation corpus should include persisted adaptive follow-ups"
        assert validation_report["targets"]["baseline"]["manifest_version"] == metrics["baseline_target_version"]
        assert validation_report["targets"]["hardened"]["manifest_version"] == metrics["hardened_target_version"]
        assert validation_report["metric_definitions"]["defense_improvement_pp"]
        assert validation_report["regressions"]["hardened"]["results"]
        assert "attachment" in validation_export_response.headers.get("content-disposition", "")

        recorded_response = client.post("/api/replay/run", json={
            "source_campaign_id": metrics["baseline_campaign_id"],
            "target_id": "builtin-hardened",
            "mode": "recorded",
        })
        assert recorded_response.status_code == 200
        replay = recorded_response.json()
        assert replay["summary"]["reconstructed"] > 0
        assert replay["summary"]["executed"] == 0
        assert replay["summary"]["target_invocations"] == 0
        replay_export_response = client.get(f"/api/replays/{replay['id']}/export")
        assert replay_export_response.status_code == 200
        replay_report = replay_export_response.json()
        assert replay_report["report_metadata"]["replay_id"] == replay["id"]
        assert replay_report["replay"]["mode"] == "recorded"
        assert len(replay_report["traces"]) == replay["summary"]["reconstructed"]
        assert all(trace["events"] for trace in replay_report["traces"])


def test_defense_improvement_is_100_points_for_all_success_to_all_blocked():
    baseline = api.calculate_attack_success([{"status": "confirmed_vulnerability"} for _ in range(7)])
    hardened = api.calculate_attack_success([{"status": "blocked"} for _ in range(7)])
    assert baseline["success_rate"] == 1.0
    assert hardened["success_rate"] == 0.0
    assert api.calculate_defense_improvement(baseline, hardened) == 100.0
