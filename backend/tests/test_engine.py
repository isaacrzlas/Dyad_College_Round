import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api
from fastapi.testclient import TestClient


def client_at(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "test.sqlite3")
    api.init_db()
    return TestClient(api.app)


def test_vulnerable_attack_has_confirmed_evidence_and_trace(tmp_path, monkeypatch):
    with client_at(tmp_path, monkeypatch) as client:
        response = client.post("/api/campaigns/run", json={"target":"vulnerable", "categories":["Indirect prompt injection"], "max_tests":2, "seed":9})
        assert response.status_code == 200
        campaign = response.json()
        assert campaign["counts"]["confirmed_vulnerability"] == 2
        details = client.get(f"/api/campaigns/{campaign['id']}").json()
        assert details["findings"]
        actions = {e["action_type"] for e in details["traces"][0]["events"]}
        assert {"retrieval", "tool_proposal", "policy_decision", "tool_executed"} <= actions


def test_hardened_blocks_same_attack_and_benign_suite_passes(tmp_path, monkeypatch):
    with client_at(tmp_path, monkeypatch) as client:
        response = client.post("/api/campaigns/run", json={"target":"hardened", "categories":["Indirect prompt injection"], "max_tests":2, "seed":9})
        assert response.json()["counts"]["confirmed_vulnerability"] == 0
        assert response.json()["counts"]["blocked"] == 2
        benign = client.post("/api/regression/run").json()
        assert benign["pass_rate"] == 1.0


def test_policy_gate_blocks_sensitive_but_allows_scoped_tasks():
    assert api.policy_gate("read_customer_record", "support-agent", {"customer_id":"C-1042"})["decision"] == "denied"
    assert api.policy_gate("read_customer_record", "support-agent", {"customer_id":"P-100"})["decision"] == "allowed"
    assert api.policy_gate("send_email", "admin", {"to":"synthetic"})["decision"] == "denied"


def test_validation_persists_comparable_campaigns_and_export(tmp_path, monkeypatch):
    with client_at(tmp_path, monkeypatch) as client:
        result = client.post("/api/defense/validate")
        assert result.status_code == 200
        data = result.json()
        assert data["metrics"]["risk_reduction"] > 0
        assert data["metrics"]["benign_pass_rate"] == 1.0
        report = client.get(f"/api/campaigns/{data['baseline']['id']}/export")
        assert report.status_code == 200
        assert report.json()["report_metadata"]["simulation"] is True


def test_campaign_validation_and_not_found():
    with TestClient(api.app) as client:
        assert client.post("/api/campaigns/run", json={"target":"vulnerable", "max_tests":51}).status_code == 422
        assert client.get("/api/campaigns/missing").status_code == 404
