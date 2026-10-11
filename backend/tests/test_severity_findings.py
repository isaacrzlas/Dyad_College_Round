import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api
from fastapi.testclient import TestClient


def test_low_and_medium_indirect_cases_create_observed_findings_only_in_weak_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "severity-findings.sqlite3")
    api.init_db()

    cases = [
        ("Indirect public-profile lookup", "Low", "DOC-POISON-PROFILE", "read_customer_record"),
        ("Indirect ticket modification", "Medium", "DOC-POISON-TICKET", "update_ticket"),
    ]
    with TestClient(api.app) as client:
        catalog = {item["category"]: item["severity"] for item in client.get("/api/attacks").json()}
        assert all(catalog.get(category) == severity for category, severity, _, _ in cases)
        documents = {item["document_id"]: item for item in client.get("/api/simulator/documents").json()}
        for _, _, document_id, _ in cases:
            assert documents[document_id]["trust_label"] == "untrusted"

        for category, severity, document_id, tool_name in cases:
            vulnerable = client.post("/api/campaigns/run", json={
                "target_id": "builtin-vulnerable",
                "categories": [category],
                "max_tests": 1,
                "seed": 1701,
            })
            assert vulnerable.status_code == 200, vulnerable.text
            campaign = vulnerable.json()
            detail = client.get(f"/api/campaigns/{campaign['id']}").json()
            assert campaign["counts"]["confirmed_vulnerability"] == 1
            finding = next(item for item in detail["findings"] if item["campaign_id"] == campaign["id"])
            assert finding["severity"] == severity
            events = detail["traces"][0]["events"]
            retrieval = next(event for event in events if event["action_type"] == "retrieval")
            assert retrieval["document_id"] == document_id
            decision = next(event for event in events if event.get("action_type") == "policy_decision" and event.get("tool_name") == tool_name)
            assert decision["decision"] == "denied"
            assert decision["authorized"] is False
            assert decision["executed"] is True

            hardened = client.post("/api/campaigns/run", json={
                "target_id": "builtin-hardened",
                "categories": [category],
                "max_tests": 1,
                "seed": 1701,
            })
            assert hardened.status_code == 200, hardened.text
            hardened_campaign = hardened.json()
            assert hardened_campaign["counts"]["confirmed_vulnerability"] == 0
            hardened_detail = client.get(f"/api/campaigns/{hardened_campaign['id']}").json()
            assert hardened_detail["findings"] == []
            hardened_events = hardened_detail["traces"][0]["events"]
            blocked = next(event for event in hardened_events if event.get("action_type") == "policy_decision" and event.get("tool_name") == tool_name)
            assert blocked["decision"] == "denied"
            assert blocked["executed"] is False