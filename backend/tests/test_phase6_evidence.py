import copy
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api
import agent_adapter
from redaction import REDACTED, redact_data


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "agentbreak-phase6.sqlite3")
    api.init_db()


def test_redaction_covers_prompts_model_output_tool_arguments_and_campaign_export(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    secret = "sk-proj-SYNTHETIC-REDTEAM-CREDENTIAL-123456789"
    manifest = copy.deepcopy(api.DEFAULT_POLICY_MANIFEST)
    manifest["schema_version"] = 1
    manifest["adapter"] = "simulator"
    manifest["redaction"] = {"sensitive_values": [secret], "sensitive_fields": ["private_note"]}
    target = api.create_target(api.TargetInput(name="Redaction fixture", adapter="simulator", manifest=manifest))
    monkeypatch.setattr(api, "public_config", lambda: {"configured": True})
    monkeypatch.setattr(api, "generate_candidates", lambda *args, **kwargs: ([{"category": "Direct prompt injection", "prompt": f"Please test {secret}", "reason": f"Model proposed {secret}"}], "model-generated"))
    campaign = api.run_campaign(api.CampaignRequest(target_id=target["id"], categories=["Direct prompt injection"], max_tests=1, seed=91))
    tree = api.campaign_tree(campaign["id"])
    assert secret not in json.dumps(tree)
    assert REDACTED in json.dumps(tree)
    trace_id = campaign["tests"][0]["trace_id"]
    trace = api.get_trace(trace_id)
    input_event = next(item for item in trace["events"] if item["action_type"] == "attacker_input")
    assert input_event["redaction_applied"] is True
    assert secret not in json.dumps(trace)

    extra_id = "phase6-redaction-evidence"
    raw_events = [
        {"timestamp": api.now(), "campaign_id": extra_id, "test_id": "test-redact", "step": 1, "action_type": "attacker_input", "input": f"input={secret}"},
        {"timestamp": api.now(), "campaign_id": extra_id, "test_id": "test-redact", "step": 2, "action_type": "model_response", "content": f"The model returned {secret}"},
        {"timestamp": api.now(), "campaign_id": extra_id, "test_id": "test-redact", "step": 3, "action_type": "tool_proposal", "arguments": {"Authorization": f"Bearer {secret}", "customer_id": "C-1042"}},
    ]
    api.persist_campaign("vulnerable", 91, [{"test_id": "test-redact", "trace_id": "trace-redact", "status": "blocked", "prompt": secret}], [("trace-redact", "test-redact", raw_events)], [], extra_id, target_id=target["id"], manifest=manifest)
    persisted = api.get_trace("trace-redact")
    assert secret not in json.dumps(persisted)
    assert all(item.get("redaction_applied") for item in persisted["events"])
    argument_event = next(item for item in persisted["events"] if item["action_type"] == "tool_proposal")
    assert argument_event["arguments"]["Authorization"] == REDACTED
    export = api.export_campaign(extra_id)
    assert secret.encode() not in export.body
    assert REDACTED.encode() in export.body
    written = api.write_memory({"target_id": target["id"], "session_id": "redacted", "key": "session.secret", "value": secret})
    assert api.list_memory(target["id"], "redacted")[0]["value"] == REDACTED
    assert written["version"] == 1


def test_redactor_handles_common_credential_shapes_and_marked_fields():
    source = {"Authorization": "Bearer synthetic-authorization-token-123", "api_key": "plain-test-key", "message": "Use sk-proj-this-is-a-synthetic-key-value-1234", "private_note": "marked value"}
    redacted, paths = redact_data(source, sensitive_fields={"private_note"})
    assert "synthetic-authorization-token-123" not in json.dumps(redacted)
    assert "plain-test-key" not in json.dumps(redacted)
    assert "sk-proj-this-is-a-synthetic-key-value-1234" not in json.dumps(redacted)
    assert redacted["private_note"] == REDACTED
    assert paths


def test_provider_credentials_are_never_returned_in_public_configuration(monkeypatch):
    secret = "synthetic-provider-credential-value-987654321"
    monkeypatch.setitem(agent_adapter._config, "api_key", secret)
    monkeypatch.setitem(agent_adapter._config, "endpoint", f"https://provider.example/v1?api_key={secret}")
    config = agent_adapter.public_config()
    assert secret not in json.dumps(config)
    assert config["api_key_configured"] is True
    assert "[REDACTED]" in config["endpoint"]


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_backend(db_path, backend_dir):
    port = _free_port()
    env = os.environ.copy()
    env["AGENTBREAK_DB"] = str(db_path)
    process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port)], cwd=backend_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Backend exited during startup with code {process.returncode}")
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=1) as response:
                if response.status == 200:
                    return process, base
        except (OSError, urllib.error.URLError):
            time.sleep(0.2)
    process.terminate()
    raise TimeoutError("Backend did not become ready")


def _stop_backend(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _request(base, path, method="GET", payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(base + path, data=body, method=method, headers={"Content-Type": "application/json"} if body is not None else {})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode())


def test_sqlite_evidence_survives_controlled_backend_restart(tmp_path):
    backend_dir = Path(api.__file__).resolve().parent
    database = tmp_path / "restart-verification.sqlite3"
    first_process, base = _start_backend(database, backend_dir)
    try:
        target = _request(base, "/api/targets/builtin-hardened")
        created = _request(base, "/api/targets", "POST", {"name": "Restart persistence target", "adapter": "simulator", "manifest": target["manifest"]})
        session_id = "phase6-restart-session"
        _request(base, "/api/memory", "POST", {"target_id": "builtin-vulnerable", "session_id": session_id, "key": "session.note", "value": "persisted evidence", "trust_label": "untrusted"})
        campaign = _request(base, "/api/campaigns/run", "POST", {"target_id": "builtin-vulnerable", "categories": ["Unauthorized tool execution"], "max_tests": 1, "seed": 707, "session_id": session_id})
        finding_id = next(item["finding_id"] for item in campaign["tests"] if item.get("finding_id"))
        trace_id = campaign["tests"][0]["trace_id"]
        validation = _request(base, "/api/defense/validate", "POST", {})
        validation_id = validation["id"]
        replay_id = validation["metrics"]["replay_id"]
        baseline_run = validation["regressions"]["baseline"]["id"]
        hardened_run = validation["regressions"]["hardened"]["id"]
        baseline_campaign = validation["metrics"]["baseline_campaign_id"]
        hardened_campaign = validation["metrics"]["hardened_campaign_id"]
        assert _request(base, f"/api/replays/{replay_id}")["cases"]
        assert _request(base, f"/api/regression/runs/{baseline_run}")["results"]
        assert _request(base, f"/api/regression/runs/{hardened_run}")["results"]
    finally:
        _stop_backend(first_process)

    second_process, base = _start_backend(database, backend_dir)
    try:
        assert _request(base, f"/api/targets/{created['id']}")["version"] == created["version"]
        assert _request(base, f"/api/campaigns/{campaign['id']}")["tests"]
        assert _request(base, f"/api/campaigns/{campaign['id']}/tree")["nodes"]
        assert _request(base, f"/api/campaigns/{baseline_campaign}")["tests"]
        assert _request(base, f"/api/campaigns/{hardened_campaign}")["tests"]
        assert _request(base, f"/api/findings/{finding_id}")["trace"]["events"]
        assert _request(base, f"/api/traces/{trace_id}")["events"]
        assert _request(base, f"/api/memory?target_id=builtin-vulnerable&session_id={session_id}")[0]["value"] == "persisted evidence"
        assert _request(base, f"/api/validations/{validation_id}/corpus")["status"] == "completed"
        assert _request(base, f"/api/validations/{validation_id}/export")["schema_version"] == 1
        assert _request(base, f"/api/replays/{replay_id}")["cases"]
        assert _request(base, f"/api/regression/runs/{baseline_run}")["results"]
        assert _request(base, f"/api/regression/runs/{hardened_run}")["results"]
    finally:
        _stop_backend(second_process)
