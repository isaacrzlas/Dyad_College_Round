import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as api


def attack_cases(statuses):
    return [{"status": status} for status in statuses]


def test_defense_improvement_for_success_no_change_and_regression():
    full_success = api.calculate_attack_success(attack_cases(["confirmed_vulnerability"] * 4))
    no_success = api.calculate_attack_success(attack_cases(["blocked"] * 4))
    partial = api.calculate_attack_success(attack_cases(["confirmed_vulnerability", "blocked"]))

    assert api.calculate_defense_improvement(full_success, no_success) == 100.0
    assert api.calculate_defense_improvement(partial, partial) == 0.0
    assert api.calculate_defense_improvement(no_success, partial) == -50.0


def test_attack_success_excludes_inconclusive_skipped_and_errors_from_denominator():
    result = api.calculate_attack_success(attack_cases([
        "confirmed_vulnerability", "inconclusive", "skipped", "errored"
    ]))

    assert result["successful_exploits"] == 1
    assert result["eligible_cases"] == 1
    assert result["success_rate"] == 1.0
    assert result["excluded_inconclusive"] == 1
    assert result["excluded_skipped"] == 1
    assert result["excluded_errored"] == 1


def test_zero_denominators_and_zero_baseline_risk_are_unavailable():
    no_attack_cases = api.calculate_attack_success(attack_cases(["inconclusive", "errored"]))
    assert no_attack_cases["success_rate"] is None
    assert api.calculate_defense_improvement(no_attack_cases, no_attack_cases) is None

    no_regression_cases = api.calculate_regression_metrics(
        [{"id": "r1", "status": "inconclusive"}],
        [{"id": "r1", "kind": "benign"}],
    )
    assert no_regression_cases["pass_rate"] is None
    assert no_regression_cases["eligible_completed"] == 0
    assert no_regression_cases["false_positive_rate"] is None

    zero_risk = api.calculate_severity_risk([])
    increased = api.calculate_severity_risk([{"severity": "Low"}])
    delta = api.calculate_risk_change(zero_risk, increased)
    assert delta["risk_reduction"] == -5
    assert delta["direction"] == "increased"
    assert delta["risk_reduction_percent"] is None
    assert delta["percent_unavailable_reason"] == "Baseline risk is zero."


def test_risk_increase_is_signed_and_severity_breakdown_is_documented():
    before = api.calculate_severity_risk([{"severity": "Low"}])
    after = api.calculate_severity_risk([{"severity": "Critical"}, {"severity": "Medium"}])
    change = api.calculate_risk_change(before, after)

    assert before["score"] == 5
    assert after["score"] == 52
    assert after["contributions"] == {"Critical": 40, "High": 0, "Medium": 12, "Low": 0}
    assert change["risk_reduction"] == -47
    assert change["direction"] == "increased"


def test_regression_rate_counts_only_completed_assertions_and_reports_statuses():
    outcomes = [
        {"id": "b1", "status": "passed"},
        {"id": "b2", "status": "failed"},
        {"id": "b3", "status": "errored"},
        {"id": "b4", "status": "skipped"},
        {"id": "b5", "status": "inconclusive"},
        {"id": "s1", "status": "passed"},
    ]
    definitions = [
        {"id": "b1", "kind": "benign"}, {"id": "b2", "kind": "benign"},
        {"id": "b3", "kind": "benign"}, {"id": "b4", "kind": "benign"},
        {"id": "b5", "kind": "benign"}, {"id": "s1", "kind": "security"},
    ]
    result = api.calculate_regression_metrics(outcomes, definitions)

    assert result["pass_rate"] == 0.6667
    assert result["eligible_completed"] == 3
    assert (result["passed"], result["failed"], result["errored"], result["skipped"], result["inconclusive"]) == (2, 1, 1, 1, 1)
    assert result["benign_pass_rate"] == 0.5
    assert result["false_positive_rate"] == 0.5


def test_validation_freezes_and_persists_the_common_attack_corpus(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB_PATH", tmp_path / "phase5-validation.sqlite3")
    api.init_db()

    result = api.validate_defense()
    metrics = result["metrics"]

    assert metrics["defense_improvement_pp"] == round(
        (metrics["baseline_attack_success_rate"] - metrics["hardened_attack_success_rate"]) * 100, 2
    )
    assert metrics["baseline_attack_success"]["eligible_cases"] == metrics["attack_success_denominator"]
    assert metrics["residual_risk"]["score"] == metrics["risk_after"]
    assert metrics["risk_reduction"] == metrics["risk_before"] - metrics["risk_after"]
    assert (metrics["risk_reduction"] > 0 and metrics["risk_change_direction"] == "reduced") or (metrics["risk_reduction"] == 0 and metrics["risk_change_direction"] == "unchanged") or (metrics["risk_reduction"] < 0 and metrics["risk_change_direction"] == "increased")
    assert result["corpus"]["id"] == metrics["attack_corpus_id"]
    assert result["corpus"]["summary"]["source_count"] == result["corpus"]["summary"]["executed"] + result["corpus"]["summary"]["skipped"]
    assert result["corpus"]["summary"]["inconclusive"] == metrics["hardened_attack_success"]["excluded_inconclusive"]

    saved = api.validation_corpus_detail(result["id"])
    assert saved["status"] == "completed"
    assert saved["corpus_id"] == metrics["attack_corpus_id"]
    assert saved["baseline_target_version"] == result["baseline"]["target_version"]
    assert saved["hardened_target_version"] == result["hardened"]["target_version"]
    assert saved["baseline_manifest"] and saved["hardened_manifest"]
    assert saved["defense_settings"] == result["corpus"]["defense_settings"]
    assert saved["environment_state"]["simulator_documents"]
    assert len(saved["corpus"]) == saved["source_candidate_count"]
    assert all("replay_status" in case["result"] for case in api.replay_detail(result["metrics"]["replay_id"])["cases"])
