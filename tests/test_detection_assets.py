import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "detections" / "rules"
SECOND_SIGMA_DIR = ROOT / "rules" / "windows"
CORRELATION_DIR = ROOT / "detections" / "correlation_candidates"


def all_sigma_files():
    return sorted(SIGMA_DIR.glob("*.yml")) + sorted(SECOND_SIGMA_DIR.glob("*.yml"))


def test_sigma_rule_count():
    assert len(all_sigma_files()) >= 15, "PRD requires at least 15 detection rules"


def test_sigma_rule_required_fields():
    identifiers = set()
    for path in all_sigma_files():
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))

        assert isinstance(rule, dict), path.name

        for field in ("title", "id", "status", "description", "references",
                      "tags", "logsource", "detection", "falsepositives", "level"):
            assert field in rule, f"{path.name}: missing {field}"
        assert rule["id"] not in identifiers, f"Duplicate Sigma ID: {rule['id']}"
        identifiers.add(rule["id"])
        assert isinstance(rule["detection"], dict), path.name
        assert isinstance(rule["logsource"], dict), path.name
        assert "condition" in rule["detection"], path.name


def test_correlation_candidates_preserved():
    assert len(list(CORRELATION_DIR.glob("*.yml"))) == 3


def test_sample_telemetry_valid_json():
    paths = [
        ROOT / "data/sample_telemetry/sysmon_sample_events.json",
        ROOT / "data/sample_telemetry/win_security_sample_events.json",
    ]

    for path in paths:
        events = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(events, list), path.name
        assert len(events) > 0, path.name


def test_bundled_wazuh_alert_json_structure():
    """Check a stored JSON artifact; does NOT attest to live rule execution."""
    path = ROOT / "docs/validation/defender_tampering_alert.json"
    alert = json.loads(path.read_text(encoding="utf-8"))

    assert str(alert["rule"]["id"]) == "100120"
    assert int(alert["rule"]["level"]) == 10
    assert "agent" in alert
    assert "data" in alert
