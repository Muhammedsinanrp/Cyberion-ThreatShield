import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "detections" / "rules"
CORRELATION_DIR = ROOT / "detections" / "correlation_candidates"


def test_sigma_rule_count():
    assert len(list(SIGMA_DIR.glob("*.yml"))) == 14


def test_sigma_rule_required_fields():
    for path in SIGMA_DIR.glob("*.yml"):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))

        assert isinstance(rule, dict), path.name

        for field in ("title", "id", "logsource", "detection"):
            assert field in rule, f"{path.name}: missing {field}"


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


def test_live_wazuh_alert_evidence():
    path = ROOT / "docs/validation/defender_tampering_alert.json"
    alert = json.loads(path.read_text(encoding="utf-8"))

    assert str(alert["rule"]["id"]) == "100120"
    assert int(alert["rule"]["level"]) == 10
    assert "agent" in alert
    assert "data" in alert
