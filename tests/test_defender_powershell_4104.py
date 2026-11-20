import re
import xml.etree.ElementTree as ET
from pathlib import Path

RULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "rules/wazuh/candidates/defender_tampering_powershell_4104.xml"
)


def load_rule():
    root = ET.parse(RULE_PATH).getroot()
    rule = root.find("rule")
    return rule, re.compile(rule.find("field").text)


def test_rule_metadata():
    rule, _ = load_rule()
    assert rule.attrib["id"] == "100123"
    assert rule.findtext("if_sid") == "91802"
    assert rule.find("field").attrib["name"] == "win.eventdata.scriptBlockText"


def test_detects_suspicious_command_text():
    _, pattern = load_rule()

    assert pattern.search(
        "Set-MpPreference -DisableRealtimeMonitoring $true"
    )
    assert pattern.search(
        "Set-MpPreference -DisableRealtimeMonitoring 1"
    )


def test_ignores_false_setting():
    _, pattern = load_rule()

    assert not pattern.search(
        "Set-MpPreference -DisableRealtimeMonitoring $false"
    )


def test_ignores_unrelated_command():
    _, pattern = load_rule()

    assert not pattern.search("Get-MpPreference")


def test_ignores_quoted_command_without_trailing_space():
    _, pattern = load_rule()

    assert not pattern.search(
        "Write-Output 'Set-MpPreference -DisableRealtimeMonitoring $true'"
    )


def test_known_false_positive_single_quotes():
    _, pattern = load_rule()

    command = (
        "Write-Output "
        "'Set-MpPreference -DisableRealtimeMonitoring $true '"
    )

    assert not pattern.search(command)


def test_known_false_positive_double_quotes():
    _, pattern = load_rule()

    command = (
        'Write-Output '
        '"Set-MpPreference -DisableRealtimeMonitoring $true "'
    )

    assert not pattern.search(command)
