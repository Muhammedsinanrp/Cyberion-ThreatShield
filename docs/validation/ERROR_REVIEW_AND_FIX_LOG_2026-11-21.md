# Error Review and Fix Log — 2026-11-21

**Scope:** GitHub repository tests and static detection-content inventory. **No VM, Wazuh service, production configuration or live agent was changed.**

## Corrections published

1. **Sigma inventory test:** Previously `tests/test_detection_assets.py` counted only `detections/rules/*.yml` (14 files) and required exactly 14, even though the PRD asks for **15+** rules and the repository also has `rules/windows/*.yml` (15 files). The test now checks both locations and enforces **at least 15 rules** (29 in the inspected source).
2. **Rule metadata checks:** Expanded the check across both rule folders to require title, id, status, description, references, tags, logsource, detection, falsepositives, and level; checks unique IDs and a condition in every detection definition. These are **structural** tests, not Sigma CLI semantic verification.
3. **Evidence naming:** Renamed `test_live_wazuh_alert_evidence` to `test_bundled_wazuh_alert_json_structure` and clarified that checking a stored JSON artifact does **not** demonstrate live EventChannel ingestion or rule firing.

## Offline test outcome

Against the available 2026-11-21 source snapshot: `python -m pytest -q` → **32 passed, 1 expected failure (xfail)**.

The expected failure documents a known **quoted PowerShell string false-positive** in an older experimental test pattern; the behavior is **not fixed** merely because the test is marked xfail.

## Unresolved items — do not claim corrected

- Wazuh custom 100120/100127 and other custom rule end-to-end outcomes are **not validated** in native Windows EventChannel context. Live 100010 was independently confirmed with six TEST alerts.
- The three files under `detections/correlation_candidates/` use draft temporal/value-count expressions with `condition` fields. **No portable, backend-compatible Sigma correlation behavior is confirmed.** Validate against an appropriate Sigma correlation schema and backend, then replay sequence data.
- Stored Wazuh alert fixture JSON and synthetic logtest records do **not** substitute for live test evidence.
- The PRD requires every submitted detection rule to be verified against actual telemetry, along with false-positive tuning and traceable case investigations. Those acceptance criteria remain **partially unmet**.
- The repository contains public lab data and screenshots; do not publish additional raw evidence without reviewing identifiers, private data, tokens and rights to redistribute datasets.

## Safe next validation

1. Run `python -m pytest -q -rx` in CI or a development environment using `pytest` and `PyYAML`.
2. Validate complete Sigma rule syntax with your chosen supported `sigma-cli` / pySigma backend (not merely PyYAML parsing).
3. Use an isolated test machine and real event sequences to validate correlation semantics.
4. Attach anonymized, reproducible positive and negative examples per rule, including real false-positive observations.
5. Keep the **PRODUCTION** Wazuh manager untouched until formal deployment approval.

**Status:** Static test corrections committed. **STAGED — NOT PRODUCTION APPROVED.**
