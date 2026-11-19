# Sigma Rule Validation

## Environment

- Sigma CLI: 3.1.0
- pySigma: 1.5.1

## Validation command

sigma check --exclude attacktag --fail-on-issues rules/

## Results

- Parsing errors: 0
- Condition errors: 0
- Validation issues: 0
- Exit code: 0

## Known limitation

The installed pySigma ATT&CK reference dataset does not contain
T1562 or T1562.001.

The attacktag validator was temporarily excluded.

ATT&CK mapping accuracy must be reviewed independently.

## Detection testing status

Sigma structural validation completed.
Detection effectiveness and false-positive testing remain pending.
