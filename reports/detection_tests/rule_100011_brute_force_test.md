# Detection Test Report: Rule 100011

## Detection Name
Repeated Failed Login Attempts

## Objective
Detect five or more failed login attempts against the same account within 120 seconds.

## Detection Configuration
- Wazuh Rule ID: 100011
- Severity Level: 10
- Frequency: 5
- Timeframe: 120 seconds
- Parent Rule: 60122
- ATT&CK Technique: T1110.001
- ATT&CK Tactic: Credential Access
- Technique Name: Password Guessing

## Lab Environment
- Windows Agent: DESKTOP-G67LTP0
- Agent ID: 001
- Windows IP: 192.168.23.134
- Wazuh Manager: cyberion-ubuntu

## Test Method
Repeated failed SSH authentication attempts were generated in the controlled Windows lab using a nonexistent username.

## Observed Evidence
- Windows Event ID: 4625
- Target Username: NOUSER
- Caller Process: C:\Windows\System32\OpenSSH\sshd.exe
- Failure Reason: Unknown user name or bad password
- Status: 0xC000006D
- Substatus: 0xC0000064
- Wazuh Alert Rule: 100011
- Alert Level: 10
- Frequency: 5
- Timeframe: 120 seconds
- Dashboard Results: 1 hit

## Result
PASS — The custom Wazuh correlation rule generated a level-10 alert after repeated failed login events.

## Security Note
This was a controlled lab simulation, not evidence of a real-world attack. The source network address was not populated in the captured event.

## Conclusion
Windows Security Event ID 4625 was collected by the Wazuh agent, and custom Rule 100011 successfully correlated repeated failures for the same username.
