# Windows failed-login collector (development branch)

The existing Ubuntu rsyslog configuration writes NXLog messages to
`/var/log/windows/windows11Target.log`. The Python collector in
`agents/windows-collector.py` follows **new** log lines and forwards
Windows failed-logon messages to the authenticated `POST /api/ingest` API.

## Before deploying

1. Run the offline parser tests:
   `python3 -m unittest discover -s tests -p 'test_windows_collector.py'`.
2. Review the registered device API key and ensure it is authorized for Windows
   ingestion; a key issued for a pfSense-only device may misattribute events.
3. Confirm NXLog is actively forwarding current Security events, including
   Event 4625, and the backend is reachable locally.
4. Check the Windows target's Security event audit policy and logon type.
   A local interactive failure (Logon Type 2) often has no remote source IP;
   such an event should be stored but must **not** count toward an
   attacker-IP brute-force threshold.
5. Review service hardening, log rotation, and permissions before enabling
   a long-running collector. Do not commit API keys.

## Known limits

- A failed-logon message is evidence of authentication failure, not proof
  of a brute-force attack. Five failures within two minutes from a known
  remote source trigger the existing supplementary detector.
- The existing detector uses in-memory counters and loses its window on
  backend restart. It does not deduplicate retransmitted log events.
- HTTP ingest success and an alert on the dashboard still require
  end-to-end verification on the actual Ubuntu and Windows hosts.
- The collector is **not** installed or enabled merely by committing it.
- Controlled Kali testing must be limited to lab hosts you own or are
  authorised to test. Flood testing is monitor-only; no automatic blocking.

## Intended lab flow

Windows Security log → NXLog → Ubuntu rsyslog TCP/514 →
Windows collector → `/api/ingest` → security event →
brute-force alert → SOC dashboard.

Do not start Hydra or other traffic-generation tools until the receiving
pipeline and source attribution have been verified.
