# Nexus SIEM Windows agent (preview)

Windows x64, administrator installation. Collects new Security, System, Application and Defender events from the local Windows event logs. Existing records are skipped on first initialization. The agent runs as SYSTEM through an explicitly installed startup task named NexusSIEM-Agent.

Download the Windows agent build artifact from GitHub Actions and extract it. In Administrator Windows PowerShell, navigate to the extracted directory and run:

    .\Install.ps1 -IngestUrl https://YOUR-SIEM-HOST/api/ingest

For the isolated development lab only:

    .\Install.ps1 -IngestUrl http://192.168.1.10:5000/api/ingest -AllowLabHttp

Enter the registered device key when prompted. Never commit it. Machine DPAPI and administrator/SYSTEM-only directory permissions protect the stored key. HTTP exposes the key and event contents to the network; use HTTPS outside the isolated lab.

Check status with:

    Get-ScheduledTask -TaskName NexusSIEM-Agent

Check the device last heartbeat and received events in the SIEM dashboard. Heartbeat currently updates on event ingestion, not independently. The agent retries failed submissions and checkpoints successful records; duplicates are possible after interruptions, and Windows log retention limits offline recovery. The current event mapping is basic and does not guarantee attack detection. Only install on authorized devices; event messages may contain personal or sensitive data.

To remove:

    .\Uninstall.ps1

Disable the registered device or rotate its key separately in the dashboard. This preview is unsigned and requires validation before production use.
