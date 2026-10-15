#!/usr/bin/env python3
"""Forward genuine Windows 4625 syslog events to the authenticated SIEM ingest API.

Deploy separately from Git; do not store API keys in this repository.
The collector follows new events only. No attacks or services are started here.
"""
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request

LOG_FILE = os.environ.get("WINDOWS_LOG_FILE", "/var/log/windows/windows11Target.log")
KEY_FILE = os.environ.get("SIEM_DEVICE_KEY_FILE", "/opt/siem-agent/pfsense.key")
SIEM_URL = os.environ.get("SIEM_INGEST_URL", "http://127.0.0.1:5000/api/ingest")
POLL_SECONDS = 0.5

# NXLog's rsyslog output escapes tabs as #011.
FIELD_SEPARATOR = r"(?:#011|\\t|\\s)+"
EVENT_MESSAGE = "An account failed to log on."


def field(text, name):
    match = re.search(
        re.escape(name) + r":" + FIELD_SEPARATOR + r"([^#\\r\\n]+?)(?=(?:\\s{2,}[A-Z][^:]{1,45}:)|$)",
        text,
        re.IGNORECASE,
    )
    return match.group(1).strip() if match else None


def parse_event(line):
    if "Microsoft-Windows-Security-Auditing" not in line or EVENT_MESSAGE not in line:
        return None

    # Match the target account, not the subject (which may be SYSTEM).
    target_section = line.split("Account For Which Logon Failed:", 1)
    target = target_section[1].split("Failure Information:", 1)[0] if len(target_section) > 1 else ""
    match = re.search(r"Account Name:(?:#011|\\s)+([^#\\s]+)", target)
    username = match.group(1) if match else "UNKNOWN"

    # The attacker address may be absent for local/interactive failed logons.
    # Never attribute those attempts to the Windows target's own IP.
    address_match = re.search(
        r"Source Network Address:(?:#011|\\s)+([^#\\s]+)", line, re.IGNORECASE
    )
    source_ip = "UNKNOWN"
    if address_match:
        candidate = address_match.group(1).strip()
        try:
            source_ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            pass

    return {
        "eventType": "WINDOWS_SECURITY_4625",
        "attackType": "FAILED_LOGIN",
        "severity": "MEDIUM",
        "sourceIP": source_ip,
        "username": username,
        "message": "Windows failed logon (Event 4625)",
        "raw": {
            "device": "Windows11Target",
            "eventId": 4625,
            "sourceIPKnown": source_ip != "UNKNOWN",
            "originalLog": line.strip()[:4000],
        },
    }


def send_event(event, api_key):
    payload = json.dumps(event).encode("utf-8")
    request = urllib.request.Request(
        SIEM_URL,
        data=payload,
        headers={"Content-Type": "application/json", "x-api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            print("FORWARDED Windows 4625:", event["username"], "HTTP", response.status, flush=True)
            return True
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print("FORWARD ERROR:", error, flush=True)
        return False


def main():
    with open(KEY_FILE, encoding="utf-8") as key_file:
        api_key = key_file.read().strip()
    if not api_key:
        raise RuntimeError("Device API key is empty")

    print("Watching", LOG_FILE, "(new events only)", flush=True)
    stream = None
    position = 0
    while True:
        try:
            stat = os.stat(LOG_FILE)
            if stream is None:
                stream = open(LOG_FILE, encoding="utf-8", errors="replace")
                position = stat.st_size
                stream.seek(position)
            elif os.fstat(stream.fileno()).st_ino != stat.st_ino or stat.st_size < position:
                stream.close()
                stream = open(LOG_FILE, encoding="utf-8", errors="replace")
                position = 0

            line = stream.readline()
            if not line:
                time.sleep(POLL_SECONDS)
                continue
            position = stream.tell()
            event = parse_event(line)
            if event:
                # Retry on HTTP/network failure rather than silently discarding the event.
                while not send_event(event, api_key):
                    time.sleep(5)
        except (OSError, UnicodeError) as error:
            print("LOG READ ERROR:", error, flush=True)
            if stream:
                stream.close()
                stream = None
            time.sleep(5)


if __name__ == "__main__":
    main()
