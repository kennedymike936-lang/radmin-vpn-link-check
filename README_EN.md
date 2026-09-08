# NetCheck — LAN game connection health check

A read-only PowerShell tool for Windows players who use **Radmin VPN (a.k.a. 蓝盾 "Blue Shield")**
to play Minecraft with friends and suffer from "1-bar" latency.

It measures the peer link, inspects the local network environment, and outputs an
evidence-based report: what's happening now, what it's based on, what to do next.

## What it detects

- Radmin VPN status, peer discovery and live ping latency (direct vs relay suspicion)
- Uplink type (phone tether / Wi-Fi / wired), CGNAT (100.64.0.0/10) and mobile-ISP risk
- NAT mapping behavior via STUN (same local UDP endpoint, multiple servers)
- IPv6 in three steps: local address / external connectivity / peer connectivity
- Firewall allow rules for Radmin
- Evidence for foreign relay connections (only when latency + connection evidence coexist)

## Usage

```powershell
.\NetCheck.bat                # read-only check, saves TXT + JSON (+redacted share JSON)
pwsh -File NetCheck.ps1 -PeerIP 26.x.x.x -PeerIPv6 2409:... 
pwsh -File NetCheck.ps1 -Compare friend-report.json   # two-side comparison
pwsh -File NetCheck.ps1 -Fix     # admin fix mode: preview -> apply -> verify, reversible with -Undo
```

Runs on Windows PowerShell 5.1 and 7+. Read-only by default; `-Fix` requires admin.

## Reliability principles

- NAT type is only reported when measurement evidence is sufficient; otherwise "undetermined"
- "High latency" and "relay suspected" are separate verdicts (relay needs connection evidence)
- IPv6 claims never imply the friend side without a test
- Probe failures are classified (timeout / unreachable / bad data / program error)
- Fix mode never reports success without re-checking each change

## Feedback

See FEEDBACK.md (Chinese) for the report template and case records.
Community thread: https://www.bilibili.com/opus/1244434707826868232

## License

MIT
