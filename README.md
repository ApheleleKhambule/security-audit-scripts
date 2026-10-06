# Security Audit Scripts

Two scripts that run a quick security health check on a computer and save a plain-text report. One is for Linux (Bash), one is for Windows (PowerShell).

## What they check

| Check | Linux (`linux_audit.sh`) | Windows (`windows_audit.ps1`) |
|---|---|---|
| Open / listening ports | `ss` or `netstat` | `Get-NetTCPConnection`, flags 21, 23, 445, 3389 |
| Failed login attempts | `/var/log/auth.log` or `/var/log/secure`, top source IPs | Security log Event ID 4625, last 7 days |
| Admin accounts | sudo/wheel groups, extra UID 0 accounts | Local Administrators group |
| Updates | `apt` or `dnf` | Last installed hotfix |
| Extra | World-writable files in `/etc`, SSH root login | Firewall profiles, Defender status |

Each problem found is marked `[!]` and counted in the summary.

## How to run

**Linux**
```bash
chmod +x linux_audit.sh
sudo ./linux_audit.sh
```

**Windows** (PowerShell as Administrator)
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\windows_audit.ps1
```

The report is saved in the same folder as `audit_report_<computer>_<date>.txt`.

## What I learned

- Where each operating system records logins and security events
- Why open ports like Telnet (23) and SMB (445) are common attack targets
- Writing the same logic in two scripting languages

## Author

Aphelele Khambule — aphelelekhambule16@gmail.com
