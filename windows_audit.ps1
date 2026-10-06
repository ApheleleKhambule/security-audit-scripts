# =========================================================
# windows_audit.ps1 — quick security health check for Windows
# Author: Aphelele Khambule
#
# Checks: listening ports, failed logins (Event ID 4625),
#         local administrators, firewall profiles,
#         Defender status and recently installed updates.
# Usage:  Run PowerShell as Administrator, then:
#         Set-ExecutionPolicy -Scope Process Bypass
#         .\windows_audit.ps1
# Output: audit_report_<computer>_<date>.txt
# =========================================================

$Report = "audit_report_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
$script:Issues = 0
$Lines = New-Object System.Collections.Generic.List[string]

function Out-Line($text) { $Lines.Add($text); Write-Host $text }
function Section($name)  { Out-Line ""; Out-Line "==== $name ====" }
function Warn($text)     { Out-Line "[!] $text"; $script:Issues++ }
function Ok($text)       { Out-Line "[ok] $text" }

Out-Line "Security audit for $env:COMPUTERNAME - $(Get-Date)"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Out-Line "Note: not running as Administrator; some checks will be incomplete." }

# 1. Listening ports
Section "Listening ports"
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Sort-Object LocalPort -Unique |
  ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Out-Line ("TCP {0,-6} {1}" -f $_.LocalPort, $proc)
  }
$risky = @(21, 23, 445, 3389)
$open = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).LocalPort
foreach ($p in $risky) { if ($open -contains $p) { Warn "Port $p is open - check it is needed" } }

# 2. Failed logins in the last 7 days (Event ID 4625)
Section "Failed logins (last 7 days)"
try {
  $fails = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-7) } -ErrorAction Stop
  Out-Line "Failed login events: $($fails.Count)"
  if ($fails.Count -gt 20) { Warn "High number of failed logins - possible password guessing" }
  $fails | ForEach-Object { $_.Properties[5].Value } | Group-Object | Sort-Object Count -Descending |
    Select-Object -First 5 | ForEach-Object { Out-Line ("  {0,-4} attempts on account '{1}'" -f $_.Count, $_.Name) }
} catch {
  Out-Line "No failed logins found, or Security log not readable (run as Administrator)."
}

# 3. Local administrators
Section "Local administrators"
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$admins | ForEach-Object { Out-Line "  $($_.Name)" }
if ($admins.Count -gt 3) { Warn "$($admins.Count) admin accounts - keep admin rights to a minimum" }

# 4. Firewall profiles
Section "Firewall"
Get-NetFirewallProfile | ForEach-Object {
  if ($_.Enabled) { Ok "$($_.Name) profile is on" } else { Warn "$($_.Name) firewall profile is OFF" }
}

# 5. Microsoft Defender
Section "Antivirus (Microsoft Defender)"
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  if ($mp.RealTimeProtectionEnabled) { Ok "Real-time protection is on" } else { Warn "Real-time protection is OFF" }
  $age = ((Get-Date) - $mp.AntivirusSignatureLastUpdated).Days
  if ($age -gt 3) { Warn "Virus definitions are $age days old" } else { Ok "Virus definitions updated $age day(s) ago" }
} catch { Out-Line "Defender status unavailable (another antivirus may be installed)." }

# 6. Recent updates
Section "Windows updates"
$last = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($last.InstalledOn) {
  $days = ((Get-Date) - $last.InstalledOn).Days
  Out-Line "Last update: $($last.HotFixID) installed $days day(s) ago"
  if ($days -gt 30) { Warn "No updates installed in over 30 days" }
}

Section "Summary"
Out-Line "Issues flagged: $script:Issues"

$Lines | Set-Content -Path $Report -Encoding UTF8
Write-Host "`nReport saved to $Report"
