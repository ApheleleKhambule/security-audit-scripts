#!/usr/bin/env bash
# =========================================================
# linux_audit.sh — quick security health check for Linux
# Author: Aphelele Khambule
#
# Checks: listening ports, failed logins, admin (sudo) users,
#         pending updates, world-writable files in /etc,
#         and SSH root-login setting.
# Usage:  sudo ./linux_audit.sh            (prints + saves report)
# Output: audit_report_<hostname>_<date>.txt
# =========================================================

set -u
REPORT="audit_report_$(hostname)_$(date +%Y%m%d_%H%M).txt"
ISSUES=0

section() { printf '\n==== %s ====\n' "$1"; }
warn()    { printf '[!] %s\n' "$1"; ISSUES=$((ISSUES + 1)); }
ok()      { printf '[ok] %s\n' "$1"; }

{
  echo "Security audit for $(hostname) — $(date)"
  [ "$(id -u)" -ne 0 ] && echo "Note: not running as root; some checks will be incomplete."

  # 1. Listening network ports
  section "Listening ports"
  if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | awk 'NR>1 {print $1, $5}' | sort -u
  else
    netstat -tuln 2>/dev/null | awk 'NR>2 {print $1, $4}'
  fi

  # 2. Failed login attempts
  section "Failed login attempts"
  LOG=""
  for f in /var/log/auth.log /var/log/secure; do [ -r "$f" ] && LOG="$f" && break; done
  if [ -n "$LOG" ]; then
    FAILS=$(grep -c "Failed password" "$LOG")
    echo "Failed password attempts in $LOG: $FAILS"
    [ "$FAILS" -gt 20 ] && warn "High number of failed logins — possible brute-force attempt"
    echo "Top source IPs:"
    grep "Failed password" "$LOG" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
      | awk '{print $2}' | sort | uniq -c | sort -rn | head -5
  else
    echo "Auth log not readable (try running with sudo)."
  fi

  # 3. Users with admin rights
  section "Admin (sudo/wheel) users"
  for grp in sudo wheel admin; do
    getent group "$grp" >/dev/null && echo "$grp: $(getent group "$grp" | cut -d: -f4)"
  done
  UID0=$(awk -F: '$3==0 {print $1}' /etc/passwd | grep -v '^root$')
  [ -n "$UID0" ] && warn "Accounts other than root with UID 0: $UID0" || ok "Only root has UID 0"

  # 4. Pending updates
  section "Pending updates"
  if command -v apt >/dev/null 2>&1; then
    COUNT=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
    echo "Upgradable packages: $COUNT"
    [ "$COUNT" -gt 0 ] && warn "$COUNT packages need updating (sudo apt update && sudo apt upgrade)"
  elif command -v dnf >/dev/null 2>&1; then
    dnf check-update -q >/dev/null; [ $? -eq 100 ] && warn "Updates available (sudo dnf upgrade)" || ok "System up to date"
  else
    echo "Package manager not recognised; skipped."
  fi

  # 5. World-writable files in /etc
  section "World-writable files in /etc"
  WW=$(find /etc -xdev -type f -perm -0002 2>/dev/null)
  [ -n "$WW" ] && { warn "World-writable files found:"; echo "$WW"; } || ok "None found"

  # 6. SSH root login
  section "SSH configuration"
  if [ -r /etc/ssh/sshd_config ]; then
    if grep -Eiq '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config; then
      warn "SSH allows direct root login (set PermitRootLogin no)"
    else
      ok "Direct root login over SSH is not enabled"
    fi
  else
    echo "sshd_config not found; SSH server probably not installed."
  fi

  section "Summary"
  echo "Issues flagged: $ISSUES"
} | tee "$REPORT"

echo
echo "Report saved to $REPORT"
