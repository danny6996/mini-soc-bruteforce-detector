from collections import Counter
from pathlib import Path

# === Config ===
ALERT_THRESHOLD = 3

log = Path("data/sample_auth.log")
out = Path("reports/report.md")
out.parent.mkdir(exist_ok=True)

ips = Counter()

# === Parse logs ===
for line in log.read_text(encoding="utf-8").splitlines():
    if "Failed password" in line:
        try:
            ip = line.split("from ")[1].split()[0]
            ips[ip] += 1
        except IndexError:
            pass

# === Build report ===
report = []
report.append("# Security Incident Report\n")

# Summary
total_alerts = sum(1 for c in ips.values() if c >= ALERT_THRESHOLD)
report.append("## Summary\n")
report.append(f"- Total failed login attempts: {sum(ips.values())}\n")
report.append(f"- Total detected alerts: {total_alerts}\n\n")

# Alerts
report.append("## Detected Alerts\n")
if total_alerts == 0:
    report.append("- No suspicious activity detected.\n")
else:
    for ip, count in ips.items():
        if count >= ALERT_THRESHOLD:
            report.append(f"- 🚨 **Brute-force suspected** from `{ip}` — {count} failed attempts\n")

# Severity
report.append("\n## Severity Assessment\n")
for ip, count in ips.items():
    if count >= ALERT_THRESHOLD:
        if count >= 6:
            severity = "HIGH"
        elif count >= 4:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        report.append(f"- `{ip}` → **{severity}** severity\n")

# Recommendations
report.append("\n## Recommended Actions\n")
report.append("- Block or rate-limit offending IP addresses\n")
report.append("- Enforce strong password and MFA policies\n")
report.append("- Monitor authentication logs for continued activity\n")
report.append("- Consider fail2ban or similar protection mechanisms\n")

# Save report
out.write_text("".join(report), encoding="utf-8")
print("DONE → reports/report.md (SOC report generated)")
