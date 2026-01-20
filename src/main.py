# Simple SOC Analyst Tool for Sample Apache Access Logs
# Analyzes logs to identify potential security threats and generates a report.
import re
from collections import Counter, defaultdict
from pathlib import Path

# Input & Output paths
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "../logs/apache_access.log"
OUTPUT_FILE = BASE_DIR.parent / "output" / "soc_report.txt"

# Regex to parse Apache access logs
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] "(?P<method>\w+) (?P<url>[^\s]+) [^"]+" (?P<status>\d{3}) \d+ "[^"]*" "(?P<ua>[^"]+)"'
)

# Dictionaries to store log info
ip_requests = Counter()
ip_status = defaultdict(Counter)
ip_user_agents = defaultdict(set)

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = log_pattern.search(line)
        if match:
            ip = match.group("ip")
            status = match.group("status")
            ua = match.group("ua")

            ip_requests[ip] += 1
            ip_status[ip][status] += 1
            ip_user_agents[ip].add(ua)

# Attack Detection Function
def detect_attack(ip):
    requests = ip_requests[ip]
    statuses = ip_status[ip]

    if requests > 300:
        return "🚨 Possible DoS / Crawling (High request volume)"
    elif statuses.get("404", 0) > 20:
        return "⚠️ Possible Brute Force / Recon (Many 404 errors)"
    elif "403" in statuses:
        return "⚠️ Unauthorized Access Attempts"
    return "ℹ️ Normal / Low Risk"

# Generate Report
with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    out.write("==== SOC ANALYST REPORT ====\n\n")

    # Top 5 Suspicious IPs
    out.write("🔎 Top 5 Suspicious IPs:\n")
    for ip, count in ip_requests.most_common(5):
        out.write(f"\nIP: {ip} → {count} requests\n")
        out.write(f"User Agents: {', '.join(list(ip_user_agents[ip])[:2])}\n")  # Show up to 2 UAs
        out.write(f"Status Codes: {dict(ip_status[ip])}\n")
        out.write(f"Analysis: {detect_attack(ip)}\n")

    # Suspicious User Agents (global)
    out.write("\n\n🤖 Suspicious User Agents Detected:\n")
    suspicious_uas = [ua for uas in ip_user_agents.values() for ua in uas
                      if any(bot in ua.lower() for bot in ["bot", "spider", "crawl", "wget", "curl", "python"])]
    for ua in set(suspicious_uas):
        out.write(f"- {ua}\n")

print(f"✅ SOC report generated: {OUTPUT_FILE}")
