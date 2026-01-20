# backend/app/parser.py
import re
from collections import Counter, defaultdict

LOG_REGEX = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] "(?P<method>\w+) (?P<url>[^\s]+) [^"]+" (?P<status>\d{3}) \d+ "[^"]*" "(?P<ua>[^"]+)"'
)

def analyze_log_lines(lines, suspicious_threshold=10):
    ip_requests = Counter()
    ip_status = defaultdict(Counter)
    ip_user_agents = defaultdict(Counter)
    status_counter = Counter()

    for line in lines:
        m = LOG_REGEX.search(line)
        if not m:
            continue
        ip = m.group("ip")
        status = m.group("status")
        ua = m.group("ua")

        ip_requests[ip] += 1
        ip_status[ip][status] += 1
        ip_user_agents[ip][ua] += 1
        status_counter[status] += 1

    # build results
    top_ips = ip_requests.most_common(10)
    suspicious_ips = [(ip, cnt) for ip, cnt in ip_requests.items() if cnt >= suspicious_threshold]

    # aggregate suspicious UAs (global)
    ua_counter = Counter()
    for ua_map in ip_user_agents.values():
        ua_counter.update(ua_map)
    suspicious_uas = [ (ua, cnt) for ua, cnt in ua_counter.most_common() if any(token in ua.lower() for token in ("bot","spider","wget","curl","python","sqlmap")) ]

    return {
        "top_ips": top_ips,
        "status_summary": dict(status_counter),
        "suspicious_ips": sorted(suspicious_ips, key=lambda x: -x[1]),
        "suspicious_uas": suspicious_uas,
        "ip_status": {ip: dict(ip_status[ip]) for ip,_ in top_ips},
        "ip_user_agents": {ip: dict(ip_user_agents[ip]) for ip,_ in top_ips},
    }
