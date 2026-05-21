from collections import defaultdict
import time

ip_activity = defaultdict(list)

def analyze_connection(ip, port):
    now = time.time()
    ip_activity[ip].append((port, now))

    # keep last 15 seconds
    ip_activity[ip] = [(p, t) for p, t in ip_activity[ip] if now - t < 15]

    ports = [p for p, _ in ip_activity[ip]]

    risk = 0
    tags = []

    # 🚨 Port scan detection
    if len(set(ports)) > 8:
        risk += 60
        tags.append("PORT SCAN")

    # 🚨 Fast connection burst
    if len(ports) > 25:
        risk += 30
        tags.append("HIGH TRAFFIC")

    # classification
    if risk >= 70:
        level = "CRITICAL"
    elif risk >= 40:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return risk, level, tags