import psutil
import time
from app.analyzer import analyze_connection
from app.dashboard import add_event, start_dashboard

def start_monitor():
    print("[+] Advanced Network Threat Console Running...\n")

    from app.dashboard import start_dashboard

    start_dashboard()

    seen = set()

    while True:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:
            if conn.raddr:
                ip = conn.raddr.ip
                port = conn.raddr.port

                key = f"{ip}:{port}"

                if key not in seen:
                    seen.add(key)

                    risk, level, tags = analyze_connection(ip, port)

                    add_event(ip, port, risk, level, tags)

        time.sleep(2)