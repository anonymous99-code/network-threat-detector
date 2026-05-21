from datetime import datetime

LOG_FILE = "logs/events.log"

def log_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")