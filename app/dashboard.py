from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

from rich.align import Align
from datetime import datetime
import threading
import keyboard

from app.geoip import get_geo_info

console = Console()

events = []
live = None

scroll_offset = 0
MAX_VISIBLE = 14


def load_logo():

    return r"""
███╗   ██╗███████╗████████╗
████╗  ██║██╔════╝╚══██╔══╝
██╔██╗ ██║█████╗     ██║
██║╚██╗██║██╔══╝     ██║
██║ ╚████║███████╗   ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝

   NETWORK THREAT SYSTEM
"""


def build_layout():

    logo = load_logo()

    # 📊 TABLE
    table = Table(
        title="Live Threat Feed",
        expand=True
    )

    table.add_column("Time", style="cyan", width=10)
    table.add_column("IP", style="white")
    table.add_column("Port", style="magenta", width=8)
    table.add_column("Country", style="yellow")
    table.add_column("Risk", style="red", width=6)
    table.add_column("Level", style="green", width=12)
    table.add_column("Tags", style="cyan")

    # 📜 SCROLLING EVENTS
    start = max(0, len(events) - MAX_VISIBLE - scroll_offset)
    end = len(events) - scroll_offset

    visible_events = events[start:end]

    for e in visible_events:

        color = "green"

        if e["level"] == "CRITICAL":
            color = "red"

        elif e["level"] == "SUSPICIOUS":
            color = "yellow"

        table.add_row(
            e["time"],
            str(e["ip"]),
            str(e["port"]),
            e["geo"]["country"],
            str(e["risk"]),
            f"[{color}]{e['level']}[/{color}]",
            ", ".join(e["tags"])
        )

    # 🧱 LAYOUT
    layout = Layout()

    layout.split_column(
        Layout(name="header", size=12),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3)
    )

    # 🧿 HEADER
    layout["header"].update(
    Panel(
        Align.center(
            Text(
                logo,
                style="bold cyan"
            )
        ),
        title="[bold white]NETWORK MONITOR[/bold white]",
        border_style="cyan",
        padding=(1, 2)
    )
)

    # 📦 BODY
    layout["body"].update(
        Panel(
            table,
            title="Threat Monitor",
            border_style="red"
        )
    )

    # ⌨ FOOTER
    footer_text = (
        "↑ Scroll Up    ↓ Scroll Down    "
        f"Showing {len(visible_events)} / {len(events)} Events"
    )

    layout["footer"].update(
        Panel(
            footer_text,
            border_style="green"
        )
    )

    return layout


def keyboard_listener():

    global scroll_offset

    while True:

        if keyboard.is_pressed("up"):

            scroll_offset = min(
                scroll_offset + 1,
                max(0, len(events) - MAX_VISIBLE)
            )

        elif keyboard.is_pressed("down"):

            scroll_offset = max(
                scroll_offset - 1,
                0
            )

        if live:
            live.update(build_layout())


def start_dashboard():

    global live

    if live is None:

        live = Live(
            build_layout(),
            refresh_per_second=4,
            screen=False,
            auto_refresh=True
        )

        live.start()

        # 🎮 KEYBOARD THREAD
        threading.Thread(
            target=keyboard_listener,
            daemon=True
        ).start()


def add_event(ip, port, risk, level, tags):

    global live

    geo = get_geo_info(ip)

    current_time = datetime.now().strftime("%H:%M:%S")

    events.append({
        "time": current_time,
        "ip": ip,
        "port": port,
        "risk": risk,
        "level": level,
        "tags": tags,
        "geo": geo
    })

    # 🧹 LIMIT MEMORY
    if len(events) > 500:
        events.pop(0)

    # 🔄 UPDATE DASHBOARD
    if live: 
        live.update(build_layout())