from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from rich.console import Console

from app.dashboard import add_event, start_dashboard
from app.ml_analyzer import TrafficMLModel

ml = TrafficMLModel()

console = Console()


def process_packet(packet):

    # Ignore packets without IP layer
    if IP not in packet:
        return

    ip_src = packet[IP].src

    proto = "OTHER"
    port = 0
    tags = []

    # =========================
    # TCP TRAFFIC ANALYSIS
    # =========================
    if TCP in packet:

        proto = "TCP"
        port = packet[TCP].dport

        # Remote access ports
        if port in [22, 23]:
            tags.append("REMOTE ACCESS PORT")

        # HTTP traffic
        if port == 80:
            tags.append("HTTP TRAFFIC (UNENCRYPTED)")

    # =========================
    # UDP TRAFFIC ANALYSIS
    # =========================
    elif UDP in packet:

        proto = "UDP"
        port = packet[UDP].dport

        # DNS queries
        if port == 53:
            tags.append("DNS QUERY")

    # =========================
    # DNS DETECTION
    # =========================
    if packet.haslayer(DNS):
        tags.append("DNS PACKET")

    # =========================
    # PAYLOAD INSPECTION
    # =========================
    if packet.haslayer(Raw):

        try:

            payload = packet[Raw].load.decode(
                errors="ignore"
            )

            if "password" in payload.lower():
                tags.append("POSSIBLE CREDENTIAL LEAK")

        except:
            pass

    # =========================
    # BASE RISK SCORING
    # =========================
    risk = 10 * len(tags)

    # =========================
    # MACHINE LEARNING ANALYSIS
    # =========================
    ml.add_sample(port, risk)

    ml.train()

    ml_result = ml.predict(port, risk)

    if ml_result == "ANOMALY":

        tags.append("AI ANOMALY DETECTED")

        risk += 30

    # =========================
    # THREAT LEVEL
    # =========================
    level = "NORMAL"

    if risk > 50:

        level = "CRITICAL"

    elif risk > 20:

        level = "SUSPICIOUS"

    # =========================
    # SEND EVENT TO DASHBOARD
    # =========================
    add_event(
        ip_src,
        port,
        risk,
        level,
        tags
    )


def start_sniffing():

    console.print(
        "[bold cyan][+] Packet Sniffer Started...[/bold cyan]"
    )

    # START UI
    start_dashboard()

    # START PACKET CAPTURE
    sniff(
        prn=process_packet,
        store=False
    )