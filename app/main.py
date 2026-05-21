import typer
from app.monitor import start_monitor
from app.packet_sniffer import start_sniffing

app = typer.Typer()

@app.command()
def monitor():
    start_monitor()

@app.command()
def sniff():
    start_sniffing()

if __name__ == "__main__":
    app()