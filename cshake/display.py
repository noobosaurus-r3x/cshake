from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from time import sleep
from collections import OrderedDict
from typing import List, Tuple, Any, Dict

console = Console()

def create_panel(content: Any, title: str, style: str) -> Panel:
    return Panel(content, title=title, border_style=style)

def build_table(title: str, columns: List[Tuple[str, str]], rows: List[List[str]]) -> Table:
    table = Table(title=title)
    for col, justify in columns:
        table.add_column(col, justify=justify)
    for row in rows:
        table.add_row(*row)
    return table

def format_subject_issuer(data: Dict[str, str]) -> str:
    return ", ".join([f"{k}={v}" for k, v in data.items()])

def display_summary(chain: List[Any], cipher_used: str, time_s: float,
                    ip_addr: str, alerts: List[str], domain: str) -> None:
    rows = [
        ["Domain", domain],
        ["Server IP", ip_addr],
        ["Cipher", cipher_used],
        ["Connection Time (s)", f"{time_s:.3f}"],
        ["Certificates", str(len(chain))],
        ["Alerts", str(len(alerts))],
    ]
    table = build_table("Connection Summary", [("Field", "left"), ("Value", "left")], rows)
    console.print(create_panel(table, "Connection Summary", "magenta"))

def display_general_info(chain: List[Any], cipher_used: str, time_s: float, ip_addr: str) -> None:
    leaf = chain[0]
    rows = [
        ["Server IP", str(ip_addr)],
        ["Selected Cipher", str(cipher_used)],
        ["Connection Time (s)", f"{time_s:.3f}"],
        ["Leaf Cert CN", leaf.subject.get("CN", "N/A")],
        ["Leaf Cert Issuer", format_subject_issuer(leaf.issuer)],
        ["Trust Status", "Unknown (no get_verify_result())"],
    ]
    table = build_table("SSL Connection Details", [("Field", "left"), ("Value", "left")], rows)
    console.print(create_panel(table, "SSL Connection Details", "blue"))

def build_cert_chain_table(chain: List[Any], minimal: bool) -> Table:
    cols = [("Index", "left"), ("Subject", "left"), ("Issuer", "left"),
            ("Not Before", "left"), ("Not After", "left")]
    if not minimal:
        cols.extend([("Days Left", "right"), ("Fingerprint (SHA256)", "left")])
    table = Table(title="Certificate Chain Details")
    for col, justify in cols:
        table.add_column(col, justify=justify)
    from cshake.utils import compute_days_left, get_cert_fingerprint
    for entry in chain:
        row = [
            str(entry.index),
            format_subject_issuer(entry.subject),
            format_subject_issuer(entry.issuer),
            entry.not_before,
            entry.not_after,
        ]
        if not minimal:
            row.append(compute_days_left(entry.not_after))
            row.append(get_cert_fingerprint(entry.cert_obj))
        table.add_row(*row)
    return table

def display_chain_info(chain: List[Any], minimal: bool = False) -> None:
    table = build_cert_chain_table(chain, minimal)
    console.print(create_panel(table, "Certificate Chain Details", "cyan"))

def display_security_alerts(alerts: List[str]) -> None:
    critical = [a for a in alerts if not a.startswith("OCSP Info:")]
    info_alerts = [a for a in alerts if a.startswith("OCSP Info:")]
    
    if critical:
        text = "\n".join("- " + a for a in critical)
        console.print(create_panel(Text(text, style="bold red"), "Critical Alerts", "red"))
    
    if info_alerts:
        text = "\n".join("- " + a for a in info_alerts)
        console.print(create_panel(Text(text, style="bold yellow"), "Informational Alerts", "yellow"))

def display_raw_curl_output(curl_output: str) -> None:
    ssl_lines, http_lines, err_lines, gen_lines = [], [], [], []
    for line in curl_output.splitlines():
        low = line.lower()
        if any(x in low for x in ["ssl", "tls", "handshake"]):
            ssl_lines.append(Text(line, style="bold green"))
        elif low.startswith("<") or low.startswith(">") or "http" in low:
            http_lines.append(Text(line, style="bold cyan"))
        elif any(x in low for x in ["error", "failed", "alert"]):
            err_lines.append(Text(line, style="bold red"))
        else:
            gen_lines.append(Text(line, style="white"))
    for title, items, color in [
        ("🔒 SSL/TLS Details", ssl_lines, "green"),
        ("🌐 HTTP Details", http_lines, "cyan"),
        ("❗ Errors / Alerts", err_lines, "red"),
        ("📄 General Details", gen_lines, "yellow"),
    ]:
        if items:
            content = "\n".join(str(i) for i in items)
            console.print(create_panel(Text(content, style=color), title, color))

def display_handshake_analysis(handshake_data: OrderedDict) -> None:
    colors = {"success": "green", "failure": "red", "pending": "yellow", "skipped": "dim"}
    icons = {"success": "✅", "failure": "❌", "pending": "⏳", "skipped": "🚫"}
    table = Table(title="Handshake Analysis Summary")
    table.add_column("Stage", style="bold cyan")
    table.add_column("Status", justify="center")
    for stage_label, info in handshake_data.items():
        status = info["status"]
        table.add_row(stage_label, f"[{colors.get(status)}]{icons.get(status)} {status}[/{colors.get(status)}]")
    console.print(create_panel(table, "Handshake Analysis Summary", "green"))

def visualize_handshake_ascii(handshake_data: OrderedDict) -> None:
    from rich.live import Live
    def generate_table() -> Table:
        icons = {"success": "✅", "failure": "⛔", "pending": "⚠️", "skipped": "🛑"}
        colors = {"success": "green", "failure": "red", "pending": "yellow", "skipped": "dim"}
        tbl = Table(title="TLS Handshake Stages")
        tbl.add_column("Stage")
        tbl.add_column("Direction", justify="center")
        tbl.add_column("Status", justify="center")
        for label, val in handshake_data.items():
            direction_symbol = "→" if val["direction"] == "OUT" else "←"
            tbl.add_row(label,
                        f"{direction_symbol} {val['direction']}",
                        f"[{colors.get(val['status'], 'white')}]{icons.get(val['status'], '❓')} {val['status']}[/{colors.get(val['status'], 'white')}]")
        return tbl
    with Live(generate_table(), console=console, refresh_per_second=2):
        for label, val in handshake_data.items():
            sleep(0.3)
            if val["status"] == "pending":
                val["status"] = "success"
            console.log(f"Processed stage: {label}")
