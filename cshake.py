#!/usr/bin/env python3

import argparse
import subprocess
import socket
import re
import sys
from urllib.parse import urlparse
from time import sleep
from datetime import datetime
from collections import OrderedDict
import json

import validators
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

console = Console()


###############################################################################
#                               CORE LOGIC                                    #
###############################################################################

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced TLS Handshake Analysis without get_verify_result() usage. "
                    "Ephemeral detection for TLS 1.3, partial OCSP/CRL checks, "
                    "and optional JSON/YAML output."
    )
    parser.add_argument("url", help="Target URL (must be HTTPS)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show raw cURL output")
    parser.add_argument("-r", "--realtime", action="store_true",
                        help="Real-time cURL-based handshake")
    parser.add_argument("-a", "--ascii", action="store_true",
                        help="ASCII animation after final handshake analysis")
    parser.add_argument("--tlsv", choices=["1.2", "1.3"], default=None,
                        help="Force TLS version")
    parser.add_argument("-o", "--output-format", choices=["json", "yaml"],
                        help="Output final results in JSON or YAML")
    return parser.parse_args()


def parse_and_validate_url(url_str: str):
    if not url_str or not isinstance(url_str, str):
        raise ValueError("URL must be a non-empty string.")
    parsed = urlparse(url_str.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("URL scheme must be HTTPS.")
    if not validators.url(url_str):
        raise ValueError("Invalid URL.")
    domain = parsed.netloc
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain, url_str.strip()


def run_curl_single_shot(url_str: str, timeout: int = 15) -> str:
    cmd = ["curl", "-vvv", "--silent", "--output", "/dev/null", url_str]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    _, err = process.communicate(timeout=timeout)
    if process.returncode != 0:
        raise RuntimeError(f"curl failed: {err}")
    return err


def run_curl_realtime(url_str: str) -> str:
    stages = [
        ("Client Hello", ["client hello"]),
        ("Server Hello", ["server hello"]),
        ("Encrypted Extensions", ["encrypted extensions"]),
        ("Certificate", ["certificate"]),
        ("CERT Verify", ["cert verify"]),
        ("Change Cipher Spec", ["change cipher spec"]),
        ("Finished", ["finished"]),
        ("New Session Ticket", ["new session ticket"]),
    ]
    stage_data = OrderedDict()
    for stage_label, _ in stages:
        direction = "OUT" if any(
            x in stage_label.lower() for x in ["client", "change cipher", "finished"]
        ) else "IN"
        stage_data[stage_label] = {"direction": direction, "status": "pending"}

    cmd = ["curl", "-vvv", "--silent", "--output", "/dev/null", url_str]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True
    )
    full_output = []
    stage_index = 0

    def make_table():
        t = Table(title="Real-Time TLS Handshake", header_style="bold cyan")
        t.add_column("Stage")
        t.add_column("Direction", justify="center")
        t.add_column("Status", justify="center")

        icons = {"pending": "⏳", "success": "✅", "failure": "❌", "skipped": "🚫"}
        colors = {"pending": "yellow", "success": "green",
                  "failure": "red", "skipped": "dim"}
        for k, v in stage_data.items():
            icon = icons.get(v["status"], "❓")
            color = colors.get(v["status"], "white")
            t.add_row(
                k,
                v["direction"],
                f"[{color}]{icon} {v['status']}[/{color}]"
            )
        return t

    with Live(make_table(), console=console, refresh_per_second=10) as live:
        while True:
            line = process.stderr.readline()
            if line:
                line_stripped = line.rstrip("\n")
                full_output.append(line_stripped)
                lower_line = line_stripped.lower()
                if "alert" in lower_line or "error" in lower_line:
                    if stage_index < len(stages):
                        current_stage = stages[stage_index][0]
                        stage_data[current_stage]["status"] = "failure"
                if stage_index < len(stages):
                    st_name, triggers = stages[stage_index]
                    for trig in triggers:
                        if trig in lower_line:
                            stage_data[st_name]["status"] = "success"
                            stage_index += 1
                            break
                live.update(make_table())
            elif process.poll() is not None:
                break

    return "\n".join(full_output)


def parse_curl_handshake(output: str) -> OrderedDict:
    initial_stages = OrderedDict({
        "Client Hello": {"direction": "OUT", "status": "pending"},
        "Server Hello": {"direction": "IN", "status": "pending"},
        "Encrypted Extensions": {"direction": "IN", "status": "pending"},
        "Certificate": {"direction": "IN", "status": "pending"},
        "CERT Verify": {"direction": "IN", "status": "pending"},
        "Change Cipher Spec": {"direction": "OUT", "status": "pending"},
        "Finished": {"direction": "OUT", "status": "pending"},
        "New Session Ticket": {"direction": "IN", "status": "skipped"},
    })

    mapping = {
        "client hello": "Client Hello",
        "server hello": "Server Hello",
        "encrypted extensions": "Encrypted Extensions",
        "certificate": "Certificate",
        "cert verify": "CERT Verify",
        "change cipher spec": "Change Cipher Spec",
        "finished": "Finished",
        "new session ticket": "New Session Ticket"
    }
    lines = output.split("\n")
    found_new_session_ticket = False
    for line in lines:
        lower_line = line.lower()
        for key, stage_label in mapping.items():
            if key in lower_line:
                initial_stages[stage_label]["status"] = "success"
                if key == "new session ticket":
                    found_new_session_ticket = True

    if not found_new_session_ticket:
        initial_stages["New Session Ticket"]["status"] = "skipped"
    return initial_stages


def detect_ephemeral_in_curl_output(curl_output: str) -> bool:
    ephemeral_keywords = ["ecdhe", "dhe", "x25519", "x448"]
    lines = curl_output.lower().split("\n")
    for line in lines:
        if "tlsv1.3" in line:
            return True
        for ek in ephemeral_keywords:
            if ek in line:
                return True
    return False


def perform_openssl_handshake(domain: str, tls_version: str = None):
    ip_addr = socket.gethostbyname(domain)

    if tls_version == "1.2":
        method = SSL.TLSv1_2_METHOD
    elif tls_version == "1.3":
        method = SSL.TLS_METHOD
    else:
        method = SSL.TLS_METHOD

    context = SSL.Context(method)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    start_time = datetime.now()
    try:
        sock.connect((ip_addr, 443))
        sock.setblocking(True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            tsk = progress.add_task("Performing TLS handshake...", total=None)
            conn = SSL.Connection(context, sock)
            conn.set_tlsext_host_name(domain.encode("utf-8"))
            conn.set_connect_state()
            conn.do_handshake()
            progress.update(tsk, description="TLS handshake complete.")
            conn.setblocking(True)

        cipher_used = conn.get_cipher_name()
        cert_chain = conn.get_peer_cert_chain()
        time_taken = (datetime.now() - start_time).total_seconds()

        parsed_chain = []
        for idx, cert in enumerate(cert_chain):
            subj = dict(cert.get_subject().get_components())
            iss = dict(cert.get_issuer().get_components())
            not_before = cert.get_notBefore().decode("ascii")
            not_after = cert.get_notAfter().decode("ascii")
            parsed_chain.append({
                "Index": idx,
                "Subject": {
                    k.decode("ascii"): v.decode("ascii") for k, v in subj.items()
                },
                "Issuer": {
                    k.decode("ascii"): v.decode("ascii") for k, v in iss.items()
                },
                "NotBefore": not_before,
                "NotAfter": not_after,
                "CertObj": cert
            })

        conn.close()
        sock.close()
        return parsed_chain, cipher_used, time_taken, ip_addr
    except Exception as err:
        sock.close()
        raise RuntimeError(f"OpenSSL handshake to {domain} failed: {err}")


def parse_openssl_time(ts_str: str):
    for fmt in ("%Y%m%d%H%M%SZ", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            pass
    return None


###############################################################################
#                              OCSP CHECKS                                    #
###############################################################################

def extract_cert_metadata_crypto(cert_obj):
    der_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_obj)
    x509_cert = x509.load_der_x509_certificate(der_bytes, default_backend())

    crl_urls = []
    try:
        cdp_ext = x509_cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        for dist_point in cdp_ext.value:
            for full_name in dist_point.full_name:
                crl_urls.append(full_name.value)
    except x509.ExtensionNotFound:
        pass

    ocsp_urls = []
    try:
        aia_ext = x509_cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for desc in aia_ext.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass

    return x509_cert, crl_urls, ocsp_urls


def attempt_ocsp_check(leaf_cert_obj, issuer_cert_obj, ocsp_urls):
    from cryptography import x509
    from cryptography.x509 import ocsp
    import requests

    if not ocsp_urls:
        return "No OCSP URL found."

    ocsp_url = ocsp_urls[0]
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        leaf_cert_obj, issuer_cert_obj, hashes.SHA256()
    )
    req = builder.build()

    try:
        encoded_request = req.public_bytes(serialization.Encoding.DER)
        headers = {"Content-Type": "application/ocsp-request"}
        resp = requests.post(ocsp_url, data=encoded_request, headers=headers)

        if resp.status_code != 200:
            return f"OCSP response failure (HTTP {resp.status_code}) from {ocsp_url}"

        ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
        if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
            return f"OCSP response not successful from {ocsp_url}"

        single = ocsp_resp.responses[0]
        if single.cert_status == OCSPCertStatus.REVOKED:
            return f"Certificate REVOKED by OCSP at {ocsp_url}"
        elif single.cert_status == OCSPCertStatus.GOOD:
            return "Leaf certificate GOOD according to OCSP"
        else:
            return "OCSP reported an UNKNOWN state."
    except Exception as e:
        return f"OCSP check error: {e}"


def do_ocsp_for_leaf(chain, show_progress=True):
    if not chain or len(chain) < 2:
        return ["No leaf & issuer chain for OCSP."]

    leaf_entry = chain[0]
    issuer_entry = chain[1]
    leaf_cert = leaf_entry["CertObj"]
    issuer_cert = issuer_entry["CertObj"]
    x509_leaf, _, ocsp_urls_leaf = extract_cert_metadata_crypto(leaf_cert)
    x509_issuer, _, _ = extract_cert_metadata_crypto(issuer_cert)

    if not ocsp_urls_leaf:
        return ["No OCSP URL found for the leaf certificate."]

    if not show_progress:
        return [attempt_ocsp_check(x509_leaf, x509_issuer, ocsp_urls_leaf)]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        ocsp_task = progress.add_task("Checking OCSP...", total=None)
        ocsp_res = attempt_ocsp_check(x509_leaf, x509_issuer, ocsp_urls_leaf)
        progress.update(ocsp_task, description="OCSP request complete.")
    return [ocsp_res]


###############################################################################
#                          SECURITY CHECKS LOGIC                               #
###############################################################################

def extract_subject_alt_names_crypto(cert_obj):
    der_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_obj)
    x509_cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    alt_names = []
    try:
        san_ext = x509_cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        alt_names = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return [n.lower() for n in alt_names]


def check_hostname(chain, domain: str):
    if not chain:
        return []
    leaf_cert = chain[0]
    cn_value = leaf_cert["Subject"].get("CN", "").lower()
    san_entries = extract_subject_alt_names_crypto(leaf_cert["CertObj"])
    domain_lower = domain.lower()

    if domain_lower == cn_value or domain_lower in san_entries:
        return []
    if cn_value.startswith("*."):
        wildcard_root = cn_value.lstrip("*.")  
        if domain_lower.endswith(wildcard_root):
            return []
    for alt_name in san_entries:
        if alt_name.startswith("*."):
            if domain_lower.endswith(alt_name.lstrip("*.")):
                return []
        elif alt_name == domain_lower:
            return []
    return [f"Hostname mismatch: {domain} not in CN or SAN"]


def check_cipher_strength(cipher_str: str):
    if not cipher_str:
        return []
    weak_algos = ["RC4", "DES", "MD5", "NULL", "RC2", "EXPORT", "PSK"]
    for algo in weak_algos:
        if algo in cipher_str.upper():
            return [f"Weak cipher: {cipher_str}"]
    return []


def check_cert_expiration(chain):
    warnings = []
    for entry in chain:
        not_after = entry["NotAfter"]
        dt_parsed = parse_openssl_time(not_after)
        if dt_parsed:
            days_left = (dt_parsed - datetime.now()).days
            if days_left < 0:
                warnings.append(
                    f"Cert index {entry['Index']} expired on {dt_parsed}"
                )
            elif days_left < 30:
                warnings.append(
                    f"Cert index {entry['Index']} expires soon (<30 days): {dt_parsed}"
                )
        else:
            warnings.append(f"Could not parse NotAfter for cert index {entry['Index']}")
    return warnings


def security_checks(chain, cipher_str: str, domain: str, ephemeral: bool):
    alerts = []
    alerts.extend(check_cipher_strength(cipher_str))
    if not ephemeral:
        alerts.append(f"No ephemeral key exchange detected in: {cipher_str}")
    alerts.extend(check_cert_expiration(chain))
    alerts.extend(check_hostname(chain, domain))
    for idx, entry in enumerate(chain):
        _, crl_points, ocsp_points = extract_cert_metadata_crypto(entry["CertObj"])
        if ocsp_points:
            alerts.append(f"OCSP responders found: {', '.join(ocsp_points)}")
        if crl_points:
            alerts.append(f"CRL distribution points found: {', '.join(crl_points)}")
    return alerts


###############################################################################
#                                PRESENTATION                                 #
###############################################################################

def display_general_info(chain, cipher_used, time_s, ip_addr):
    if not chain:
        console.print("[bold red]No certificate chain[/bold red]")
        return
    leaf = chain[0]
    info_table = Table(title="SSL Connection Details", show_header=False, box=None)
    info_table.add_column("Field")
    info_table.add_column("Value")
    info_table.add_row("Server IP", str(ip_addr))
    info_table.add_row("Selected Cipher", str(cipher_used))
    info_table.add_row("Connection Time (s)", f"{time_s:.3f}")
    info_table.add_row("Leaf Cert CN", leaf["Subject"].get("CN", "N/A"))
    info_table.add_row("Leaf Cert Issuer", str(leaf["Issuer"]))
    info_table.add_row("Trust Status", "Unknown (PyOpenSSL get_verify_result() not used)")
    console.print(Panel(info_table, border_style="bold blue"))


def display_chain_info(chain):
    chain_table = Table(title="Certificate Chain Details")
    chain_table.add_column("Index")
    chain_table.add_column("Subject")
    chain_table.add_column("Issuer")
    chain_table.add_column("Not Before")
    chain_table.add_column("Not After")

    for cert_entry in chain:
        chain_table.add_row(
            str(cert_entry["Index"]),
            str(cert_entry["Subject"]),
            str(cert_entry["Issuer"]),
            cert_entry["NotBefore"],
            cert_entry["NotAfter"]
        )
    console.print(Panel(chain_table, border_style="bold cyan"))


def display_security_alerts(alerts):
    if not alerts:
        return
    msg = "\n".join("- " + a for a in alerts)
    console.print(
        Panel(
            Text(msg, style="red"),
            title="Security Alerts",
            border_style="red"
        )
    )


def display_raw_curl_output(curl_output):
    if not curl_output:
        return
    lines = curl_output.splitlines()
    ssl_lines, http_lines, err_lines, general_lines = [], [], [], []
    for line in lines:
        lower_line = line.lower()
        if any(x in lower_line for x in ["ssl", "tls", "handshake"]):
            ssl_lines.append(Text(line, style="bold green"))
        elif lower_line.startswith("<") or lower_line.startswith(">") \
                or "http" in lower_line:
            http_lines.append(Text(line, style="bold cyan"))
        elif any(x in lower_line for x in ["error", "failed", "alert"]):
            err_lines.append(Text(line, style="bold red"))
        else:
            general_lines.append(Text(line, style="white"))

    def show_panel(title, items, color):
        if items:
            content = "\n".join(str(i) for i in items)
            console.print(Panel(Text(content, style=color), title=title,
                                border_style=color))

    show_panel("🔒 SSL/TLS Details", ssl_lines, "green")
    show_panel("🌐 HTTP Details", http_lines, "cyan")
    show_panel("❗ Errors / Alerts", err_lines, "red")
    show_panel("📄 General Details", general_lines, "yellow")


def display_handshake_analysis(handshake_data):
    summary_table = Table(title="Handshake Analysis Summary", box=None)
    summary_table.add_column("Stage", style="bold cyan")
    summary_table.add_column("Status", justify="center")

    color_map = {
        "success": "green", "failure": "red",
        "pending": "yellow", "skipped": "dim"
    }
    icon_map = {
        "success": "✅", "failure": "❌",
        "pending": "⏳", "skipped": "🚫"
    }

    for stage_label, info in handshake_data.items():
        status = info["status"]
        status_color = color_map.get(status, "white")
        status_icon = icon_map.get(status, "❓")
        summary_table.add_row(
            stage_label,
            f"[{status_color}]{status_icon} {status}[/{status_color}]"
        )
    console.print(Panel(summary_table, border_style="bold green"))


def visualize_handshake_ascii(handshake_data):
    def generate_table():
        tbl = Table(title="🔒 TLS Handshake Stages")
        tbl.add_column("Stage")
        tbl.add_column("Direction", justify="center")
        tbl.add_column("Status", justify="center")

        icons = {
            "success": "✅", "failure": "⛔",
            "pending": "⚠️", "skipped": "🛑"
        }
        colors = {
            "success": "green", "failure": "red",
            "pending": "yellow", "skipped": "dim"
        }

        for stage_label, val in handshake_data.items():
            direction_symbol = "→" if val["direction"] == "OUT" else "←"
            clr = colors.get(val["status"], "white")
            ic = icons.get(val["status"], "❓")
            tbl.add_row(
                stage_label,
                f"{direction_symbol} {val['direction']}",
                f"[{clr}]{ic} {val['status']}[/{clr}]"
            )
        return tbl

    with Live(generate_table(), console=console, refresh_per_second=2):
        for stage_label, val in handshake_data.items():
            sleep(0.3)
            if val["status"] == "pending":
                val["status"] = "success"
            console.log(f"Processed stage: {stage_label}")


###############################################################################
#                            OUTPUT FORMATTING                                #
###############################################################################

def prepare_structured_output(domain, url_full, chain_info, cipher_used,
                              conn_time, ip_address, handshake_data, alerts,
                              ephemeral, ocsp_responses):
    cert_chain_export = []
    for cert_entry in chain_info:
        cert_chain_export.append({
            "Index": cert_entry["Index"],
            "Subject": cert_entry["Subject"],
            "Issuer": cert_entry["Issuer"],
            "NotBefore": cert_entry["NotBefore"],
            "NotAfter": cert_entry["NotAfter"]
        })

    handshake_stages = []
    for stage_label, info in handshake_data.items():
        handshake_stages.append({
            "Stage": stage_label,
            "Direction": info["direction"],
            "Status": info["status"]
        })

    output_dict = {
        "Domain": domain,
        "URL": url_full,
        "ServerIP": ip_address,
        "CipherUsed": cipher_used,
        "ConnectionTimeSec": conn_time,
        "EphemeralDetected": ephemeral,
        "CertificateChain": cert_chain_export,
        "HandshakeStages": handshake_stages,
        "OCSPResults": ocsp_responses,
        "Alerts": alerts,
        "TrustStatus": "Unknown (no get_verify_result())"
    }
    return output_dict


def output_as_json(data):
    return json.dumps(data, indent=2)


def output_as_yaml(data):
    if not HAS_YAML:
        raise RuntimeError("PyYAML is not installed. Can't output YAML.")
    return yaml.dump(data, sort_keys=False)


###############################################################################
#                                  MAIN                                       #
###############################################################################

def main():
    try:
        args = parse_arguments()
        domain, url_full = parse_and_validate_url(args.url)
        console.print(
            f"[bold cyan]🔍 Analyzing TLS handshake for "
            f"[underline]{url_full}[/underline][/bold cyan]"
        )

        # cURL approach (either realtime or single-shot)
        if args.realtime:
            console.print(
                "[bold green]Using real-time cURL approach (state machine)...[/bold green]"
            )
            curl_output = run_curl_realtime(url_full)
        else:
            console.print(
                "[bold green]Using single-shot cURL approach...[/bold green]"
            )
            curl_output = run_curl_single_shot(url_full)

        # Parse cURL logs
        handshake_data = parse_curl_handshake(curl_output)
        ephemeral_detected = detect_ephemeral_in_curl_output(curl_output)

        # Perform OpenSSL handshake
        chain_info, cipher_used, conn_time, ip_address = perform_openssl_handshake(
            domain, tls_version=args.tlsv
        )

        # Basic security checks
        alerts = security_checks(
            chain_info, cipher_used, domain, ephemeral=ephemeral_detected
        )

        # Attempt an OCSP check
        ocsp_responses = do_ocsp_for_leaf(chain_info, show_progress=not args.realtime)
        for ocsp_res in ocsp_responses:
            # Negative or unknown => alert
            if ("REVOKED" in ocsp_res) or ("FAILURE" in ocsp_res) \
               or ("UNKNOWN" in ocsp_res) or ("error" in ocsp_res.lower()):
                alerts.append(f"OCSP: {ocsp_res}")
            else:
                # Otherwise, just info
                alerts.append(f"OCSP Info: {ocsp_res}")

        # If user wants structured output, skip console printing
        if args.output_format:
            structured_results = prepare_structured_output(
                domain, url_full, chain_info, cipher_used,
                conn_time, ip_address, handshake_data, alerts,
                ephemeral_detected, ocsp_responses
            )
            if args.output_format == "json":
                print(output_as_json(structured_results))
            elif args.output_format == "yaml":
                print(output_as_yaml(structured_results))
            sys.exit(0)

        # Console display
        display_general_info(chain_info, cipher_used, conn_time, ip_address)
        display_chain_info(chain_info)
        display_security_alerts(alerts)

        if args.verbose:
            display_raw_curl_output(curl_output)

        if args.ascii and not args.realtime:
            visualize_handshake_ascii(handshake_data)
        else:
            display_handshake_analysis(handshake_data)

    except KeyboardInterrupt:
        console.print("[red]Cancelled by user[/red]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        if "args" in locals() and args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
