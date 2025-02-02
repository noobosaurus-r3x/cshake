import hashlib
from datetime import datetime
from contextlib import contextmanager
import socket
from OpenSSL import SSL
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Global constants used across the package.
HANDSHAKE_STAGE_CONFIG = [
    ("Client Hello", ["client hello"], "OUT", "pending"),
    ("Server Hello", ["server hello"], "IN", "pending"),
    ("Encrypted Extensions", ["encrypted extensions"], "IN", "pending"),
    ("Certificate", ["certificate"], "IN", "pending"),
    ("CERT Verify", ["cert verify"], "IN", "pending"),
    ("Change Cipher Spec", ["change cipher spec"], "OUT", "pending"),
    ("Finished", ["finished"], "OUT", "pending"),
    ("New Session Ticket", ["new session ticket"], "IN", "skipped"),
]

TLS_METHODS = {
    "1.2": getattr(SSL, "TLSv1_2_METHOD", SSL.TLS_METHOD),
    "1.3": SSL.TLS_METHOD,
}


# Simple in‑memory DNS cache.
dns_cache = {}

def get_cert_fingerprint(cert_obj) -> str:
    der = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_obj)
    fp = hashlib.sha256(der).hexdigest().upper()
    return ":".join(fp[i:i+2] for i in range(0, len(fp), 2))

def compute_days_left(ts_str: str) -> str:
    dt = parse_openssl_time(ts_str)
    if dt:
        return str((dt - datetime.now()).days)
    return "N/A"

def parse_openssl_time(ts_str: str):
    for fmt in ("%Y%m%d%H%M%SZ", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None

def resolve_ip(domain: str) -> str:
    if domain in dns_cache:
        return dns_cache[domain]
    infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    ip_addr = ""
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            ip_addr = sockaddr[0]
            break
    if not ip_addr:
        ip_addr = infos[0][4][0]
    dns_cache[domain] = ip_addr
    return ip_addr

def load_x509(cert_obj) -> x509.Certificate:
    der_bytes = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_obj)
    return x509.load_der_x509_certificate(der_bytes, default_backend())

@contextmanager
def managed_ssl_connection(context, sock: socket.socket, domain: str):
    from OpenSSL import SSL
    conn = SSL.Connection(context, sock)
    try:
        conn.set_tlsext_host_name(domain.encode("utf-8"))
        conn.set_connect_state()
        conn.do_handshake()
        yield conn
    finally:
        conn.close()
