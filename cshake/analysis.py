import subprocess
import socket
from urllib.parse import urlparse
from time import sleep
from datetime import datetime
from collections import OrderedDict
from typing import Tuple, List, Dict, Any, Optional
import logging
import validators
import requests

from OpenSSL import SSL, crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
from dataclasses import dataclass

from .utils import (
    HANDSHAKE_STAGE_CONFIG,
    TLS_METHODS,
    get_cert_fingerprint,
    compute_days_left,
    parse_openssl_time,
    resolve_ip,
    load_x509,
    managed_ssl_connection,
)

logger = logging.getLogger(__name__)
ocsp_session = requests.Session()
ocsp_session.headers.update({"Content-Type": "application/ocsp-request"})

@dataclass
class CertificateEntry:
    index: int
    subject: Dict[str, str]
    issuer: Dict[str, str]
    not_before: str
    not_after: str
    cert_obj: Any

    def export(self) -> Dict[str, Any]:
        return {
            "Index": self.index,
            "Subject": self.subject,
            "Issuer": self.issuer,
            "NotBefore": self.not_before,
            "NotAfter": self.not_after,
            "Fingerprint": get_cert_fingerprint(self.cert_obj),
            "DaysLeft": compute_days_left(self.not_after),
        }

def parse_and_validate_url(url_str: str) -> Tuple[str, str]:
    """
    Parse and validate the provided URL string.
    Returns the domain and the full, stripped URL.
    """
    parsed = urlparse(url_str.strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("URL scheme must be HTTPS.")
    if not validators.url(url_str):
        raise ValueError("Invalid URL.")
    domain = parsed.netloc.split(":")[0]
    return domain, url_str.strip()

def run_curl_single_shot(url_str: str, timeout: int = 15) -> str:
    """
    Run curl in single-shot mode and return stderr output.
    """
    cmd = ["curl", "-vvv", "--silent", "--output", "/dev/null", url_str]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, check=True
        )
        return result.stderr
    except subprocess.CalledProcessError as e:
        logger.error(f"curl error: {e}")
        raise

def run_curl_realtime(url_str: str, timeout: int = 15) -> str:
    """
    Run curl in real-time mode, process the output line by line,
    and return the complete stderr output.
    """
    stage_data: OrderedDict = OrderedDict()
    for label, _, direction, default_status in HANDSHAKE_STAGE_CONFIG:
        stage_data[label] = {"direction": direction, "status": default_status}
    cmd = ["curl", "-vvv", "--silent", "--output", "/dev/null", url_str]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=1, text=True, universal_newlines=True
    )
    full_output: List[str] = []
    stage_index = 0
    while True:
        line = process.stderr.readline()
        if line:
            ls = line.rstrip("\n")
            full_output.append(ls)
            lower = ls.lower()
            if "alert" in lower or "error" in lower:
                if stage_index < len(HANDSHAKE_STAGE_CONFIG):
                    current = HANDSHAKE_STAGE_CONFIG[stage_index][0]
                    stage_data[current]["status"] = "failure"
            if stage_index < len(HANDSHAKE_STAGE_CONFIG):
                stage_label, triggers, _, _ = HANDSHAKE_STAGE_CONFIG[stage_index]
                if any(trig in lower for trig in triggers):
                    stage_data[stage_label]["status"] = "success"
                    stage_index += 1
        elif process.poll() is not None:
            break
    return "\n".join(full_output)

def parse_curl_handshake(output: str) -> OrderedDict:
    """
    Parse curl output to determine the status of each TLS handshake stage.
    """
    stages: OrderedDict = OrderedDict()
    for label, _, direction, default_status in HANDSHAKE_STAGE_CONFIG:
        stages[label] = {"direction": direction, "status": default_status}
    found_ticket = False
    for line in output.splitlines():
        lower = line.lower()
        for label, triggers, _, _ in HANDSHAKE_STAGE_CONFIG:
            if any(trigger in lower for trigger in triggers):
                stages[label]["status"] = "success"
                if label == "New Session Ticket":
                    found_ticket = True
    if not found_ticket:
        stages["New Session Ticket"]["status"] = "skipped"
    return stages

def detect_ephemeral_in_curl_output(curl_output: str) -> bool:
    """
    Detect if ephemeral key exchange is used based on curl output.
    """
    keywords = ["ecdhe", "dhe", "x25519", "x448"]
    for line in curl_output.lower().splitlines():
        if "tlsv1.3" in line or any(kw in line for kw in keywords):
            return True
    return False

def perform_openssl_handshake(domain: str, tls_version: Optional[str] = None) -> Tuple[List[CertificateEntry], str, float, str]:
    """
    Perform a TLS handshake using OpenSSL.
    Returns the certificate chain, cipher used, connection time, and server IP.
    """
    ip_addr: str = resolve_ip(domain)
    method = TLS_METHODS.get(tls_version, TLS_METHODS["1.3"])
    context = SSL.Context(method)
    start_time = datetime.now()
    with socket.create_connection((ip_addr, 443), timeout=10) as sock:
        sock.setblocking(True)
        with managed_ssl_connection(context, sock, domain) as conn:
            cipher_used: str = conn.get_cipher_name()
            cert_chain = conn.get_peer_cert_chain()
            time_taken: float = (datetime.now() - start_time).total_seconds()
            parsed_chain: List[CertificateEntry] = []
            for idx, cert in enumerate(cert_chain):
                subj = {k.decode("ascii"): v.decode("ascii") for k, v in dict(cert.get_subject().get_components()).items()}
                issuer = {k.decode("ascii"): v.decode("ascii") for k, v in dict(cert.get_issuer().get_components()).items()}
                not_before: str = cert.get_notBefore().decode("ascii")
                not_after: str = cert.get_notAfter().decode("ascii")
                entry = CertificateEntry(idx, subj, issuer, not_before, not_after, cert)
                parsed_chain.append(entry)
            return parsed_chain, cipher_used, time_taken, ip_addr

def extract_cert_metadata_crypto(cert_obj: Any) -> Tuple[x509.Certificate, List[str], List[str]]:
    """
    Extract metadata from a certificate using cryptography.
    Returns the x509 certificate, CRL URLs, and OCSP URLs.
    """
    x509_cert = load_x509(cert_obj)
    crl_urls: List[str] = []
    try:
        cdp = x509_cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for dp in cdp.value:
            for name in dp.full_name:
                crl_urls.append(name.value)
    except x509.ExtensionNotFound:
        pass
    ocsp_urls: List[str] = []
    try:
        aia = x509_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass
    return x509_cert, crl_urls, ocsp_urls

def extract_subject_alt_names_crypto(cert_obj: Any) -> List[str]:
    """
    Extract Subject Alternative Names (SANs) from a certificate.
    """
    x509_cert = load_x509(cert_obj)
    try:
        san = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [n.lower() for n in san.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        return []

def attempt_ocsp_check(leaf_cert_obj: x509.Certificate, issuer_cert_obj: x509.Certificate, ocsp_urls: List[str]) -> str:
    """
    Attempt an OCSP check for the leaf certificate.
    Returns a detailed status message.
    """
    for ocsp_url in ocsp_urls:
        try:
            builder = x509.ocsp.OCSPRequestBuilder().add_certificate(leaf_cert_obj, issuer_cert_obj, hashes.SHA256())
            req = builder.build()
            encoded = req.public_bytes(serialization.Encoding.DER)
            resp = ocsp_session.post(ocsp_url, data=encoded, timeout=5)
            if resp.status_code != 200:
                logger.warning(f"OCSP URL {ocsp_url} returned status code {resp.status_code}")
                continue
            ocsp_resp = x509.ocsp.load_der_ocsp_response(resp.content)
            if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
                logger.warning(f"OCSP response from {ocsp_url} not successful: {ocsp_resp.response_status}")
                continue
            first_response = next(ocsp_resp.responses, None)
            if first_response is None:
                logger.warning(f"No responses in OCSP reply from {ocsp_url}")
                continue
            if first_response.certificate_status == OCSPCertStatus.REVOKED:
                return f"Certificate REVOKED according to OCSP at {ocsp_url}"
            elif first_response.certificate_status == OCSPCertStatus.GOOD:
                return f"Certificate GOOD according to OCSP at {ocsp_url}"
            else:
                return f"Certificate status UNKNOWN according to OCSP at {ocsp_url}"
        except Exception as e:
            logger.exception(f"Error during OCSP check at {ocsp_url}: {e}")
            continue
    return "OCSP check could not determine certificate status."

def check_crl_for_cert(leaf_cert_obj: x509.Certificate, crl_urls: List[str]) -> List[str]:
    """
    Check certificate revocation status using CRL distribution points.
    Downloads and parses each CRL, then checks if the certificate is revoked.
    Returns a list of status messages.
    """
    messages: List[str] = []
    serial_number = leaf_cert_obj.serial_number
    for url in crl_urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                messages.append(f"CRL URL {url} returned status code {response.status_code}")
                continue
            crl_data = response.content
            try:
                crl = x509.load_der_x509_crl(crl_data)
            except Exception:
                crl = x509.load_pem_x509_crl(crl_data)
            revoked_cert = crl.get_revoked_certificate_by_serial_number(serial_number)
            if revoked_cert:
                messages.append(f"Certificate REVOKED according to CRL at {url}")
            else:
                messages.append(f"Certificate not revoked according to CRL at {url}")
        except Exception as e:
            logger.exception(f"Error checking CRL at {url}: {e}")
            messages.append(f"Error checking CRL at {url}: {e}")
    return messages

def do_ocsp_and_crl_checks(chain: List[CertificateEntry], show_progress: bool = True) -> List[str]:
    """
    Perform both OCSP and CRL checks for the leaf certificate.
    Returns a list of revocation status messages.
    """
    if not chain or len(chain) < 2:
        return ["No leaf & issuer chain available for revocation checks."]
    leaf_entry, issuer_entry = chain[0], chain[1]
    x509_leaf, crl_urls, ocsp_urls = extract_cert_metadata_crypto(leaf_entry.cert_obj)
    x509_issuer, _, _ = extract_cert_metadata_crypto(issuer_entry.cert_obj)

    results: List[str] = []
    if ocsp_urls:
        ocsp_result = attempt_ocsp_check(x509_leaf, x509_issuer, ocsp_urls)
        results.append(f"OCSP: {ocsp_result}")
    else:
        results.append("No OCSP URL found for the leaf certificate.")

    if crl_urls:
        crl_results = check_crl_for_cert(x509_leaf, crl_urls)
        results.extend([f"CRL: {msg}" for msg in crl_results])
    else:
        results.append("No CRL distribution points found for the leaf certificate.")
    return results

def check_hostname(chain: List[CertificateEntry], domain: str) -> List[str]:
    """
    Verify that the domain matches the certificate's CN or SAN.
    """
    if not chain:
        return []
    leaf = chain[0]
    cn_value = leaf.subject.get("CN", "").lower()
    san_entries = extract_subject_alt_names_crypto(leaf.cert_obj)
    domain_lower = domain.lower()
    if domain_lower == cn_value or domain_lower in san_entries:
        return []
    if cn_value.startswith("*.") and domain_lower.endswith(cn_value.lstrip("*.") ):
        return []
    for alt in san_entries:
        if alt.startswith("*.") and domain_lower.endswith(alt.lstrip("*.") ):
            return []
        if alt == domain_lower:
            return []
    return [f"Hostname mismatch: {domain} not in CN or SAN"]

def check_cipher_strength(cipher_str: str) -> List[str]:
    """
    Evaluate whether the cipher used is weak.
    """
    if not cipher_str:
        return []
    weak = ["RC4", "DES", "MD5", "NULL", "RC2", "EXPORT", "PSK"]
    for algo in weak:
        if algo in cipher_str.upper():
            return [f"Weak cipher: {cipher_str}"]
    return []

def check_cert_expiration(chain: List[CertificateEntry]) -> List[str]:
    """
    Check the expiration status of each certificate in the chain.
    """
    warnings: List[str] = []
    for entry in chain:
        dt = parse_openssl_time(entry.not_after)
        if dt:
            days_left = (dt - datetime.now()).days
            if days_left < 0:
                warnings.append(f"Cert index {entry.index} expired on {dt}")
            elif days_left < 30:
                warnings.append(f"Cert index {entry.index} expires soon (<30 days): {dt}")
        else:
            warnings.append(f"Could not parse NotAfter for cert index {entry.index}")
    return warnings

def security_checks(chain: List[CertificateEntry], cipher_str: str, domain: str, ephemeral: bool) -> List[str]:
    """
    Perform security checks including cipher strength, certificate expiration,
    hostname verification, and revocation checks (OCSP and CRL).
    """
    alerts: List[str] = []
    alerts.extend(check_cipher_strength(cipher_str))
    if not ephemeral:
        alerts.append(f"No ephemeral key exchange detected in: {cipher_str}")
    alerts.extend(check_cert_expiration(chain))
    alerts.extend(check_hostname(chain, domain))
    revocation_results = do_ocsp_and_crl_checks(chain, show_progress=False)
    alerts.extend(revocation_results)
    return alerts
