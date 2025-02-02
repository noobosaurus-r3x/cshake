import json
from typing import Dict, Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def prepare_structured_output(
    domain: str,
    url_full: str,
    chain_info: list,
    cipher_used: str,
    conn_time: float,
    ip_address: str,
    handshake_data: dict,
    alerts: list,
    ephemeral: bool,
    ocsp_responses: list
) -> Dict[str, Any]:
    """
    Prepare a structured output dictionary with all analysis details.
    """
    return {
        "Connection": {
            "Domain": domain,
            "URL": url_full,
            "ServerIP": ip_address,
            "CipherUsed": cipher_used,
            "ConnectionTimeSec": conn_time,
            "EphemeralDetected": ephemeral,
        },
        "Certificates": [entry.export() for entry in chain_info],
        "Handshake": [
            {"Stage": label, "Direction": info["direction"], "Status": info["status"]}
            for label, info in handshake_data.items()
        ],
        "OCSP": ocsp_responses,
        "Security": alerts,
        "TrustStatus": "Unknown (no get_verify_result())"
    }


def output_as_json(data: Dict[str, Any]) -> str:
    """
    Return a JSON-formatted string of the analysis data.
    """
    return json.dumps(data, indent=4, ensure_ascii=False)


def output_as_yaml(data: Dict[str, Any]) -> str:
    """
    Return a YAML-formatted string of the analysis data.
    """
    if not HAS_YAML:
        raise RuntimeError("PyYAML is not installed. Cannot output YAML.")
    return yaml.dump(data, sort_keys=False)


def output_as_html(
    data: Dict[str, Any],
    template_path: str = ".",
    template_name: str = "report_template.html"
) -> str:
    """
    Render an HTML report from the analysis data using a Jinja2 template.

    The function supports both single and bulk results. For bulk results,
    data should contain a key "BulkResults" that is a list of analysis dictionaries.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        raise RuntimeError("Jinja2 is required for HTML output. Install it via pip.")

    # Wrap single result in a list if necessary.
    bulk_results = data.get("BulkResults") or [data]

    env = Environment(
        loader=FileSystemLoader(template_path),
        autoescape=select_autoescape(['html', 'xml'])
    )
    try:
        template = env.get_template(template_name)
    except Exception as e:
        raise RuntimeError(
            f"Template '{template_name}' not found in search path: {template_path}"
        ) from e

    return template.render(bulk_results=bulk_results)
