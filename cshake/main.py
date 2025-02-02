import sys
import logging
from rich.console import Console
import argparse
from typing import List, Dict, Any

from cshake.analysis import (
    parse_and_validate_url,
    run_curl_single_shot,
    run_curl_realtime,
    parse_curl_handshake,
    detect_ephemeral_in_curl_output,
    perform_openssl_handshake,
    security_checks,
)
from cshake.output import (
    prepare_structured_output,
    output_as_json,
    output_as_yaml,
    output_as_html,
)
from cshake.display import (
    display_summary,
    display_general_info,
    display_chain_info,
    display_security_alerts,
    display_raw_curl_output,
    display_handshake_analysis,
    visualize_handshake_ascii,
)

logger = logging.getLogger(__name__)
console = Console()

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced TLS Handshake Analysis Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="Target URL (must be HTTPS)")
    parser.add_argument("--input-file", type=str, help="File containing URLs (one per line)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show raw cURL output")
    parser.add_argument("-r", "--realtime", action="store_true", help="Real-time cURL-based handshake")
    parser.add_argument("-a", "--ascii", action="store_true", help="ASCII animation after handshake analysis")
    parser.add_argument("--tlsv", choices=["1.2", "1.3"], default=None, help="Force TLS version")
    parser.add_argument("-f", "--output-format", choices=["json", "yaml", "html"],
                        help="Output final results in JSON, YAML, or HTML")
    parser.add_argument("--minimal", action="store_true", help="Display minimal summary output")
    parser.add_argument("-o", "--outfile", type=str, help="Write structured output to file")
    return parser.parse_args()

def process_url(url: str, args: argparse.Namespace) -> Dict[str, Any]:
    """
    Process a single URL: perform handshake analysis and return structured results.
    """
    domain, url_full = parse_and_validate_url(url)
    logger.info(f"Starting analysis for {url_full}")
    console.print(f"[bold cyan]🔍 Analyzing TLS handshake for [underline]{url_full}[/underline][/bold cyan]")
    if args.realtime:
        console.print("[bold green]Using real-time cURL approach...[/bold green]")
        curl_output = run_curl_realtime(url_full)
    else:
        console.print("[bold green]Using single-shot cURL approach...[/bold green]")
        curl_output = run_curl_single_shot(url_full)
    handshake_data = parse_curl_handshake(curl_output)
    ephemeral_detected = detect_ephemeral_in_curl_output(curl_output)
    chain_info, cipher_used, conn_time, ip_address = perform_openssl_handshake(domain, tls_version=args.tlsv)
    alerts = security_checks(chain_info, cipher_used, domain, ephemeral=ephemeral_detected)
    structured = prepare_structured_output(
        domain, url_full, chain_info, cipher_used, conn_time, ip_address,
        handshake_data, alerts, ephemeral_detected, []
    )
    # Preserve raw objects for interactive display only
    structured["chain_obj"] = chain_info
    structured["curl_output"] = curl_output
    structured["handshake_data"] = handshake_data
    return structured

def process_urls(urls: List[str], args: argparse.Namespace) -> List[Dict[str, Any]]:
    """
    Process multiple URLs and return a list of structured results.
    """
    results: List[Dict[str, Any]] = []
    for url in urls:
        try:
            result = process_url(url, args)
            results.append(result)
        except Exception as e:
            logger.exception(f"Error processing {url}: {e}")
            console.print(f"[bold red]Error processing {url}: {e}[/bold red]")
    return results

def cleanup_structured_output(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove non-serializable keys from the structured output.
    """
    cleaned = dict(data)
    for key in ["chain_obj", "curl_output", "handshake_data"]:
        cleaned.pop(key, None)
    return cleaned

def output_results(results: List[Dict[str, Any]], args: argparse.Namespace) -> None:
    """
    Output results based on the specified output format or display interactively.
    """
    if args.output_format:
        if len(results) == 1:
            cleaned = cleanup_structured_output(results[0])
        else:
            cleaned = {"BulkResults": [cleanup_structured_output(r) for r in results]}
        if args.output_format == "json":
            out_str = output_as_json(cleaned)
        elif args.output_format == "yaml":
            out_str = output_as_yaml(cleaned)
        elif args.output_format == "html":
            out_str = output_as_html(cleaned)
        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as f:
                f.write(out_str)
            console.print(f"[bold green]Output written to {args.outfile}[/bold green]")
        else:
            print(out_str)
    else:
        # Interactive display for each result
        for res in results:
            domain = res.get("Connection", {}).get("Domain", "Unknown")
            console.print(f"[bold cyan]Result for {domain}[/bold cyan]")
            chain_obj = res.get("chain_obj", [])
            display_summary(
                chain_obj,
                res["Connection"].get("CipherUsed", ""),
                res["Connection"].get("ConnectionTimeSec", 0),
                res["Connection"].get("ServerIP", ""),
                res.get("Security", []),
                domain
            )
            display_general_info(
                chain_obj,
                res["Connection"].get("CipherUsed", ""),
                res["Connection"].get("ConnectionTimeSec", 0),
                res["Connection"].get("ServerIP", "")
            )
            display_chain_info(chain_obj, minimal=False)
            display_security_alerts(res.get("Security", []))
            if args.verbose:
                display_raw_curl_output(res.get("curl_output", ""))
            if args.ascii and not args.realtime:
                visualize_handshake_ascii(res.get("handshake_data", {}))
            else:
                display_handshake_analysis(res.get("handshake_data", {}))

def main() -> None:
    try:
        args = parse_arguments()
        urls: List[str] = []
        if args.input_file:
            with open(args.input_file, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        elif args.url:
            urls = [args.url]
        else:
            raise ValueError("Either a URL or --input-file must be provided.")
        results = process_urls(urls, args)
        output_results(results, args)
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("Cancelled by user")
        console.print("[red]Cancelled by user[/red]")
        sys.exit(1)
    except Exception as exc:
        logger.exception(f"Error: {exc}")
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
