import asyncio
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

from .subdomain import SubdomainScanner
from .portscan import PortScanner
from .shodan_api import ShodanLookup
from .report import ReportGenerator

console = Console(force_terminal=True)

BANNER = r"""
 ____  _____ ____  ___  _   _       _____ ___   ___  _     _  _____ _____
|  _ \| ____/ ___|/ _ \| \ | |     |_   _/ _ \ / _ \| |   | |/ /_ _|_   _|
| |_) |  _|| |  | | | |  \| |       | || | | | | | || |   | ' / | |  | |
|  _ <| |__| |__| |_| | |\  |       | || |_| | |_| || |___| . \ | |  | |
|_| \_\_____\____\___/|_| \_|       |_| \___/ \___/|_____|_|\_\___| |_|
"""


@click.group()
@click.version_option("1.0.0", prog_name="recon-toolkit")
def cli():
    """Passive reconnaissance toolkit for bug bounty hunters and pentesters."""
    pass


@cli.command()
@click.argument("target")
@click.option("--wordlist", "-w", default=None, help="Custom subdomain wordlist path")
@click.option("--threads", "-t", default=50, show_default=True, help="Number of concurrent threads")
@click.option("--output", "-o", default=None, help="Save results to file (txt)")
@click.option("--no-crt", is_flag=True, default=False, help="Skip crt.sh certificate transparency lookup")
def subdomains(target, wordlist, threads, output, no_crt):
    """Enumerate subdomains for a target domain.

    \b
    Examples:
      recon subdomains example.com
      recon subdomains example.com -w wordlist.txt -t 100
      recon subdomains example.com -o results.txt
    """
    _print_banner()
    asyncio.run(_run_subdomains(target, wordlist, threads, output, no_crt))


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="common", show_default=True,
              help="Port range: 'common', 'top1000', '1-65535' or '80,443,8080'")
@click.option("--timeout", "-t", default=1.0, show_default=True, help="Connection timeout in seconds")
@click.option("--output", "-o", default=None, help="Save results to file (txt)")
def portscan(target, ports, timeout, output):
    """Scan open ports on a target host or IP.

    \b
    Examples:
      recon portscan example.com
      recon portscan 192.168.1.1 -p top1000
      recon portscan example.com -p 80,443,8080,8443
    """
    _print_banner()
    asyncio.run(_run_portscan(target, ports, timeout, output))


@cli.command()
@click.argument("target")
@click.option("--api-key", "-k", envvar="SHODAN_API_KEY", required=True,
              help="Shodan API key (or set SHODAN_API_KEY env var)")
@click.option("--output", "-o", default=None, help="Save results to file (txt)")
def shodan(target, api_key, output):
    """Query Shodan for information about a target IP or domain.

    \b
    Examples:
      recon shodan 8.8.8.8 -k YOUR_API_KEY
      SHODAN_API_KEY=xxx recon shodan example.com
    """
    _print_banner()
    asyncio.run(_run_shodan(target, api_key, output))


@cli.command()
@click.argument("target")
@click.option("--wordlist", "-w", default=None, help="Custom subdomain wordlist path")
@click.option("--threads", "-t", default=50, show_default=True, help="Concurrent threads for subdomain scan")
@click.option("--ports", "-p", default="common", show_default=True, help="Port range to scan")
@click.option("--shodan-key", "-k", envvar="SHODAN_API_KEY", default=None,
              help="Shodan API key (optional, or set SHODAN_API_KEY)")
@click.option("--output", "-o", default="report.html", show_default=True, help="HTML report output path")
@click.option("--no-crt", is_flag=True, default=False, help="Skip crt.sh lookup")
def full(target, wordlist, threads, ports, shodan_key, output, no_crt):
    """Run full recon: subdomains + port scan + Shodan + HTML report.

    \b
    Examples:
      recon full example.com -o report.html
      recon full example.com -k YOUR_SHODAN_KEY -o report.html
    """
    _print_banner()
    asyncio.run(_run_full(target, wordlist, threads, ports, shodan_key, output, no_crt))


def _print_banner():
    text = Text(BANNER, style="bold cyan")
    console.print(text)
    console.print(
        Panel.fit(
            "[bold white]Passive Recon Toolkit[/bold white] - [dim]v1.0.0[/dim]",
            box=box.ASCII,
            border_style="cyan",
        )
    )
    console.print()


async def _run_subdomains(target, wordlist, threads, output, no_crt):
    scanner = SubdomainScanner(target, wordlist=wordlist, threads=threads, use_crt=not no_crt)
    results = await scanner.run()

    if output:
        with open(output, "w") as f:
            for sub in results:
                f.write(sub + "\n")
        console.print(f"\n[green]Results saved to[/green] [bold]{output}[/bold]")

    return results


async def _run_portscan(target, ports, timeout, output):
    scanner = PortScanner(target, ports=ports, timeout=timeout)
    results = await scanner.run()

    if output:
        with open(output, "w") as f:
            for port, info in results.items():
                f.write(f"{port}/tcp\t{info['state']}\t{info.get('service', 'unknown')}\n")
        console.print(f"\n[green]Results saved to[/green] [bold]{output}[/bold]")

    return results


async def _run_shodan(target, api_key, output):
    lookup = ShodanLookup(api_key)
    results = await lookup.query(target)

    if output and results:
        with open(output, "w") as f:
            import json
            f.write(json.dumps(results, indent=2))
        console.print(f"\n[green]Results saved to[/green] [bold]{output}[/bold]")

    return results


async def _run_full(target, wordlist, threads, ports, shodan_key, output, no_crt):
    console.print(f"[bold cyan]Target:[/bold cyan] [bold white]{target}[/bold white]\n")

    console.rule("[cyan]Phase 1: Subdomain Enumeration[/cyan]")
    subdomain_scanner = SubdomainScanner(target, wordlist=wordlist, threads=threads, use_crt=not no_crt)
    subdomains_found = await subdomain_scanner.run()

    console.rule("[cyan]Phase 2: Port Scanning[/cyan]")
    port_scanner = PortScanner(target, ports=ports)
    open_ports = await port_scanner.run()

    shodan_data = None
    if shodan_key:
        console.rule("[cyan]Phase 3: Shodan Lookup[/cyan]")
        lookup = ShodanLookup(shodan_key)
        shodan_data = await lookup.query(target)
    else:
        console.print("[dim]Shodan skipped (no API key provided)[/dim]\n")

    console.rule("[cyan]Phase 4: Generating Report[/cyan]")
    reporter = ReportGenerator(
        target=target,
        subdomains=subdomains_found,
        open_ports=open_ports,
        shodan_data=shodan_data,
    )
    reporter.generate(output)
    console.print(f"\n[bold green]Report saved:[/bold green] [bold white]{output}[/bold white]")


def main():
    cli()


if __name__ == "__main__":
    main()
