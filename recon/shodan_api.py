import asyncio
import socket
from typing import Optional
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

SHODAN_API_BASE = "https://api.shodan.io"


class ShodanLookup:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def _resolve_to_ip(self, target: str) -> Optional[str]:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    async def _get_host_info(self, session: aiohttp.ClientSession, ip: str) -> Optional[dict]:
        url = f"{SHODAN_API_BASE}/shodan/host/{ip}?key={self.api_key}"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 401:
                    console.print("[red]Shodan: Invalid API key[/red]")
                elif resp.status == 404:
                    console.print(f"[yellow]Shodan: No information for this IP[/yellow]")
                else:
                    console.print(f"[yellow]Shodan API error: HTTP {resp.status}[/yellow]")
        except aiohttp.ClientError as e:
            console.print(f"[red]Shodan request failed: {e}[/red]")
        return None

    async def _get_dns_resolve(self, session: aiohttp.ClientSession, domain: str) -> Optional[dict]:
        url = f"{SHODAN_API_BASE}/dns/resolve?hostnames={domain}&key={self.api_key}"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
        except aiohttp.ClientError:
            pass
        return None

    async def query(self, target: str) -> Optional[dict]:
        console.print(f"[bold]>> Shodan Lookup:[/bold] [white]{target}[/white]")

        ip = self._resolve_to_ip(target)
        if not ip:
            console.print(f"[red]Could not resolve hostname:[/red] {target}")
            return None

        if ip != target:
            console.print(f"   Resolved: [cyan]{ip}[/cyan]")

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            with console.status("[cyan]Querying Shodan...[/cyan]"):
                data = await self._get_host_info(session, ip)

        if not data:
            return None

        self._print_results(data, target, ip)
        return data

    def _print_results(self, data: dict, target: str, ip: str):
        # Basic info panel
        org = data.get("org", "N/A")
        isp = data.get("isp", "N/A")
        country = data.get("country_name", "N/A")
        city = data.get("city", "N/A")
        os_info = data.get("os", "N/A")
        last_update = data.get("last_update", "N/A")
        hostnames = ", ".join(data.get("hostnames", [])) or "N/A"
        vulns = data.get("vulns", {})

        info_text = (
            f"[bold white]IP:[/bold white] {ip}\n"
            f"[bold white]Organization:[/bold white] {org}\n"
            f"[bold white]ISP:[/bold white] {isp}\n"
            f"[bold white]Location:[/bold white] {city}, {country}\n"
            f"[bold white]OS:[/bold white] {os_info}\n"
            f"[bold white]Hostnames:[/bold white] {hostnames}\n"
            f"[bold white]Last Update:[/bold white] {last_update}"
        )

        console.print()
        console.print(Panel(
            info_text,
            title=f"[bold cyan]Shodan — {target}[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
        ))

        # Open ports / services table
        services = data.get("data", [])
        if services:
            table = Table(
                title="Services Detected by Shodan",
                box=box.ROUNDED,
                border_style="cyan",
                show_lines=True,
            )
            table.add_column("Port", style="bold white", width=8)
            table.add_column("Protocol", width=10)
            table.add_column("Product / Banner", style="yellow")
            table.add_column("Version", style="dim")

            for svc in services:
                port = str(svc.get("port", "?"))
                proto = svc.get("transport", "tcp")
                product = svc.get("product", "") or svc.get("_shodan", {}).get("module", "")
                version = svc.get("version", "")
                if not product:
                    banner = svc.get("data", "")
                    product = banner.split("\n")[0][:60] if banner else "N/A"
                table.add_row(port, proto, product, version)

            console.print(table)

        # Vulnerabilities
        if vulns:
            vuln_table = Table(
                title="[bold red]Known Vulnerabilities (CVEs)[/bold red]",
                box=box.ROUNDED,
                border_style="red",
                show_lines=True,
            )
            vuln_table.add_column("CVE", style="bold red", width=18)
            vuln_table.add_column("CVSS", width=8)
            vuln_table.add_column("Summary", style="white")

            for cve, info in list(vulns.items())[:20]:
                cvss = str(info.get("cvss", "N/A"))
                summary = info.get("summary", "")[:80]
                vuln_table.add_row(cve, cvss, summary)

            console.print(vuln_table)
            if len(vulns) > 20:
                console.print(f"[dim]... and {len(vulns) - 20} more vulnerabilities[/dim]")
        else:
            console.print("[dim]No CVEs found in Shodan database for this IP.[/dim]")

        console.print()
