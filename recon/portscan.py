import asyncio
import socket
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

console = Console()

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 993, 995, 1080, 1433, 1521, 2181, 2375, 3000, 3306,
    3389, 4444, 5000, 5432, 5601, 5900, 6379, 6443, 7070, 7443,
    8000, 8080, 8081, 8082, 8083, 8088, 8443, 8444, 8888, 9000,
    9090, 9200, 9300, 9443, 10000, 11211, 27017, 27018, 50000,
]

TOP_1000_PORTS = list(range(1, 1001))

SERVICE_BANNERS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2181: "Zookeeper", 2375: "Docker", 3000: "HTTP-alt", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5000: "HTTP-alt", 5432: "PostgreSQL",
    5601: "Kibana", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes",
    7070: "HTTP-alt", 7443: "HTTPS-alt", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8081: "HTTP-alt", 8082: "HTTP-alt", 8083: "HTTP-alt", 8088: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "HTTP-alt", 9090: "HTTP-alt",
    9200: "Elasticsearch", 9300: "Elasticsearch-cluster", 9443: "HTTPS-alt",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
    50000: "SAP",
}

STATE_COLORS = {"open": "bold green", "filtered": "yellow", "closed": "dim red"}


class PortScanner:
    def __init__(
        self,
        target: str,
        ports: str = "common",
        timeout: float = 1.0,
        concurrency: int = 500,
    ):
        self.target = target
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.port_list = self._parse_ports(ports)

    def _parse_ports(self, ports: str) -> list[int]:
        if ports == "common":
            return COMMON_PORTS
        if ports == "top1000":
            return TOP_1000_PORTS
        if ports == "all":
            return list(range(1, 65536))

        result = []
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        return sorted(set(result))

    def _resolve_target(self) -> Optional[str]:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None

    async def _scan_port(self, ip: str, port: int) -> tuple[int, str]:
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port, "open"
            except (asyncio.TimeoutError, ConnectionRefusedError):
                return port, "closed"
            except OSError:
                return port, "filtered"

    async def run(self) -> dict[int, dict]:
        console.print(f"[bold]>> Port Scan:[/bold] [white]{self.target}[/white]")

        ip = self._resolve_target()
        if not ip:
            console.print(f"[red]Could not resolve hostname:[/red] {self.target}")
            return {}

        if ip != self.target:
            console.print(f"   Resolved: [cyan]{ip}[/cyan]")

        console.print(f"   Scanning {len(self.port_list)} ports (timeout={self.timeout}s)\n")

        tasks = [self._scan_port(ip, port) for port in self.port_list]
        results: dict[int, dict] = {}

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning ports...", total=len(tasks))

            for coro in asyncio.as_completed(tasks):
                port, state = await coro
                progress.advance(task)
                if state == "open":
                    results[port] = {
                        "state": state,
                        "service": SERVICE_BANNERS.get(port, "unknown"),
                    }

        self._print_results(results)
        return results

    def _print_results(self, results: dict[int, dict]):
        if not results:
            console.print("\n[yellow]No open ports found.[/yellow]\n")
            return

        table = Table(
            title=f"Open Ports — [bold cyan]{self.target}[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_lines=True,
        )
        table.add_column("Port", style="bold white", width=8)
        table.add_column("State", width=10)
        table.add_column("Service", style="bold yellow")

        for port in sorted(results):
            info = results[port]
            state_style = STATE_COLORS.get(info["state"], "white")
            table.add_row(
                str(port),
                f"[{state_style}]{info['state']}[/{state_style}]",
                info.get("service", "unknown"),
            )

        console.print()
        console.print(table)
        console.print(f"\n[bold green]Total:[/bold green] {len(results)} open port(s)\n")
