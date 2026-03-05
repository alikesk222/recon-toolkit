import asyncio
import aiohttp
import dns.asyncresolver
import dns.exception
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

console = Console()

DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "api", "app", "test",
    "staging", "cdn", "static", "media", "img", "images", "video", "portal",
    "vpn", "remote", "gateway", "ns1", "ns2", "smtp", "pop", "imap",
    "webmail", "m", "mobile", "shop", "store", "secure", "auth", "login",
    "dashboard", "panel", "cp", "cpanel", "whm", "plesk", "autodiscover",
    "autoconfig", "support", "help", "docs", "status", "monitor",
    "git", "gitlab", "github", "jira", "confluence", "jenkins", "ci", "cd",
    "backup", "db", "database", "mysql", "postgres", "redis", "elastic",
    "internal", "intranet", "corp", "office", "files", "download", "upload",
    "s3", "storage", "assets", "preview", "beta", "alpha", "old", "new",
]


class SubdomainScanner:
    def __init__(
        self,
        domain: str,
        wordlist: Optional[str] = None,
        threads: int = 50,
        use_crt: bool = True,
    ):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.use_crt = use_crt
        self.found: list[str] = []
        self.semaphore = asyncio.Semaphore(threads)

        if wordlist:
            wl_path = Path(wordlist)
            if wl_path.exists():
                self.wordlist = wl_path.read_text().splitlines()
            else:
                console.print(f"[yellow]Wordlist not found: {wordlist}, using defaults[/yellow]")
                self.wordlist = self._load_default_wordlist()
        else:
            self.wordlist = self._load_default_wordlist()

    def _load_default_wordlist(self) -> list[str]:
        if DEFAULT_WORDLIST.exists():
            return DEFAULT_WORDLIST.read_text().splitlines()
        return COMMON_SUBDOMAINS

    async def _resolve(self, subdomain: str) -> Optional[str]:
        fqdn = f"{subdomain}.{self.domain}"
        async with self.semaphore:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                await resolver.resolve(fqdn, "A")
                return fqdn
            except (dns.exception.DNSException, Exception):
                return None

    async def _crt_sh_lookup(self) -> list[str]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower()
                                if sub.endswith(f".{self.domain}") and "*" not in sub:
                                    subdomains.add(sub)
        except Exception as e:
            console.print(f"[yellow]crt.sh lookup failed: {e}[/yellow]")
        return list(subdomains)

    async def run(self) -> list[str]:
        found = set()

        # Phase 1: crt.sh
        if self.use_crt:
            console.print("[bold]>> Certificate Transparency (crt.sh)[/bold]")
            with console.status("[cyan]Querying crt.sh...[/cyan]"):
                crt_results = await self._crt_sh_lookup()

            if crt_results:
                console.print(f"   [green]Found {len(crt_results)} subdomains via crt.sh[/green]")
                found.update(crt_results)
            else:
                console.print("   [dim]No results from crt.sh[/dim]")

        # Phase 2: DNS brute-force
        console.print(f"\n[bold]>> DNS Brute-Force ({len(self.wordlist)} words, {self.threads} threads)[/bold]")

        tasks = [self._resolve(word) for word in self.wordlist]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(tasks))
            brute_found = []

            for coro in asyncio.as_completed(tasks):
                result = await coro
                progress.advance(task)
                if result:
                    brute_found.append(result)
                    found.add(result)

        console.print(f"   [green]Found {len(brute_found)} subdomains via brute-force[/green]")

        # Display results table
        self.found = sorted(found)
        self._print_results()
        return self.found

    def _print_results(self):
        if not self.found:
            console.print("\n[yellow]No subdomains found.[/yellow]")
            return

        table = Table(
            title=f"Subdomains found for [bold cyan]{self.domain}[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Subdomain", style="bold white")

        for i, sub in enumerate(self.found, 1):
            table.add_row(str(i), sub)

        console.print()
        console.print(table)
        console.print(f"\n[bold green]Total:[/bold green] {len(self.found)} subdomains found\n")
