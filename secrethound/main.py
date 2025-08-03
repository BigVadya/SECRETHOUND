import sys
import re
import json
import time
import mmap
import os
import asyncio
import hashlib
import argparse
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import lru_cache
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn, TaskProgressColumn
from rich.panel import Panel
from rich import print as rprint
from .utils.duplicate_finder import DuplicateFinder
from .utils.web_scanner import download_and_scan_website
from difflib import SequenceMatcher
from typing import Dict, List, Set, Optional, Tuple

console = Console()

BANNER = r"""
 ███████╗███████╗ ██████╗██████╗ ███████╗████████╗    ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
 ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
 ███████╗█████╗  ██║     ██████╔╝█████╗     ██║       ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
 ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║       ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
 ███████║███████╗╚██████╗██║  ██║███████╗   ██║       ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
 ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
                                                                                             
                                                / \__
                                               (    @\___
                                               /         O
                                              /   (_____/
                                            /_____/   U

                        [bold cyan]A powerful tool for sniffing out secrets in your codebase[/bold cyan]
"""

COLORS = {
    "Private Key PEM": "red bold",
    "Password": "red bold", 
    "Credit Card": "red bold",
    "API Key": "red",
    "JWT Token": "green",
    "Email": "yellow",
    "Phone": "cyan",
    "URL": "blue",
    "Default": "white",
}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".rb", ".php", ".cs",
    ".go", ".rs", ".json", ".yaml", ".yml", ".env", ".log", ".txt",
    ".html", ".xml", ".sql", ".md", ".conf", ".properties"
}

EXCLUDE_DIRS = {".git", "__pycache__", "venv", "node_modules", ".vscode"}

OUTPUT_DIR = Path('output')
OUTPUT_DIR.mkdir(exist_ok=True)

PATTERNS = None

def display_results_optimized(results):
    console.print("\n" + "=" * 60)
    console.print("[bold cyan][🔍] SCAN RESULTS[/bold cyan]", justify="center")
    console.print("=" * 60 + "\n")
    if not results:
        console.print("[green][✓] No sensitive data found[/green]")
        return
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results_by_severity = {}
    for item in results:
        severity = item.get("severity", "medium")
        if severity not in results_by_severity:
            results_by_severity[severity] = {}
        item_type = item["type"]
        if item_type not in results_by_severity[severity]:
            results_by_severity[severity][item_type] = []
        results_by_severity[severity][item_type].append(item)
    for severity in sorted(results_by_severity.keys(), key=lambda x: severity_order.get(x, 99)):
        severity_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue"
        }.get(severity, "white")
        console.print(f"\n[{severity_color}]═══ {severity.upper()} SEVERITY ═══[/{severity_color}]")
        for item_type, items in results_by_severity[severity].items():
            color = COLORS.get(item_type, COLORS["Default"])
            console.print(f"\n[bold][{color}]{item_type}[/][/bold] ({len(items)} found)")
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("File", style="cyan")
            table.add_column("Line", justify="right", style="green")
            table.add_column("Snippet", style="white")
            for item in items:
                table.add_row(
                    item["file"],
                    str(item["line"]),
                    item["snippet"]
                )
            console.print(table)

class OptimizedScanner:
    def __init__(self, custom_domains=None, max_workers=None, cache_dir=None, search_term=None):
        global PATTERNS
        if PATTERNS is None:
            raise ValueError("PATTERNS not initialized. Make sure main_async() was called first.")
        self.compiled_patterns = self._compile_patterns()
        self.custom_domain_pattern = self._compile_custom_domains(custom_domains)
        self.file_cache = {}
        self.max_workers = max_workers or (os.cpu_count() * 2)
        self.cache_dir = cache_dir
        self.search_term = search_term
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        self.process_pool = ProcessPoolExecutor(max_workers=self.max_workers)
    def _compile_patterns(self):
        compiled = {}
        for name, pattern in PATTERNS.items():
            if isinstance(pattern, str):
                flags = re.IGNORECASE | re.MULTILINE
                compiled[name] = re.compile(pattern, flags)
            else:
                compiled[name] = pattern
        return compiled
    def _compile_custom_domains(self, domains):
        if not domains:
            return None
        escaped = "|".join(re.escape(d.strip()) for d in domains if d.strip())
        if not escaped:
            return None
        pattern = rf"https?://(?:[\w-]+\.)*(?:{escaped})(?::\d+)?(?:/\S*)?"
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    def _get_file_hash(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return None
    def _get_cache_path(self, file_path):
        if not self.cache_dir:
            return None
        file_hash = self._get_file_hash(file_path)
        if not file_hash:
            return None
        return os.path.join(self.cache_dir, f"{file_hash}.json")
    def _load_from_cache(self, file_path):
        cache_path = self._get_cache_path(file_path)
        if not cache_path or not os.path.exists(cache_path):
            return None
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    def _save_to_cache(self, file_path, results):
        cache_path = self._get_cache_path(file_path)
        if not cache_path:
            return
        try:
            with open(cache_path, 'w') as f:
                json.dump(results, f)
        except Exception:
            pass
    @lru_cache(maxsize=1000)
    def _should_skip_file(self, file_path_str):
        path = Path(file_path_str)
        try:
            if path.stat().st_size > 50 * 1024 * 1024:
                return True
        except OSError:
            return True
        return any(excl in path.parts for excl in EXCLUDE_DIRS)
    async def _read_file_async(self, file_path):
        try:
            file_size = file_path.stat().st_size
            with file_path.open('rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    if file_size > 10 * 1024 * 1024:
                        buffer_size = 1024 * 1024
                        content = bytearray()
                        while True:
                            chunk = mm.read(buffer_size)
                            if not chunk:
                                break
                            content.extend(chunk)
                            await asyncio.sleep(0)
                        return content.decode('utf-8', errors='ignore')
                    else:
                        return mm.read().decode('utf-8', errors='ignore')
        except Exception as e:
            console.print(f"[yellow][WARNING] Cannot read {file_path}: {e}[/yellow]")
            return ""
    def _find_line_number(self, content, position):
        return content[:position].count('\n') + 1
    async def analyze_file_async(self, file_path, base_path, decode_unicode=False):
        if self._should_skip_file(str(file_path)):
            return []
        cached_results = self._load_from_cache(file_path)
        if cached_results is not None:
            return cached_results
        try:
            # Decode file before analysis if option is enabled
            if decode_unicode:
                decode_file(str(file_path))
                
            content = await self._read_file_async(file_path)
            if not content:
                return []
            rel_path = str(file_path.relative_to(base_path))
            findings = []
            seen_hashes = set()
            if self.search_term:
                for match in re.finditer(re.escape(self.search_term), content):
                    line_num = self._find_line_number(content, match.start())
                    findings.append({
                        'file': rel_path,
                        'line': line_num,
                        'type': 'User Search',
                        'severity': 'info',
                        'snippet': content[match.start():match.end()].strip(),
                        'hash': hashlib.md5(content[match.start():match.end()].encode()).hexdigest()
                    })
            else:
                for pattern_name, pattern in self.compiled_patterns.items():
                    for match in pattern.finditer(content):
                        line_num = self._find_line_number(content, match.start())
                        snippet = match.group(0)[:100]
                        finding_hash = hash((pattern_name, rel_path, line_num, snippet))
                        if finding_hash not in seen_hashes:
                            seen_hashes.add(finding_hash)
                            findings.append({
                                "type": pattern_name,
                                "file": rel_path,
                                "line": line_num,
                                "snippet": snippet,
                                "severity": self._get_severity(pattern_name)
                            })
                if self.custom_domain_pattern:
                    for match in self.custom_domain_pattern.finditer(content):
                        line_num = self._find_line_number(content, match.start())
                        snippet = match.group(0)[:100]
                        finding_hash = hash(("Custom Domain URL", rel_path, line_num, snippet))
                        if finding_hash not in seen_hashes:
                            seen_hashes.add(finding_hash)
                            findings.append({
                                "type": "Custom Domain URL",
                                "file": rel_path,
                                "line": line_num,
                                "snippet": snippet,
                                "severity": "medium"
                            })
            self._save_to_cache(file_path, findings)
            return findings
        except Exception as e:
            console.print(f"[red][ERROR] Error processing file: {e}[/red]")
            return []
    def _get_severity(self, pattern_name):
        critical = ["Private Key PEM", "Password", "Credit Card", "API Key"]
        high = ["JWT Token", "Certificate", "Bank Account"]
        name_lower = pattern_name.lower()
        if any(crit.lower() in name_lower for crit in critical):
            return "critical"
        elif any(high_item.lower() in name_lower for high_item in high):
            return "high"
        else:
            return "medium"

async def scan_directory_async(path, extensions=None, decode_unicode=False):
    target_path = Path(path).resolve()
    if target_path.is_file():
        return [target_path]
    if not target_path.exists():
        console.print(f"[red][ERROR] Path does not exist: {target_path}[/red]")
        return []
    files = []
    extensions = extensions or SUPPORTED_EXTENSIONS
    async def scan_dir(dir_path):
        try:
            with os.scandir(dir_path) as entries:
                for entry in entries:
                    if entry.is_dir():
                        if entry.name not in EXCLUDE_DIRS:
                            await scan_dir(entry.path)
                    elif entry.is_file():
                        if Path(entry.path).suffix in extensions:
                            files.append(Path(entry.path))
                            await asyncio.sleep(0)
        except PermissionError:
            console.print(f"[yellow][WARNING] Permission denied: {dir_path}[/yellow]")
        except Exception as e:
            console.print(f"[yellow][WARNING] Error scanning {dir_path}: {e}[/yellow]")
    await scan_dir(target_path)
    return files

def decode_file(path: str) -> None:
    """
    Reads file content, decodes unicode-escaped sequences and overwrites the file.
    """
    try:
        # Read original content
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Decode \uXXXX sequences
        try:
            decoded = content.encode('utf-8').decode('unicode-escape')
        except UnicodeDecodeError:
            # Fallback for files that can't be decoded as unicode-escape
            decoded = content

        # Overwrite file with decoded content
        with open(path, 'w', encoding='utf-8') as f:
            f.write(decoded)
            
        console.print(f"[green]✓ File '{path}' successfully decoded[/green]")
    except Exception as e:
        console.print(f"[red]✗ Error decoding file '{path}': {e}[/red]")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Sensitive data scanner')
    parser.add_argument('-t', '--target',
                      help='Path to directory or file for scanning (for local scanning)')
    parser.add_argument('-d', '--domains', 
                      help='Path to file with custom domains or comma-separated string')
    parser.add_argument('-b', '--big-patterns', action='store_true', 
                      help='Use large pattern set (sensitive_patterns_big.py)')
    parser.add_argument('-c', '--cache', 
                      help='Path to directory for caching')
    parser.add_argument('-s', '--search',
                      help='Search for specific string in files')
    parser.add_argument('-ud', '--decode-unicode', action='store_true',
                      help='Decode unicode escape sequences in files before scanning')
    parser.add_argument('-u', '--url', 
                      help='Website URL for scanning (downloads files and analyzes them)')
    parser.add_argument('--url-file', 
                      help='Path to file with list of URLs for scanning (one URL per line)')
    parser.add_argument('--web-output', default='web_files',
                      help='Folder for saving downloaded web files (default: web_files)')
    parser.add_argument('--web-depth', type=int, default=3,
                      help='Search depth for web scanning (default: 3)')
    parser.add_argument('--web-delay', type=float, default=0.1,
                      help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--web-max-size', type=int, default=10 * 1024 * 1024,
                      help='Maximum file size for download in bytes (default: 10MB)')
    parser.add_argument('--no-web-follow-redirects', action='store_true',
                      help='Disable following redirects during web scanning')
    parser.add_argument('--no-web-respect-robots', action='store_true',
                      help='Disable robots.txt compliance during web scanning')
    parser.add_argument('--update', action='store_true',
                      help='Update dependencies and project version')
    return parser.parse_args()

async def main_async():
    start_time = time.perf_counter()
    args = parse_arguments()
    
    # Check if update is needed
    if args.update:
        from .utils.updater import SecretHoundUpdater
        updater = SecretHoundUpdater()
        success = updater.run_full_update()
        sys.exit(0 if success else 1)
    
    # Check that either target or url is specified
    if not args.target and not args.url and not args.url_file:
        console.print("[red][ERROR] Must specify either -t/--target for local scanning, or -u/--url for web scanning, or --url-file for scanning from file[/red]")
        sys.exit(1)
    global PATTERNS
    try:
        if args.big_patterns:
            from .utils.sensitive_patterns_big import PATTERNS as BIG_PATTERNS
            PATTERNS = BIG_PATTERNS
            console.print("[cyan]Using large pattern set[/cyan]")
        else:
            from .utils.sensitive_patterns import PATTERNS as STD_PATTERNS
            PATTERNS = STD_PATTERNS
            console.print("[cyan]Using standard pattern set[/cyan]")
    except ImportError as e:
        console.print(f"[red][ERROR] Pattern import error: {e}[/red]")
        sys.exit(1)
    custom_domains = None
    if args.domains:
        if os.path.isfile(args.domains):
            try:
                with open(args.domains, 'r', encoding='utf-8') as f:
                    custom_domains = [line.strip() for line in f if line.strip()]
                console.print(f"[cyan]Loaded custom domains from file: {args.domains}[/cyan]")
            except Exception as e:
                console.print(f"[red][ERROR] Failed to read domains file: {e}[/red]")
        else:
            custom_domains = [d.strip() for d in args.domains.split(',') if d.strip()]
            if custom_domains:
                console.print(f"[cyan]Using custom domains: {', '.join(custom_domains)}[/cyan]")
            else:
                console.print(f"[yellow][WARN] Failed to parse domains from string: {args.domains}[/yellow]")
    scanner = OptimizedScanner(custom_domains, cache_dir=args.cache, search_term=args.search)
    if args.search:
        console.print(f"[cyan]Searching for string: {args.search}[/cyan]")
    if args.decode_unicode:
        console.print("[cyan]Unicode escape sequence decoding enabled[/cyan]")
    
    # Determine files for scanning
    if args.url:
        # Web scanning
        console.print(f"[cyan]🌐 Web scanning: {args.url}[/cyan]")
        console.print(f"[cyan]📊 Web scanning parameters:[/cyan]")
        console.print(f"[cyan]   • Depth: {args.web_depth}[/cyan]")
        console.print(f"[cyan]   • Delay: {args.web_delay} sec[/cyan]")
        console.print(f"[cyan]   • Max file size: {args.web_max_size // (1024*1024)}MB[/cyan]")
        console.print(f"[cyan]   • Follow redirects: {'No' if args.no_web_follow_redirects else 'Yes'}[/cyan]")
        console.print(f"[cyan]   • Respect robots.txt: {'No' if args.no_web_respect_robots else 'Yes'}[/cyan]")
        
        web_output_dir = Path(args.web_output)
        files = await download_and_scan_website(
            url=args.url,
            output_dir=web_output_dir,
            max_depth=args.web_depth,
            max_file_size=args.web_max_size,
            follow_redirects=not args.no_web_follow_redirects,
            respect_robots_txt=not args.no_web_respect_robots,
            delay_between_requests=args.web_delay
        )
        if not files:
            console.print("[yellow]Failed to download files from website[/yellow]")
            sys.exit(0)
    elif args.url_file:
        # Scanning from URL file
        console.print(f"[cyan]🌐 Scanning from URL file: {args.url_file}[/cyan]")
        files = []
        try:
            with open(args.url_file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
                console.print(f"[cyan]Found URLs for scanning: {len(urls)}[/cyan]")
                for url in urls:
                    if url:
                        console.print(f"[cyan]Scanning URL: {url}[/cyan]")
                        web_output_dir = Path(args.web_output)
                        web_output_dir.mkdir(exist_ok=True)
                        file_results = await download_and_scan_website(
                            url=url,
                            output_dir=web_output_dir,
                            max_depth=args.web_depth,
                            max_file_size=args.web_max_size,
                            follow_redirects=not args.no_web_follow_redirects,
                            respect_robots_txt=not args.no_web_respect_robots,
                            delay_between_requests=args.web_delay
                        )
                        if file_results:
                            files.extend(file_results)
                        else:
                            console.print(f"[yellow]Failed to download files from URL: {url}[/yellow]")
        except FileNotFoundError:
            console.print(f"[red][ERROR] URL file not found: {args.url_file}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red][ERROR] Error reading URL file: {e}[/red]")
            sys.exit(1)
    else:
        # Local scanning
        files = await scan_directory_async(args.target, decode_unicode=args.decode_unicode)
        if not files:
            console.print("[yellow]No files to scan[/yellow]")
            sys.exit(0)
    results = []
    
    # Determine base path for relative paths
    if args.url or args.url_file:
        base_path = Path(args.web_output).resolve()
    else:
        base_path = Path(args.target).resolve()
    
    # For web scanning use absolute paths
    if args.url or args.url_file:
        files = [Path(file).resolve() for file in files]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=len(files))
        tasks = [scanner.analyze_file_async(file, base_path, args.decode_unicode) for file in files]
        for completed_task in asyncio.as_completed(tasks):
            try:
                file_results = await completed_task
                results.extend(file_results)
            except Exception as e:
                console.print(f"[red][ERROR] Error processing file: {e}[/red]")
            finally:
                progress.update(task, advance=1)
    raw_output_path = OUTPUT_DIR / 'raw_scan_results.json'
    with open(raw_output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Raw results saved to file {raw_output_path}[/green]")
    finder = DuplicateFinder()
    cleaned_results = finder.clean_duplicates(results)
    cleaned_output_path = OUTPUT_DIR / 'scan_results.json'
    with open(cleaned_output_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned_results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Cleaned results saved to file {cleaned_output_path}[/green]")
    display_results_optimized(cleaned_results)
    elapsed_time = time.perf_counter() - start_time
    console.print("\n" + "=" * 60)
    console.print(f"[cyan]Execution statistics:[/cyan]")
    console.print(f"[green]Files processed:[/green] {len(files)}")
    console.print(f"[green]Matches found (before cleaning):[/green] {len(results)}")
    console.print(f"[green]Matches found (after cleaning):[/green] {len(cleaned_results)}")
    console.print(f"[green]Execution time:[/green] {elapsed_time:.2f} sec.")
    console.print("=" * 60 + "\n")

def main():
    console.print(BANNER)
    console.print("\n")
    asyncio.run(main_async())

if __name__ == "__main__":
    main()