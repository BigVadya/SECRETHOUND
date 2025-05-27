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
from utils.duplicate_finder import DuplicateFinder
from difflib import SequenceMatcher
from typing import Dict, List, Set, Optional, Tuple

console = Console()

# ASCII Art Banner
BANNER = """
 ███████╗███████╗ ██████╗██████╗ ████████╗    ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
 ██╔════╝██╔════╝██╔════╝██╔══██╗╚══██╔══╝    ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
 ███████╗█████╗  ██║     ██████╔╝   ██║       ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
 ╚════██║██╔══╝  ██║     ██╔══██╗   ██║       ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
 ███████║███████╗╚██████╗██║  ██║   ██║       ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
 ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
                                                                                            
[bold cyan]A powerful tool for sniffing out secrets in your codebase[/bold cyan]
"""

# Оптимизированные цвета
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

# Создаем папку output, если она не существует
OUTPUT_DIR = Path('output')
OUTPUT_DIR.mkdir(exist_ok=True)

# Импорт паттернов будет происходить в main_async()
PATTERNS = None

class OptimizedScanner:
    """
    Основной класс для сканирования файлов на наличие чувствительных данных.
    Использует оптимизированные методы для быстрого поиска и обработки данных.
    """
    def __init__(self, custom_domains=None, max_workers=None, cache_dir=None, search_term=None):
        """
        Инициализация сканера.
        
        Args:
            custom_domains: Список пользовательских доменов для поиска
            max_workers: Максимальное количество рабочих процессов
            cache_dir: Директория для кэширования результатов
            search_term: Строка для поиска в файлах
        """
        global PATTERNS
        if PATTERNS is None:
            raise ValueError("PATTERNS не инициализированы. Убедитесь, что main_async() был вызван первым.")
            
        self.compiled_patterns = self._compile_patterns()
        self.custom_domain_pattern = self._compile_custom_domains(custom_domains)
        self.file_cache = {}
        self.max_workers = max_workers or (os.cpu_count() * 2)
        self.cache_dir = cache_dir
        self.search_term = search_term
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        
    def _compile_patterns(self):
        """
        Компилирует регулярные выражения для поиска чувствительных данных.
        Оптимизирует флаги для более быстрого поиска.
        """
        compiled = {}
        for name, pattern in PATTERNS.items():
            if isinstance(pattern, str):
                # Используем IGNORECASE для поиска без учета регистра
                # и MULTILINE для поиска по всем строкам
                flags = re.IGNORECASE | re.MULTILINE
                compiled[name] = re.compile(pattern, flags)
            else:
                compiled[name] = pattern
        return compiled
    
    def _compile_custom_domains(self, domains):
        """
        Компилирует регулярное выражение для поиска пользовательских доменов.
        
        Args:
            domains: Список доменов для поиска
        """
        if not domains:
            return None
        escaped = "|".join(re.escape(d.strip()) for d in domains if d.strip())
        if not escaped:
            return None
        pattern = rf"https?://(?:[\w-]+\.)*(?:{escaped})(?::\d+)?(?:/\S*)?"
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    
    def _get_file_hash(self, file_path):
        """
        Вычисляет MD5 хеш файла для кэширования.
        
        Args:
            file_path: Путь к файлу
        """
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return None
    
    def _get_cache_path(self, file_path):
        """
        Получает путь к файлу кэша для конкретного файла.
        
        Args:
            file_path: Путь к файлу
        """
        if not self.cache_dir:
            return None
        file_hash = self._get_file_hash(file_path)
        if not file_hash:
            return None
        return os.path.join(self.cache_dir, f"{file_hash}.json")
    
    def _load_from_cache(self, file_path):
        """
        Загружает результаты сканирования из кэша.
        
        Args:
            file_path: Путь к файлу
        """
        cache_path = self._get_cache_path(file_path)
        if not cache_path or not os.path.exists(cache_path):
            return None
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def _save_to_cache(self, file_path, results):
        """
        Сохраняет результаты сканирования в кэш.
        
        Args:
            file_path: Путь к файлу
            results: Результаты сканирования
        """
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
        """
        Проверяет, нужно ли пропустить файл при сканировании.
        Использует LRU кэш для оптимизации.
        
        Args:
            file_path_str: Строковый путь к файлу
        """
        path = Path(file_path_str)
        
        # Пропускаем файлы больше 50MB
        try:
            if path.stat().st_size > 50 * 1024 * 1024:  # 50MB
                return True
        except OSError:
            return True
            
        # Пропускаем исключенные директории
        return any(excl in path.parts for excl in EXCLUDE_DIRS)
    
    async def _read_file_async(self, file_path):
        """
        Асинхронно читает содержимое файла.
        Использует mmap для оптимизации чтения больших файлов.
        
        Args:
            file_path: Путь к файлу
        """
        try:
            file_size = file_path.stat().st_size
            
            with file_path.open('rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Для больших файлов используем буферизированное чтение
                    if file_size > 10 * 1024 * 1024:  # 10MB
                        buffer_size = 1024 * 1024  # 1MB буфер
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
    
    async def analyze_file_async(self, file_path, base_path):
        """
        Асинхронно анализирует файл на наличие чувствительных данных.
        
        Args:
            file_path: Путь к файлу
            base_path: Базовый путь для относительных путей
        """
        if self._should_skip_file(str(file_path)):
            return []
        
        # Проверяем кэш
        cached_results = self._load_from_cache(file_path)
        if cached_results is not None:
            return cached_results
            
        try:
            content = await self._read_file_async(file_path)
            if not content:
                return []
                
            rel_path = str(file_path.relative_to(base_path))
            
            # Если задан поисковый запрос, ищем его в файле
            if self.search_term:
                for line_num, line in enumerate(content.splitlines(), 1):
                    if self.search_term in line:
                        return [{
                            'file': rel_path,
                            'line': line_num,
                            'type': 'User Search',
                            'severity': 'info',
                            'snippet': line.strip(),
                            'hash': hashlib.md5(line.encode()).hexdigest()
                        }]
            else:
                # Обычное сканирование на чувствительные данные
                findings = []
                seen_hashes = set()
                
                # Разбиваем на строки только один раз
                lines = content.splitlines()
                
                # Проходим по строкам
                for line_num, line in enumerate(lines, 1):
                    if not line.strip():  # Пропускаем пустые строки
                        continue
                        
                    # Применяем все паттерны к строке
                    self._check_line_patterns(line, line_num, rel_path, findings, seen_hashes)
                    
                    # Проверяем кастомные домены
                    if self.custom_domain_pattern:
                        self._check_custom_domains(line, line_num, rel_path, findings, seen_hashes)
                    
                    # Даем возможность другим задачам выполниться каждые 1000 строк
                    if line_num % 1000 == 0:
                        await asyncio.sleep(0)
                    
            # Сохраняем результаты в кэш
            self._save_to_cache(file_path, findings)
            return findings

        except Exception as e:
            console.print(f"[red][ERROR] Error processing {file_path}: {e}[/red]")
            return []
    
    def _check_line_patterns(self, line, line_num, rel_path, findings, seen_hashes):
        """
        Проверяет строку на соответствие всем паттернам.
        
        Args:
            line: Текст строки
            line_num: Номер строки
            rel_path: Относительный путь к файлу
            findings: Список найденных совпадений
            seen_hashes: Множество уже найденных хешей
        """
        for pattern_name, compiled_pattern in self.compiled_patterns.items():
            for match in compiled_pattern.finditer(line):
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
    
    def _check_custom_domains(self, line, line_num, rel_path, findings, seen_hashes):
        """
        Проверяет строку на наличие пользовательских доменов.
        
        Args:
            line: Текст строки
            line_num: Номер строки
            rel_path: Относительный путь к файлу
            findings: Список найденных совпадений
            seen_hashes: Множество уже найденных хешей
        """
        for match in self.custom_domain_pattern.finditer(line):
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
    
    def _get_severity(self, pattern_name):
        """
        Определяет важность найденного совпадения.
        
        Args:
            pattern_name: Название паттерна
        """
        critical = ["Private Key PEM", "Password", "Credit Card", "API Key"]
        high = ["JWT Token", "Certificate", "Bank Account"]
        
        name_lower = pattern_name.lower()
        if any(crit.lower() in name_lower for crit in critical):
            return "critical"
        elif any(high_item.lower() in name_lower for high_item in high):
            return "high"
        else:
            return "medium"


async def scan_directory_async(path, extensions=None):
    """Асинхронное сканирование директории"""
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
                            # Даем возможность другим задачам выполниться
                            await asyncio.sleep(0)
        except PermissionError:
            console.print(f"[yellow][WARNING] Permission denied: {dir_path}[/yellow]")
        except Exception as e:
            console.print(f"[yellow][WARNING] Error scanning {dir_path}: {e}[/yellow]")
    
    await scan_dir(target_path)
    return files


def display_results_optimized(results):
    """Оптимизированный вывод результатов"""
    console.print("\n" + "=" * 60)
    console.print("[bold cyan][🔍] РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ[/bold cyan]", justify="center")
    console.print("=" * 60 + "\n")
    
    if not results:
        console.print("[green][✓] Не найдено чувствительных данных[/green]")
        return
    
    # Группируем по важности
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
    
    # Выводим по важности
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
            console.print(f"\n[bold][{color}]{item_type}[/][/bold] ({len(items)} найдено)")
            
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


class SensitiveDataScanner:
    """
    Класс для сканирования файлов на наличие чувствительных данных.
    Поддерживает параллельное сканирование.
    """
    def __init__(self, root_dir: str, exclude_dirs: Optional[Set[str]] = None):
        """
        Инициализация сканера.
        
        Args:
            root_dir: Корневая директория для сканирования
            exclude_dirs: Множество директорий для исключения
        """
        self.root_dir = Path(root_dir)
        self.exclude_dirs = exclude_dirs or set()
        self.console = Console()
        self.results: Dict[str, List[Dict]] = {}
        self.chunk_size = 1024 * 1024  # 1MB chunks for streaming
        
    async def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Сканирует один файл на наличие чувствительных данных.
        
        Args:
            file_path: Путь к файлу
            
        Returns:
            List[Dict]: Список найденных совпадений
        """
        findings = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_number = 0
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                        
                    lines = chunk.split('\n')
                    for line in lines:
                        line_number += 1
                        for pattern_name, pattern in PATTERNS.items():
                            if pattern.search(line):
                                findings.append({
                                    'pattern': pattern_name,
                                    'line': line_number,
                                    'content': line.strip()
                                })
        except Exception as e:
            self.console.print(f"[red]Error scanning {file_path}: {str(e)}[/red]")
            
        return findings

    async def scan_directory(self):
        """
        Сканирует директорию на наличие чувствительных данных.
        Использует параллельное сканирование файлов.
        """
        files_to_scan = []
        
        # Собираем все файлы для сканирования
        for root, dirs, files in os.walk(self.root_dir):
            # Пропускаем исключенные директории
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.is_file():
                    files_to_scan.append(file_path)

        # Обрабатываем файлы параллельно с ограничением количества одновременных операций
        sem = asyncio.Semaphore(10)  # Ограничение в 10 одновременных сканирований
        
        async def scan_with_semaphore(file_path: Path):
            async with sem:
                findings = await self.scan_file(file_path)
                if findings:
                    self.results[str(file_path)] = findings
                return file_path

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Scanning files...", total=len(files_to_scan))
            
            # Создаем задачи для всех файлов
            tasks = [scan_with_semaphore(f) for f in files_to_scan]
            
            # Обрабатываем файлы по мере их завершения
            for completed in asyncio.as_completed(tasks):
                await completed
                progress.advance(task)

    def display_results(self, results: List[Dict]):
        """
        Отображает результаты сканирования в консоли.
        
        Args:
            results: Список результатов сканирования
        """
        if not results:
            self.console.print("[green]Чувствительные данные не найдены![/green]")
            return
            
        # Группируем результаты по типу и уровню важности
        grouped_results = {}
        for result in results:
            key = (result['type'], result['severity'])
            if key not in grouped_results:
                grouped_results[key] = []
            grouped_results[key].append(result)
            
        # Сортируем группы по уровню важности и типу
        sorted_groups = sorted(
            grouped_results.items(),
            key=lambda x: (x[0][1] == 'critical', x[0][0])
        )
        
        self.console.print("\n" + "=" * 60)
        self.console.print(" " * 30 + "[🔍] РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
        self.console.print("=" * 60 + "\n")
        
        current_severity = None
        for (result_type, severity), type_results in sorted_groups:
            if severity != current_severity:
                current_severity = severity
                self.console.print(f"\n═══ {severity.upper()} SEVERITY ═══\n")
                
            # Создаем таблицу для текущей группы
            table = Table(title=f"{result_type} ({len(type_results)} найдено)")
            table.add_column("File", style="cyan")
            table.add_column("Line", justify="right", style="green")
            table.add_column("Snippet", style="yellow")
            
            # Добавляем строки в таблицу
            for result in type_results:
                table.add_row(
                    result['file'],
                    str(result['line']),
                    result['snippet']
                )
                
            self.console.print(table)
            
        # Выводим статистику
        self.console.print("\n" + "=" * 60)
        self.console.print("Статистика выполнения:")
        self.console.print(f"Обработано файлов: {self.stats['files_processed']}")
        self.console.print(f"Найдено совпадений (до очистки): {self.stats['matches_before_cleanup']}")
        self.console.print(f"Найдено совпадений (после очистки): {len(results)}")
        self.console.print(f"Время выполнения: {self.stats['execution_time']:.2f} сек.")
        self.console.print("=" * 60)

def parse_arguments():
    """
    Парсит аргументы командной строки.
    
    Returns:
        argparse.Namespace: Объект с аргументами
    """
    parser = argparse.ArgumentParser(description='Сканер чувствительных данных')
    parser.add_argument('-t', '--target', required=True,
                      help='Путь к директории или файлу для сканирования')
    parser.add_argument('-d', '--domains', 
                      help='Путь к файлу с пользовательскими доменами или строка с запятыми')
    parser.add_argument('-b', '--big-patterns', action='store_true', 
                      help='Использовать большой набор паттернов (sensitive_patterns_big.py)')
    parser.add_argument('-c', '--cache', 
                      help='Путь к директории для кэширования')
    parser.add_argument('-s', '--search',
                      help='Поиск конкретной строки в файлах')
    
    return parser.parse_args()

async def main_async():
    """
    Основная асинхронная функция программы.
    Обрабатывает аргументы командной строки и запускает сканирование.
    """
    start_time = time.perf_counter()
    
    # Парсим аргументы командной строки
    args = parse_arguments()
    
    # Выбираем набор паттернов
    global PATTERNS
    try:
        if args.big_patterns:
            from utils.sensitive_patterns_big import PATTERNS as BIG_PATTERNS
            PATTERNS = BIG_PATTERNS
            console.print("[cyan]Используется большой набор паттернов[/cyan]")
        else:
            from utils.sensitive_patterns import PATTERNS as STD_PATTERNS
            PATTERNS = STD_PATTERNS
            console.print("[cyan]Используется стандартный набор паттернов[/cyan]")
    except ImportError as e:
        console.print(f"[red][ERROR] Ошибка импорта паттернов: {e}[/red]")
        sys.exit(1)
    
    custom_domains = None
    if args.domains:
        if os.path.isfile(args.domains):
            try:
                with open(args.domains, 'r', encoding='utf-8') as f:
                    custom_domains = [line.strip() for line in f if line.strip()]
                console.print(f"[cyan]Загружены пользовательские домены из файла: {args.domains}[/cyan]")
            except Exception as e:
                console.print(f"[red][ERROR] Не удалось прочитать файл с доменами: {e}[/red]")
        else:
            # Если это не файл, пробуем разобрать как строку доменов через запятую
            custom_domains = [d.strip() for d in args.domains.split(',') if d.strip()]
            if custom_domains:
                console.print(f"[cyan]Используются пользовательские домены: {', '.join(custom_domains)}[/cyan]")
            else:
                console.print(f"[yellow][WARN] Не удалось разобрать домены из строки: {args.domains}[/yellow]")
    
    # Инициализируем сканер и запускаем сканирование
    scanner = OptimizedScanner(custom_domains, cache_dir=args.cache, search_term=args.search)
    if args.search:
        console.print(f"[cyan]Поиск строки: {args.search}[/cyan]")
    files = await scan_directory_async(args.target)
    
    if not files:
        console.print("[yellow]Нет файлов для сканирования[/yellow]")
        sys.exit(0)
    
    results = []
    base_path = Path(args.target).resolve()
    
    # Показываем прогресс сканирования
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=len(files))
        
        # Создаем задачи для каждого файла
        tasks = [scanner.analyze_file_async(file, base_path) for file in files]
        
        # Запускаем все задачи одновременно
        for completed_task in asyncio.as_completed(tasks):
            try:
                file_results = await completed_task
                results.extend(file_results)
            except Exception as e:
                console.print(f"[red][ERROR] Error processing file: {e}[/red]")
            finally:
                progress.update(task, advance=1)
    
    # Сохраняем неочищенные результаты в JSON файл
    raw_output_path = OUTPUT_DIR / 'raw_scan_results.json'
    with open(raw_output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Неочищенные результаты сохранены в файл {raw_output_path}[/green]")
    
    # Запускаем поиск дубликатов и очистку результатов
    finder = DuplicateFinder()
    cleaned_results = finder.clean_duplicates(results)
    
    # Сохраняем очищенные результаты
    cleaned_output_path = OUTPUT_DIR / 'scan_results.json'
    with open(cleaned_output_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned_results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Очищенные результаты сохранены в файл {cleaned_output_path}[/green]")
    
    # Выводим очищенные результаты
    display_results_optimized(cleaned_results)
    
    # Выводим статистику выполнения
    elapsed_time = time.perf_counter() - start_time
    console.print("\n" + "=" * 60)
    console.print(f"[cyan]Статистика выполнения:[/cyan]")
    console.print(f"[green]Обработано файлов:[/green] {len(files)}")
    console.print(f"[green]Найдено совпадений (до очистки):[/green] {len(results)}")
    console.print(f"[green]Найдено совпадений (после очистки):[/green] {len(cleaned_results)}")
    console.print(f"[green]Время выполнения:[/green] {elapsed_time:.2f} сек.")
    console.print("=" * 60 + "\n")

def main():
    """
    Точка входа в программу.
    Запускает асинхронную основную функцию.
    """
    # Отображаем баннер
    console.print(BANNER)
    console.print("\n")
    
    # Запускаем основную функцию
    asyncio.run(main_async())


if __name__ == "__main__":
    main()