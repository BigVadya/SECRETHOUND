import asyncio
import aiohttp
import aiofiles
import re
import os
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import Set, List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

class WebScanner:
    """
    Сканер для загрузки и анализа файлов с веб-сервисов
    """
    
    def __init__(self, max_depth: int = 2, max_file_size: int = 1024 * 1024):
        self.max_depth = max_depth
        self.max_file_size = max_file_size
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: Set[str] = set()
        self.downloaded_files: List[Path] = []
        
        # Расширения файлов для скачивания
        self.target_extensions = {
            '.js', '.ts', '.jsx', '.tsx', '.json', '.xml', 
            '.html', '.htm', '.css', '.txt', '.md', '.yaml', '.yml'
        }
        
        # CDN домены для исключения
        self.cdn_domains = {
            'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net',
            'code.jquery.com', 'cdn.jsdelivr.net', 'stackpath.bootstrapcdn.com'
        }
    
    async def __aenter__(self):
        # Создаем SSL контекст, который игнорирует ошибки сертификатов
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'SecretHound/1.0'},
            connector=connector
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _should_skip_url(self, url: str) -> bool:
        """Проверяет, нужно ли пропустить URL"""
        parsed = urlparse(url)
        
        # Пропускаем CDN
        if any(cdn in parsed.netloc for cdn in self.cdn_domains):
            return True
            
        # Пропускаем уже посещенные
        if url in self.visited_urls:
            return True
            
        # Пропускаем не-HTTP(S)
        if parsed.scheme not in ('http', 'https'):
            return True
            
        return False
    
    def _get_filename_from_url(self, url: str) -> str:
        """Извлекает имя файла из URL"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Получаем имя файла из пути
        filename = path.split('/')[-1]
        
        # Если имя файла пустое или нет расширения, генерируем
        if not filename or '.' not in filename:
            content_type = 'text/plain'  # будет обновлено позже
            ext = self._get_file_extension(url, content_type)
            filename = f"file_{len(self.downloaded_files):04d}{ext}"
        
        return filename
    
    def _get_file_extension(self, url: str, content_type: str) -> str:
        """Определяет расширение файла"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Из URL
        for ext in self.target_extensions:
            if path.endswith(ext):
                return ext
        
        # Из Content-Type
        if 'javascript' in content_type:
            return '.js'
        elif 'json' in content_type:
            return '.json'
        elif 'html' in content_type:
            return '.html'
        elif 'css' in content_type:
            return '.css'
        elif 'xml' in content_type:
            return '.xml'
        
        return '.txt'
    
    async def _download_file(self, url: str, output_dir: Path) -> Optional[Path]:
        """Скачивает один файл"""
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                
                content_type = response.headers.get('content-type', '').lower()
                content_length = int(response.headers.get('content-length', 0))
                
                # Проверяем размер
                if content_length > self.max_file_size:
                    console.print(f"[yellow]Пропускаем большой файл: {url} ({content_length} bytes)[/yellow]")
                    return None
                
                # Читаем содержимое
                content = await response.read()
                
                # Получаем оригинальное имя файла
                original_filename = self._get_filename_from_url(url)
                
                # Проверяем, не существует ли уже файл с таким именем
                file_path = output_dir / original_filename
                counter = 1
                while file_path.exists():
                    name, ext = os.path.splitext(original_filename)
                    file_path = output_dir / f"{name}_{counter}{ext}"
                    counter += 1
                
                # Сохраняем файл
                async with aiofiles.open(file_path, 'wb') as f:
                    await f.write(content)
                
                self.downloaded_files.append(file_path)
                console.print(f"[green]✓ Скачан: {url} -> {file_path.name}[/green]")
                return file_path
                
        except Exception as e:
            console.print(f"[red]✗ Ошибка скачивания {url}: {e}[/red]")
            return None
    
    async def _extract_links(self, html_content: str, base_url: str) -> Set[str]:
        """Извлекает ссылки из HTML"""
        links = set()
        
        # Ищем ссылки на файлы
        js_patterns = [
            r'src=["\']([^"\']*\.js[^"\']*)["\']',
            r'href=["\']([^"\']*\.css[^"\']*)["\']',
            r'url\(["\']?([^"\')\s]*\.(?:js|css|json|xml|yaml|yml)["\']?\)',
        ]
        
        for pattern in js_patterns:
            try:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    full_url = urljoin(base_url, match)
                    if not self._should_skip_url(full_url):
                        links.add(full_url)
            except re.error as e:
                console.print(f"[yellow]Ошибка в регулярном выражении: {e}[/yellow]")
        
        return links
    
    async def scan_website(self, base_url: str, output_dir: Path) -> List[Path]:
        """Сканирует веб-сайт и скачивает файлы"""
        console.print(f"[cyan]🔍 Начинаю сканирование: {base_url}[/cyan]")
        
        # Извлекаем домен из URL
        parsed_url = urlparse(base_url)
        domain = parsed_url.netloc
        
        # Создаем папку с доменом внутри web_files
        domain_dir = output_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        console.print(f"[cyan]📁 Файлы будут сохранены в: {domain_dir}[/cyan]")
        
        # Скачиваем главную страницу
        try:
            async with self.session.get(base_url) as response:
                if response.status == 200:
                    html_content = await response.text()
                    
                    # Сохраняем главную страницу
                    main_file = domain_dir / "index.html"
                    async with aiofiles.open(main_file, 'w', encoding='utf-8') as f:
                        await f.write(html_content)
                    self.downloaded_files.append(main_file)
                    
                    # Извлекаем ссылки
                    links = await self._extract_links(html_content, base_url)
                    
                    # Скачиваем найденные файлы
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=console
                    ) as progress:
                        task = progress.add_task("Скачивание файлов...", total=len(links))
                        
                        for link in links:
                            await self._download_file(link, domain_dir)
                            progress.advance(task)
                            
        except Exception as e:
            console.print(f"[red]Ошибка при сканировании {base_url}: {e}[/red]")
        
        console.print(f"[green]✅ Сканирование завершено. Скачано файлов: {len(self.downloaded_files)}[/green]")
        return self.downloaded_files

async def download_and_scan_website(url: str, output_dir: Path) -> List[Path]:
    """Удобная функция для скачивания и сканирования веб-сайта"""
    async with WebScanner() as scanner:
        return await scanner.scan_website(url, output_dir) 