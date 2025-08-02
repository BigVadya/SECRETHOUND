import asyncio
import aiohttp
import aiofiles
import re
import os
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import Set, List, Optional, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from .file_formats import WEB_TARGET_EXTENSIONS, CDN_DOMAINS

console = Console()

class WebScanner:
    """
    Сканер для загрузки и анализа файлов с веб-сервисов
    """
    
    def __init__(self, max_depth: int = 3, max_file_size: int = 10 * 1024 * 1024, 
                 follow_redirects: bool = True, respect_robots_txt: bool = True,
                 delay_between_requests: float = 0.1):
        self.max_depth = max_depth
        self.max_file_size = max_file_size
        self.follow_redirects = follow_redirects
        self.respect_robots_txt = respect_robots_txt
        self.delay_between_requests = delay_between_requests
        self.session: Optional[aiohttp.ClientSession] = None
        self.visited_urls: Set[str] = set()
        self.downloaded_files: List[Path] = []
        self.url_depth_map: Dict[str, int] = {}  # Отслеживаем глубину для каждого URL
        
        # Используем конфигурацию из file_formats.py
        self.target_extensions = WEB_TARGET_EXTENSIONS
        self.cdn_domains = CDN_DOMAINS
    
    async def __aenter__(self):
        # Создаем SSL контекст, который игнорирует ошибки сертификатов
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        # Настраиваем сессию с учетом параметров
        timeout = aiohttp.ClientTimeout(total=30)
        headers = {'User-Agent': 'SecretHound/1.0'}
        
        # Если не следуем редиректам, добавляем соответствующий заголовок
        if not self.follow_redirects:
            headers['X-No-Redirect'] = 'true'
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers=headers,
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
        
        # Проверяем robots.txt если включено
        if self.respect_robots_txt:
            if self._is_disallowed_by_robots(url):
                return True
            
        return False
    
    def _is_disallowed_by_robots(self, url: str) -> bool:
        """Проверяет, запрещен ли URL в robots.txt"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            
            # Кэшируем robots.txt для каждого домена
            if not hasattr(self, '_robots_cache'):
                self._robots_cache = {}
            
            if parsed.netloc not in self._robots_cache:
                # Здесь можно добавить асинхронную загрузку robots.txt
                # Пока просто возвращаем False (не запрещено)
                self._robots_cache[parsed.netloc] = False
            
            return self._robots_cache[parsed.netloc]
        except Exception:
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
            # Настраиваем параметры запроса
            request_kwargs = {}
            if not self.follow_redirects:
                request_kwargs['allow_redirects'] = False
            
            async with self.session.get(url, **request_kwargs) as response:
                if response.status != 200:
                    return None
                
                content_type = response.headers.get('content-type', '').lower()
                content_length = int(response.headers.get('content-length', 0))
                
                # Check size
                if content_length > self.max_file_size:
                    console.print(f"[yellow]Skipping large file: {url} ({content_length} bytes)[/yellow]")
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
                console.print(f"[green]✓ Downloaded: {url} -> {file_path.name}[/green]")
                return file_path
                
        except Exception as e:
            console.print(f"[red]✗ Download error {url}: {e}[/red]")
            return None
    
    async def _extract_links(self, html_content: str, base_url: str, current_depth: int = 0) -> Set[str]:
        """Извлекает ссылки из HTML с учетом глубины поиска"""
        links = set()
        
        # Расширенные паттерны для поиска ссылок
        link_patterns = [
            # Стандартные ссылки на файлы
            r'src=["\']([^"\']*\.(?:js|ts|jsx|tsx|json|xml|html|htm|css|scss|sass|less|txt|md|yaml|yml|vue|svelte|astro|php|asp|aspx|jsp)[^"\']*)["\']',
            r'href=["\']([^"\']*\.(?:css|html|htm|xml|pdf|doc|docx)[^"\']*)["\']',
            r'url\(["\']?([^"\')\s]+\.(?:js|css|json|xml|ya?ml|png|jpe?g|gif|svg|ico|woff2?|ttf|eot)(\?[^"\')\s]*)?)["\']?\)'

            # Конфигурационные файлы
            r'["\']([^"\']*\.(?:env|config|conf|ini|toml|properties|lock|lockfile|gitignore|dockerignore|editorconfig)[^"\']*)["\']',
            
            # Package managers
            r'["\']([^"\']*(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|Pipfile|poetry\.lock|Cargo\.toml|composer\.json|Gemfile|pom\.xml|build\.gradle|go\.mod|pubspec\.yaml|mix\.exs)[^"\']*)["\']',
            
            # CI/CD файлы
            r'["\']([^"\']*\.(?:travis\.yml|gitlab-ci\.yml|jenkins|jenkinsfile|circleci/config\.yml)[^"\']*)["\']',
            
            # API и схемы
            r'["\']([^"\']*\.(?:swagger|openapi|graphql|gql|wsdl|xsd)[^"\']*)["\']',
            
            # Безопасность
            r'["\']([^"\']*\.(?:pem|key|crt|cer|p12|pfx|htaccess|htpasswd|htgroup|htdigest)[^"\']*)["\']',
            
            # Логи и отладка
            r'["\']([^"\']*\.(?:log|out|err|debug|trace|profile)[^"\']*)["\']',
            
            # Специальные форматы
            r'["\']([^"\']*\.(?:map|min\.js|min\.css|bundle\.js|chunk\.js|manifest|webmanifest|service-worker\.js)[^"\']*)["\']',
            
            # Дополнительные форматы
            r'["\']([^"\']*\.(?:csv|tsv|xls|xlsx|ods|sql|db|bak|backup|old|orig|tmp|temp|cache|session|cookie|localstorage)[^"\']*)["\']',
            
            # Ссылки на другие страницы (если глубина позволяет)
            r'href=["\']([^"\']*\.(?:html|htm|php|asp|aspx|jsp)[^"\']*)["\']',
            r'action=["\']([^"\']*\.(?:php|asp|aspx|jsp)[^"\']*)["\']',
            
            # API endpoints
            r'["\']([^"\']*/api/[^"\']*)["\']',
            r'["\']([^"\']*/v[0-9]+/[^"\']*)["\']',
            
            # GraphQL endpoints
            r'["\']([^"\']*/graphql[^"\']*)["\']',
            
            # WebSocket endpoints
            r'["\']([^"\']*/ws[^"\']*)["\']',
            r'["\']([^"\']*/socket\.io[^"\']*)["\']',
            
            # Статические ресурсы
            r'["\']([^"\']*/static/[^"\']*)["\']',
            r'["\']([^"\']*/assets/[^"\']*)["\']',
            r'["\']([^"\']*/public/[^"\']*)["\']',
            r'["\']([^"\']*/dist/[^"\']*)["\']',
            r'["\']([^"\']*/build/[^"\']*)["\']',
            
            # Документация
            r'["\']([^"\']*/docs/[^"\']*)["\']',
            r'["\']([^"\']*/documentation/[^"\']*)["\']',
            r'["\']([^"\']*/api-docs/[^"\']*)["\']',
            
            # Конфигурационные файлы в корне
            r'["\']([^"\']*/(?:robots\.txt|sitemap\.xml|favicon\.ico)[^"\']*)["\']',
        ]
        
        for pattern in link_patterns:
            try:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    full_url = urljoin(base_url, match)
                    
                    # Проверяем глубину для внутренних ссылок
                    if current_depth < self.max_depth:
                        if not self._should_skip_url(full_url):
                            links.add(full_url)
                    else:
                        # At maximum depth download only files, not pages
                        if self._is_file_url(full_url):
                            if not self._should_skip_url(full_url):
                                links.add(full_url)
                                
            except re.error as e:
                console.print(f"[yellow]Regex error: {e}[/yellow]")
        
        return links
    
    def _is_file_url(self, url: str) -> bool:
        """Проверяет, является ли URL файлом, а не страницей"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Проверяем расширения файлов
        for ext in self.target_extensions:
            if path.endswith(ext.lower()):
                return True
        
        # Проверяем специальные файлы
        special_files = {
            'robots.txt', 'sitemap.xml', 'favicon.ico', 'manifest.json',
            'sw.js', 'service-worker.js', 'webmanifest'
        }
        
        filename = path.split('/')[-1]
        if filename in special_files:
            return True
            
        return False
    
    async def scan_website(self, base_url: str, output_dir: Path) -> List[Path]:
        """Scans website and downloads files with search depth consideration"""
        console.print(f"[cyan]🔍 Starting scan: {base_url} (depth: {self.max_depth})[/cyan]")
        
        # Extract domain from URL
        parsed_url = urlparse(base_url)
        domain = parsed_url.netloc
        
        # Create domain folder inside web_files
        domain_dir = output_dir / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        console.print(f"[cyan]📁 Files will be saved to: {domain_dir}[/cyan]")
        
        # Start recursive scanning
        await self._scan_recursive(base_url, domain_dir, depth=0)
        
        console.print(f"[green]✅ Scanning completed. Downloaded files: {len(self.downloaded_files)}[/green]")
        return self.downloaded_files
    
    async def _scan_recursive(self, url: str, output_dir: Path, depth: int = 0):
        """Recursively scans website with depth consideration"""
        if depth > self.max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.url_depth_map[url] = depth
        
        console.print(f"[cyan]🔍 Scanning {url} (depth: {depth})[/cyan]")
        
        try:
            # Add delay between requests
            if self.delay_between_requests > 0:
                await asyncio.sleep(self.delay_between_requests)
            
            # Настраиваем параметры запроса
            request_kwargs = {}
            if not self.follow_redirects:
                request_kwargs['allow_redirects'] = False
            
            async with self.session.get(url, **request_kwargs) as response:
                if response.status == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    if 'text/html' in content_type:
                        # This is an HTML page - extract links and scan recursively
                        html_content = await response.text()
                        
                        # Save HTML page
                        filename = self._get_filename_from_url(url)
                        if not filename.endswith('.html'):
                            filename += '.html'
                        
                        file_path = output_dir / filename
                        counter = 1
                        while file_path.exists():
                            name, ext = os.path.splitext(filename)
                            file_path = output_dir / f"{name}_{counter}{ext}"
                            counter += 1
                        
                        async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                            await f.write(html_content)
                        self.downloaded_files.append(file_path)
                        
                        # Extract links for recursive scanning
                        links = await self._extract_links(html_content, url, depth)
                        
                        # Create tasks for recursive scanning
                        tasks = []
                        for link in links:
                            if link not in self.visited_urls:
                                task = self._scan_recursive(link, output_dir, depth + 1)
                                tasks.append(task)
                        
                        # Execute tasks in parallel (with limitation)
                        if tasks:
                            semaphore = asyncio.Semaphore(5)  # Maximum 5 concurrent requests
                            async def limited_scan(task):
                                async with semaphore:
                                    return await task
                            
                            await asyncio.gather(*[limited_scan(task) for task in tasks], return_exceptions=True)
                    
                    else:
                        # This is a file - download it
                        await self._download_file(url, output_dir)
                        
        except Exception as e:
            console.print(f"[red]Error scanning {url}: {e}[/red]")

async def download_and_scan_website(url: str, output_dir: Path, max_depth: int = 3, 
                                   max_file_size: int = 10 * 1024 * 1024,
                                   follow_redirects: bool = True, 
                                   respect_robots_txt: bool = True,
                                   delay_between_requests: float = 0.1) -> List[Path]:
    """Convenient function for downloading and scanning website with configurable parameters"""
    async with WebScanner(
        max_depth=max_depth,
        max_file_size=max_file_size,
        follow_redirects=follow_redirects,
        respect_robots_txt=respect_robots_txt,
        delay_between_requests=delay_between_requests
    ) as scanner:
        return await scanner.scan_website(url, output_dir) 