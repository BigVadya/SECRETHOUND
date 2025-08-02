"""
Модуль для автоматического обновления SecretHound
Обновляет зависимости и проверяет работоспособность проекта
"""

import subprocess
import sys
import os
import re
from pathlib import Path
from typing import List, Tuple, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

class SecretHoundUpdater:
    """Класс для автоматического обновления SecretHound"""
    
    def __init__(self):
        # Пытаемся найти корневую директорию проекта
        current_path = Path.cwd()
        self.project_root = None
        self.pyproject_path = None
        self.requirements_path = None
        
        # Сначала попробуем найти через относительный путь от модуля
        try:
            module_path = Path(__file__)
            # Ищем pyproject.toml в родительских директориях от модуля
            search_path = module_path.parent
            while search_path != search_path.parent:
                pyproject_candidate = search_path / "pyproject.toml"
                if pyproject_candidate.exists():
                    self.project_root = search_path
                    self.pyproject_path = pyproject_candidate
                    self.requirements_path = search_path / "requirements.txt"
                    break
                search_path = search_path.parent
        except Exception:
            pass
        
        # Если не нашли через модуль, ищем в текущей директории и родительских
        if not self.project_root:
            search_path = current_path
            while search_path != search_path.parent:
                pyproject_candidate = search_path / "pyproject.toml"
                if pyproject_candidate.exists():
                    self.project_root = search_path
                    self.pyproject_path = pyproject_candidate
                    self.requirements_path = search_path / "requirements.txt"
                    break
                search_path = search_path.parent
        
        # Отладочная информация
        print(f"🔍 Отладка: текущая директория = {current_path}")
        print(f"🔍 Отладка: project_root = {self.project_root}")
        print(f"🔍 Отладка: pyproject_path = {self.pyproject_path}")
        if self.pyproject_path:
            print(f"🔍 Отладка: pyproject_path.exists() = {self.pyproject_path.exists()}")
        
    def run_command(self, cmd: str, description: str) -> Tuple[bool, str]:
        """Выполняет команду и возвращает результат"""
        console.print(f"🔄 {description}...")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                console.print(f"✅ {description} - успешно")
                return True, result.stdout.strip()
            else:
                console.print(f"❌ {description} - ошибка")
                console.print(f"   Ошибка: {result.stderr.strip()}")
                return False, result.stderr.strip()
        except Exception as e:
            console.print(f"❌ {description} - исключение: {e}")
            return False, str(e)
    
    def check_python_version(self) -> bool:
        """Проверяет версию Python"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            console.print("❌ Требуется Python 3.8 или выше")
            return False
        console.print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    
    def get_current_dependencies(self) -> List[str]:
        """Получает текущие зависимости из pyproject.toml"""
        if not self.pyproject_path.exists():
            return []
        
        with open(self.pyproject_path, 'r') as f:
            content = f.read()
        
        # Извлекаем зависимости
        dependencies = []
        lines = content.split('\n')
        in_dependencies = False
        
        for line in lines:
            if 'dependencies = [' in line:
                in_dependencies = True
                continue
            elif in_dependencies and line.strip() == ']':
                break
            elif in_dependencies and line.strip().startswith('"'):
                dep = line.strip().strip('",')
                if dep and not dep.startswith('#'):
                    dependencies.append(dep)
        
        return dependencies
    
    def update_dependencies(self) -> bool:
        """Обновляет зависимости проекта"""
        console.print("\n📦 Обновление зависимостей...")
        
        # Основные зависимости для обновления (без фиксированных версий)
        core_dependencies = [
            "rich",
            "typer", 
            "aiofiles",
            "aiohttp"
        ]
        
        success_count = 0
        for dep in core_dependencies:
            cmd = f"pip install --user --break-system-packages --upgrade {dep}"
            success, _ = self.run_command(cmd, f"Обновление {dep}")
            if success:
                success_count += 1
        
        console.print(f"📊 Обновлено {success_count}/{len(core_dependencies)} зависимостей")
        return success_count == len(core_dependencies)
    
    def test_project_modules(self) -> bool:
        """Тестирует работоспособность всех модулей проекта"""
        console.print("\n🧪 Тестирование модулей проекта...")
        
        tests = [
            ("python -c 'import secrethound'", "Импорт основного модуля"),
            ("python -c 'from secrethound.utils.sensitive_patterns import PATTERNS; print(f\"Загружено {len(PATTERNS)} паттернов\")'", "Загрузка стандартных паттернов"),
            ("python -c 'from secrethound.utils.sensitive_patterns_big import PATTERNS; print(f\"Загружено {len(PATTERNS)} расширенных паттернов\")'", "Загрузка расширенных паттернов"),
            ("python -c 'from secrethound.utils.duplicate_finder import DuplicateFinder'", "Тест DuplicateFinder"),
            ("python -c 'from secrethound.utils.web_scanner import WebScanner'", "Тест WebScanner"),
            ("python -c 'from secrethound.utils.file_formats import SUPPORTED_EXTENSIONS'", "Тест file_formats"),
            ("python -m secrethound.main --help", "Тест CLI интерфейса")
        ]
        
        success_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Тестирование модулей...", total=len(tests))
            
            for cmd, description in tests:
                success, _ = self.run_command(cmd, description)
                if success:
                    success_count += 1
                progress.advance(task)
        
        console.print(f"📊 Протестировано {success_count}/{len(tests)} модулей")
        return success_count == len(tests)
    
    def update_version(self) -> bool:
        """Обновляет версию проекта"""
        console.print("\n📝 Обновление версии проекта...")
        
        if not self.pyproject_path.exists():
            console.print("❌ Файл pyproject.toml не найден")
            return False
        
        with open(self.pyproject_path, 'r') as f:
            content = f.read()
        
        # Ищем строку с версией
        version_match = re.search(r'version = "(\d+\.\d+\.\d+)"', content)
        if not version_match:
            console.print("❌ Не удалось найти версию в pyproject.toml")
            return False
        
        current_version = version_match.group(1)
        major, minor, patch = map(int, current_version.split('.'))
        new_version = f"{major}.{minor}.{patch + 1}"
        
        # Обновляем версию
        new_content = re.sub(r'version = "\d+\.\d+\.\d+"', f'version = "{new_version}"', content)
        
        with open(self.pyproject_path, 'w') as f:
            f.write(new_content)
        
        console.print(f"✅ Версия обновлена: {current_version} → {new_version}")
        return True
    
    def clean_dependencies(self) -> bool:
        """Очищает зависимости от фиксированных версий"""
        console.print("\n🧹 Очистка зависимостей от фиксированных версий...")
        
        # Обновляем pyproject.toml
        if self.pyproject_path.exists():
            with open(self.pyproject_path, 'r') as f:
                content = f.read()
            
            # Заменяем фиксированные версии на минимальные требования
            replacements = [
                (r'rich>=14\.1\.0', 'rich>=14.0.0'),
                (r'typer>=0\.16\.0', 'typer>=0.9.0'),
                (r'aiofiles>=24\.1\.0', 'aiofiles>=23.0.0'),
                (r'aiohttp>=3\.12\.0', 'aiohttp>=3.8.0'),
                (r'pytest>=7\.4\.3', 'pytest>=7.0.0'),
                (r'pytest-asyncio>=0\.21\.1', 'pytest-asyncio>=0.21.0'),
                (r'pytest-cov>=4\.1\.0', 'pytest-cov>=4.0.0')
            ]
            
            for old, new in replacements:
                content = re.sub(old, new, content)
            
            with open(self.pyproject_path, 'w') as f:
                f.write(content)
            
            console.print("✅ pyproject.toml очищен от фиксированных версий")
        
        # Обновляем requirements.txt
        if self.requirements_path.exists():
            with open(self.requirements_path, 'r') as f:
                content = f.read()
            
            # Заменяем фиксированные версии на минимальные требования
            replacements = [
                (r'rich>=14\.1\.0', 'rich>=14.0.0'),
                (r'typer>=0\.16\.0', 'typer>=0.9.0'),
                (r'aiofiles>=24\.1\.0', 'aiofiles>=23.0.0'),
                (r'aiohttp>=3\.12\.0', 'aiohttp>=3.8.0'),
                (r'pytest>=7\.4\.3', 'pytest>=7.0.0'),
                (r'pytest-asyncio>=0\.21\.1', 'pytest-asyncio>=0.21.0'),
                (r'pytest-cov>=4\.1\.0', 'pytest-cov>=4.0.0')
            ]
            
            for old, new in replacements:
                content = re.sub(old, new, content)
            
            with open(self.requirements_path, 'w') as f:
                f.write(content)
            
            console.print("✅ requirements.txt очищен от фиксированных версий")
        
        return True
    
    def show_status(self) -> None:
        """Показывает текущий статус проекта"""
        console.print("\n📊 Статус проекта SecretHound")
        
        # Проверяем версию Python
        version = sys.version_info
        console.print(f"🐍 Python: {version.major}.{version.minor}.{version.micro}")
        
        # Проверяем версию проекта
        if self.pyproject_path.exists():
            with open(self.pyproject_path, 'r') as f:
                content = f.read()
            version_match = re.search(r'version = "(\d+\.\d+\.\d+)"', content)
            if version_match:
                console.print(f"📦 Версия проекта: {version_match.group(1)}")
        
        # Показываем зависимости
        dependencies = self.get_current_dependencies()
        if dependencies:
            table = Table(title="Зависимости проекта")
            table.add_column("Пакет", style="cyan")
            table.add_column("Версия", style="green")
            
            for dep in dependencies:
                if '>=' in dep:
                    package, version = dep.split('>=', 1)
                    table.add_row(package, f">= {version}")
                else:
                    table.add_row(dep, "любая")
            
            console.print(table)
    
    def run_full_update(self) -> bool:
        """Выполняет полное обновление проекта"""
        console.print("🚀 Запуск полного обновления SecretHound...")
        
        # Проверяем, что мы в корневой директории проекта
        if not self.project_root or not self.pyproject_path or not self.pyproject_path.exists():
            console.print("❌ Не удалось найти файл pyproject.toml")
            console.print("   Убедитесь, что вы находитесь в корневой директории проекта SecretHound")
            console.print(f"   Текущая директория: {Path.cwd()}")
            if self.project_root:
                console.print(f"   Найденная корневая директория: {self.project_root}")
            return False
        
        # Показываем текущий статус
        self.show_status()
        
        # Проверяем версию Python
        if not self.check_python_version():
            return False
        
        # Очищаем зависимости от фиксированных версий
        if not self.clean_dependencies():
            console.print("❌ Ошибка при очистке зависимостей")
            return False
        
        # Обновляем зависимости
        if not self.update_dependencies():
            console.print("❌ Ошибка при обновлении зависимостей")
            return False
        
        # Тестируем проект
        if not self.test_project_modules():
            console.print("❌ Ошибка при тестировании проекта")
            return False
        
        # Обновляем версию
        if not self.update_version():
            console.print("❌ Ошибка при обновлении версии")
            return False
        
        console.print("\n🎉 Обновление SecretHound завершено успешно!")
        console.print("📋 Что было сделано:")
        console.print("   ✅ Очищены зависимости от фиксированных версий")
        console.print("   ✅ Обновлены зависимости до последних версий")
        console.print("   ✅ Протестирована работоспособность всех модулей")
        console.print("   ✅ Обновлена версия проекта")
        console.print("\n💡 Для использования:")
        console.print("   python -m secrethound.main -t <путь>")
        console.print("   или после установки: secrethound -t <путь>")
        
        return True

def main():
    """Основная функция для запуска обновления"""
    updater = SecretHoundUpdater()
    success = updater.run_full_update()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 