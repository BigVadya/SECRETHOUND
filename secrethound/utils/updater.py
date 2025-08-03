"""
Module for automatic updating of SecretHound
Updates dependencies and checks project functionality
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
    """Class for automatic updating of SecretHound"""
    
    def __init__(self):
        # Try to find project root directory
        current_path = Path.cwd()
        self.project_root = None
        self.pyproject_path = None
        self.requirements_path = None
        
        # First try to find through relative path from module
        try:
            module_path = Path(__file__)
            # Look for pyproject.toml in parent directories from module
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
        
        # If not found through module, search in current directory and parent directories
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
        
        # Debug information
        print(f"🔍 Debug: current directory = {current_path}")
        print(f"🔍 Debug: project_root = {self.project_root}")
        print(f"🔍 Debug: pyproject_path = {self.pyproject_path}")
        if self.pyproject_path:
            print(f"🔍 Debug: pyproject_path.exists() = {self.pyproject_path.exists()}")
        
    def run_command(self, cmd: str, description: str) -> Tuple[bool, str]:
        """Executes command and returns result"""
        console.print(f"🔄 {description}...")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                console.print(f"✅ {description} - success")
                return True, result.stdout.strip()
            else:
                console.print(f"❌ {description} - error")
                console.print(f"   Error: {result.stderr.strip()}")
                return False, result.stderr.strip()
        except Exception as e:
            console.print(f"❌ {description} - exception: {e}")
            return False, str(e)
    
    def check_python_version(self) -> bool:
        """Checks Python version"""
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            console.print("❌ Python 3.8 or higher required")
            return False
        console.print(f"✅ Python {version.major}.{version.minor}.{version.micro}")
        return True
    
    def get_current_dependencies(self) -> List[str]:
        """Gets current dependencies from pyproject.toml"""
        if not self.pyproject_path.exists():
            return []
        
        with open(self.pyproject_path, 'r') as f:
            content = f.read()
        
        # Extract dependencies
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
        """Updates project dependencies"""
        console.print("\n📦 Updating dependencies...")
        
        # Core dependencies for updating (without fixed versions)
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
        
        console.print(f"📊 Updated {success_count}/{len(core_dependencies)} dependencies")
        return success_count == len(core_dependencies)
    
    def test_project_modules(self) -> bool:
        """Tests functionality of all project modules"""
        console.print("\n🧪 Testing project modules...")
        
        tests = [
            ("python -c 'import secrethound'", "Import main module"),
            ("python -c 'from secrethound.utils.sensitive_patterns import PATTERNS; print(f\"Loaded {len(PATTERNS)} patterns\")'", "Load standard patterns"),
            ("python -c 'from secrethound.utils.sensitive_patterns_big import PATTERNS; print(f\"Loaded {len(PATTERNS)} extended patterns\")'", "Load extended patterns"),
            ("python -c 'from secrethound.utils.duplicate_finder import DuplicateFinder'", "Test DuplicateFinder"),
            ("python -c 'from secrethound.utils.web_scanner import WebScanner'", "Test WebScanner"),
            ("python -c 'from secrethound.utils.file_formats import SUPPORTED_EXTENSIONS'", "Test file_formats"),
            ("python -m secrethound.main --help", "Test CLI interface")
        ]
        
        success_count = 0
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Testing modules...", total=len(tests))
            
            for cmd, description in tests:
                success, _ = self.run_command(cmd, description)
                if success:
                    success_count += 1
                progress.advance(task)
        
        console.print(f"📊 Tested {success_count}/{len(tests)} modules")
        return success_count == len(tests)
    
    def update_version(self) -> bool:
        """Updates project version"""
        console.print("\n📝 Updating project version...")
        
        if not self.pyproject_path.exists():
            console.print("❌ pyproject.toml file not found")
            return False
        
        with open(self.pyproject_path, 'r') as f:
            content = f.read()
        
        # Look for version line
        version_match = re.search(r'version = "(\d+\.\d+\.\d+)"', content)
        if not version_match:
            console.print("❌ Failed to find version in pyproject.toml")
            return False
        
        current_version = version_match.group(1)
        major, minor, patch = map(int, current_version.split('.'))
        new_version = f"{major}.{minor}.{patch + 1}"
        
        # Update version
        new_content = re.sub(r'version = "\d+\.\d+\.\d+"', f'version = "{new_version}"', content)
        
        with open(self.pyproject_path, 'w') as f:
            f.write(new_content)
        
        console.print(f"✅ Version updated: {current_version} → {new_version}")
        return True
    
    def clean_dependencies(self) -> bool:
        """Cleans dependencies from fixed versions"""
        console.print("\n🧹 Cleaning dependencies from fixed versions...")
        
        # Update pyproject.toml
        if self.pyproject_path.exists():
            with open(self.pyproject_path, 'r') as f:
                content = f.read()
            
            # Replace fixed versions with minimum requirements
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
            
            console.print("✅ pyproject.toml cleaned from fixed versions")
        
        # Update requirements.txt
        if self.requirements_path.exists():
            with open(self.requirements_path, 'r') as f:
                content = f.read()
            
            # Replace fixed versions with minimum requirements
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
            
            console.print("✅ requirements.txt cleaned from fixed versions")
        
        return True
    
    def show_status(self) -> None:
        """Shows current project status"""
        console.print("\n📊 SecretHound Project Status")
        
        # Check Python version
        version = sys.version_info
        console.print(f"🐍 Python: {version.major}.{version.minor}.{version.micro}")
        
        # Check project version
        if self.pyproject_path.exists():
            with open(self.pyproject_path, 'r') as f:
                content = f.read()
            version_match = re.search(r'version = "(\d+\.\d+\.\d+)"', content)
            if version_match:
                console.print(f"📦 Project version: {version_match.group(1)}")
        
        # Show dependencies
        dependencies = self.get_current_dependencies()
        if dependencies:
            table = Table(title="Project Dependencies")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="green")
            
            for dep in dependencies:
                if '>=' in dep:
                    package, version = dep.split('>=', 1)
                    table.add_row(package, f">= {version}")
                else:
                    table.add_row(dep, "any")
            
            console.print(table)
    
    def run_full_update(self) -> bool:
        """Performs full project update"""
        console.print("🚀 Starting full SecretHound update...")
        
        # Check that we are in project root directory
        if not self.project_root or not self.pyproject_path or not self.pyproject_path.exists():
            console.print("❌ Failed to find pyproject.toml file")
            console.print("   Make sure you are in the SecretHound project root directory")
            console.print(f"   Current directory: {Path.cwd()}")
            if self.project_root:
                console.print(f"   Found root directory: {self.project_root}")
            return False
        
        # Show current status
        self.show_status()
        
        # Check Python version
        if not self.check_python_version():
            return False
        
        # Clean dependencies from fixed versions
        if not self.clean_dependencies():
            console.print("❌ Error cleaning dependencies")
            return False
        
        # Update dependencies
        if not self.update_dependencies():
            console.print("❌ Error updating dependencies")
            return False
        
        # Test project
        if not self.test_project_modules():
            console.print("❌ Error testing project")
            return False
        
        # Update version
        if not self.update_version():
            console.print("❌ Error updating version")
            return False
        
        console.print("\n🎉 SecretHound update completed successfully!")
        console.print("📋 What was done:")
        console.print("   ✅ Dependencies cleaned from fixed versions")
        console.print("   ✅ Dependencies updated to latest versions")
        console.print("   ✅ All modules functionality tested")
        console.print("   ✅ Project version updated")
        console.print("\n💡 For usage:")
        console.print("   python -m secrethound.main -t <path>")
        console.print("   or after installation: secrethound -t <path>")
        
        return True

def main():
    """Main function for running update"""
    updater = SecretHoundUpdater()
    success = updater.run_full_update()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 