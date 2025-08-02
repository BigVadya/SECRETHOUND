# SecretHound 🐕‍🦺

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.16-brightgreen)](https://github.com/BigVadya/SECRETHOUND/releases)
[![GitHub Stars](https://img.shields.io/github/stars/BigVadya/SECRETHOUND?style=social)](https://github.com/BigVadya/SECRETHOUND/stargazers)

---

> **SecretHound** is a powerful and efficient tool for scanning files and directories to detect sensitive information such as private keys, passwords, API keys, and other confidential data. Like a trained hound, it sniffs out secrets in your codebase.

---

## 🚀 Features

- **Comprehensive Scanning**: Detects private keys, passwords, credit card numbers, API keys, JWT tokens, emails, phone numbers, URLs, and custom domains.
- **Web Scanning**: Downloads and analyzes files from web services, JavaScript files, and web applications with configurable depth.
- **Performance Optimized**: Asynchronous file processing, parallel scanning, memory-mapped file reading, LRU caching, and chunked reading for large files.
- **Advanced Options**: Custom domain detection, duplicate finding, configurable patterns, progress tracking, results caching, severity levels, custom string search, Unicode decoding, and web file downloading.
- **Rich Output**: Color-coded console output, organized tables, and detailed statistics.
- **Extensive File Support**: 200+ file types including programming languages, config files, documents, and specialized formats.
- **Configurable Web Scanning**: Adjustable depth, delay, file size limits, and redirect handling.
- **Auto-Update System**: Built-in update mechanism for dependencies and project version management.

## 📦 Installation (Cross-platform)

### Recommended: pipx (isolated, user-level CLI)

```bash
pip install --user pipx  # if not installed
pipx install 'git+https://github.com/BigVadya/SECRETHOUND.git'
```

### Or: pip (user or venv)

```bash
git clone https://github.com/BigVadya/SECRETHOUND.git
cd SECRETHOUND
pip install -e . --break-system-packages  # for system-wide install
# OR
pip install -e .  # for virtual environment
```

- Python 3.8+ required. All dependencies will be installed automatically.
- After install, the `secrethound` command will be available in your terminal on **Windows, Linux, macOS**.

## 🔄 Updating SecretHound

### Using the Built-in Update Command (Recommended)

```bash
# Update dependencies and project version
secrethound --update

# Or using the module directly
python -m secrethound.main --update
```

The update command automatically:
- ✅ Cleans dependencies from fixed versions
- ✅ Updates packages to latest versions
- ✅ Tests all project modules
- ✅ Updates project version
- ✅ Shows detailed progress and status

### Using pipx (Alternative)

```bash
# Update to latest version
pipx upgrade secrethound

# Or reinstall from git
pipx uninstall secrethound
pipx install 'git+https://github.com/BigVadya/SECRETHOUND.git'
```

### Using pip

```bash
# If installed in user space
pip install --user --upgrade git+https://github.com/BigVadya/SECRETHOUND.git

# If installed in virtual environment
pip install --upgrade git+https://github.com/BigVadya/SECRETHOUND.git

# Or update from local repository
cd /path/to/SECRETHOUND
git pull origin main
pip install --upgrade -e .
```

## 🛠 Usage

Basic scan:

```bash
secrethound -t <target-path>
```

Advanced scan:

```bash
# Локальное сканирование
secrethound -t <target-path> [-d DOMAINS] [-b] [-c CACHE_DIR] [-s SEARCH_TERM] [-ud]

# Веб-сканирование
secrethound -u <url> [-d DOMAINS] [-b] [-c CACHE_DIR] [-s SEARCH_TERM] [-ud] [--web-output DIR]

# Обновление инструмента
secrethound --update
```

### Command Line Arguments

- `-t, --target`: Path to the directory or file to scan (для локального сканирования)
- `-u, --url`: URL веб-сайта для сканирования (скачивает файлы и анализирует их)
- `-d, --domains`: File or comma-separated list of custom domains
- `-b, --big-patterns`: Use extended pattern set (402 patterns vs standard set)
- `-c, --cache`: Path to cache directory
- `-s, --search`: Search for a specific string
- `-ud, --decode-unicode`: Decode unicode escape sequences in files before scanning
- `--web-output`: Directory for downloaded web files (default: web_files)
- `--update`: Update dependencies and project version
- `--web-depth`: Глубина поиска для веб-сканирования (по умолчанию: 3)
- `--web-delay`: Задержка между запросами в секундах (по умолчанию: 0.1)
- `--web-max-size`: Максимальный размер файла для скачивания в байтах (по умолчанию: 10MB)
- `--web-follow-redirects`: Следовать редиректам при веб-сканировании
- `--web-respect-robots`: Учитывать robots.txt при веб-сканировании

### Examples

```bash
# Локальное сканирование
secrethound -t ./my_project -d domains.txt -b -c ./cache -ud

# Веб-сканирование
secrethound -u https://example.com -ud --web-output ./downloaded_files
secrethound -u https://api.example.com -b -c ./cache

# Веб-сканирование с настраиваемой глубиной
secrethound -u https://example.com --web-depth 5 --web-delay 0.2
secrethound -u https://api.example.com --web-depth 2 --web-max-size 5242880

# Обновление инструмента
secrethound --update
```

### For Developers: Run without install

```bash
python -m secrethound.main -t <target-path>
python -m secrethound.main --update
```

## 📤 Output

- Results are saved in the `output` directory:
  - `raw_scan_results.json`: All findings before duplicate cleaning
  - `scan_results.json`: Cleaned results after removing duplicates
- Console output includes severity levels, tables, and statistics
- Update process shows detailed progress and status information

## 🗂 Supported File Types

SecretHound supports **200+ file types** organized into categories:

### Programming Languages
- **Python**: `.py`, `.pyw`, `.pyx`, `.pyi`
- **JavaScript/TypeScript**: `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`
- **Java**: `.java`, `.jar`, `.war`, `.ear`
- **C/C++**: `.c`, `.cpp`, `.h`, `.hpp`, `.cc`, `.cxx`
- **Web**: `.html`, `.htm`, `.xml`, `.xhtml`, `.php`, `.asp`, `.aspx`, `.jsp`
- **Other**: `.rb`, `.cs`, `.go`, `.rs`, `.swift`, `.kt`, `.scala`, `.clj`, `.hs`, `.ml`, `.fs`, `.vb`, `.pl`, `.r`, `.m`, `.mm`, `.sh`, `.bash`, `.zsh`, `.fish`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.lua`, `.dart`, `.nim`

### Configuration Files
- **Environment**: `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`
- **Config**: `.json`, `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.conf`, `.config`, `.properties`
- **Package Managers**: `package.json`, `requirements.txt`, `Pipfile`, `poetry.lock`, `Cargo.toml`, `composer.json`, `Gemfile`, `pom.xml`, `build.gradle`, `go.mod`, `pubspec.yaml`
- **CI/CD**: `.travis.yml`, `.gitlab-ci.yml`, `.github/workflows/*.yml`, `.jenkins`, `.jenkinsfile`, `.circleci/config.yml`

### Documents & Data
- **Documents**: `.md`, `.markdown`, `.rst`, `.txt`, `.text`, `.doc`, `.docx`, `.pdf`, `.rtf`, `.odt`, `.pages`
- **Spreadsheets**: `.csv`, `.tsv`, `.xls`, `.xlsx`, `.ods`, `.ppt`, `.pptx`, `.odp`
- **Database**: `.sql`, `.db`, `.sqlite`, `.sqlite3`, `.mdb`, `.accdb`, `.dbf`

### Security & Certificates
- **Keys**: `.pem`, `.key`, `.crt`, `.cer`, `.der`, `.p12`, `.pfx`, `.p7b`
- **SSH**: `.ssh/config`, `.ssh/known_hosts`, `.ssh/authorized_keys`, `.ssh/id_rsa`, `.ssh/id_ed25519`
- **Web Security**: `.htaccess`, `.htpasswd`, `.htgroup`, `.htdigest`, `.htdbm`

### System & Network
- **System**: `.system`, `.service`, `.socket`, `.timer`, `.path`, `.mount`, `.automount`
- **Network**: `.hosts`, `.resolv.conf`, `.nsswitch.conf`, `.netrc`
- **Firewall**: `.firewall`, `.iptables`, `.ufw`, `.fail2ban`, `.modsecurity`

### Logs & Monitoring
- **Logs**: `.log`, `.out`, `.err`, `.access`, `.error`, `.debug`, `.info`, `.warn`, `.audit`, `.security`, `.auth`, `.syslog`, `.messages`, `.kern`, `.daemon`

### Virtualization & Cloud
- **Virtual Machines**: `.vbox`, `.vmdk`, `.vdi`, `.vhd`, `.vhdx`, `.qcow2`, `.raw`, `.img`, `.iso`, `.ova`, `.ovf`
- **Cloud**: `.tf`, `.tfvars`, `.tfstate`, `.aws`, `.azure`, `.gcp`, `.cloudformation`, `.serverless`, `.sam`

### Specialized Formats
- **Archives**: `.zip`, `.tar`, `.gz`, `.bz2`, `.7z`, `.rar`, `.xz`
- **Media**: `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`, `.tiff`, `.webp`, `.mp4`, `.avi`, `.mov`, `.wmv`, `.flv`, `.mp3`, `.wav`, `.flac`, `.aac`, `.ogg`, `.wma`
- **Development**: `.gitignore`, `.gitattributes`, `.editorconfig`, `.dockerignore`, `.dockerfile`, `.docker-compose.yml`, `.kubernetes.yml`, `.helm.yml`

### And many more...
- **Executables**: `.exe`, `.dll`, `.so`, `.dylib`, `.a`, `.lib`, `.o`, `.obj`, `.class`
- **Packages**: `.rpm`, `.deb`, `.apk`, `.ipa`, `.dmg`, `.pkg`, `.msi`
- **Special**: `.pcap`, `.pcapng`, `.cap`, `.dump`, `.core`, `.crash`, `.minidump`, `.hprof`, `.heap`, `.thread`, `.gc`, `.jfr`, `.jstack`, `.jmap`

## 🚫 Excluded Directories

- **Version Control**: `.git`, `.svn`, `.hg`
- **Cache & Build**: `__pycache__`, `.pytest_cache`, `.mypy_cache`, `node_modules`, `bower_components`, `vendor`, `dist`, `build`, `target`, `bin`, `obj`, `.gradle`, `.mvn`, `.sass-cache`
- **IDE**: `.vscode`, `.idea`, `.DS_Store`, `Thumbs.db`, `.Trash`
- **Coverage**: `coverage`, `.nyc_output`
- **Temporary**: `tmp`, `temp`, `cache`, `.cache`, `logs`, `log`

## ⚡ Performance

- **Smart File Handling**: Skips files > 50MB, uses memory mapping and chunked reading
- **Parallel Processing**: Configurable workers for optimal performance
- **Caching**: LRU cache for repeated scans, configurable cache directory
- **Web Scanning**: Configurable depth, delay, and file size limits
- **Memory Efficient**: Processes large files in chunks to minimize memory usage
- **Auto-Update**: Efficient dependency management and version control

## 🖥️ Cross-platform

- Works on **Windows, Linux, macOS**
- CLI command is available after install via pip/pipx
- No manual PATH setup needed with pipx or modern pip
- Built-in update system works across all platforms

## 🔧 Development

### Project Structure

```
SECRETHOUND/
├── secrethound/
│   ├── __init__.py
│   ├── main.py              # Main CLI interface
│   └── utils/
│       ├── __init__.py
│       ├── duplicate_finder.py
│       ├── file_formats.py
│       ├── sensitive_patterns.py
│       ├── sensitive_patterns_big.py
│       ├── updater.py       # Auto-update system
│       └── web_scanner.py
├── docs/
│   └── developer_guide.md
├── output/                  # Scan results
├── pyproject.toml          # Project configuration
├── requirements.txt
└── README.md
```

### Key Features

- **Modular Design**: Separate modules for different functionalities
- **Auto-Update System**: Built-in dependency and version management
- **Extensible Patterns**: Easy to add new detection patterns
- **Comprehensive Testing**: All modules are tested during updates
- **Rich CLI**: Beautiful console output with progress tracking

## 🤝 Contributing

Contributions are welcome! See [docs/developer_guide.md](docs/developer_guide.md) for developer documentation and contribution guidelines.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Thanks to all contributors
- Inspired by the need for better security scanning tools
- Built with modern Python practices and async programming
