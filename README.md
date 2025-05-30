# SecretHound 🐕‍🦺

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/BigVadya/SECRETHOUND?style=social)](https://github.com/BigVadya/SECRETHOUND/stargazers)

---

> **SecretHound** is a powerful and efficient tool for scanning files and directories to detect sensitive information such as private keys, passwords, API keys, and other confidential data. Like a trained hound, it sniffs out secrets in your codebase.

---

## 🚀 Features

- **Comprehensive Scanning**: Detects private keys, passwords, credit card numbers, API keys, JWT tokens, emails, phone numbers, URLs, and custom domains.
- **Performance Optimized**: Asynchronous file processing, parallel scanning, memory-mapped file reading, LRU caching, and chunked reading for large files.
- **Advanced Options**: Custom domain detection, duplicate finding, configurable patterns, progress tracking, results caching, severity levels, and custom string search.
- **Rich Output**: Color-coded console output, organized tables, and detailed statistics.

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
pip install .
```

- Python 3.8+ required. All dependencies will be installed automatically.
- After install, the `secrethound` command will be available in your terminal on **Windows, Linux, macOS**.

## 🛠 Usage

Basic scan:

```bash
secrethound -t <target-path>
```

Advanced scan:

```bash
secrethound -t <target-path> [-d DOMAINS] [-b] [-c CACHE_DIR] [-s SEARCH_TERM]
```

### Command Line Arguments

- `-t, --target`: Path to the directory or file to scan (**required**)
- `-d, --domains`: File or comma-separated list of custom domains
- `-b, --big-patterns`: Use extended pattern set
- `-c, --cache`: Path to cache directory
- `-s, --search`: Search for a specific string

### Example

```bash
secrethound -t ./my_project -d domains.txt -b -c ./cache
```

### For Developers: Run without install

```bash
python -m secrethound.main -t <target-path>
```

## 📤 Output

- Results are saved in the `output` directory:
  - `raw_scan_results.json`: All findings before duplicate cleaning
  - `scan_results.json`: Cleaned results after removing duplicates
- Console output includes severity levels, tables, and statistics

## 🗂 Supported File Types

- Programming: `.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.rb`, `.php`, `.cs`, `.go`, `.rs`
- Config: `.json`, `.yaml`, `.yml`, `.env`, `.conf`, `.properties`
- Docs: `.md`, `.txt`
- Web: `.html`, `.xml`
- Database: `.sql`
- Logs: `.log`

## 🚫 Excluded Directories

- `.git`, `__pycache__`, `venv`, `node_modules`, `.vscode`

## ⚡ Performance

- Skips files > 50MB
- Uses memory mapping and chunked reading
- Parallel processing with configurable workers

## 🖥️ Cross-platform

- Works on **Windows, Linux, macOS**
- CLI command is available after install via pip/pipx
- No manual PATH setup needed with pipx or modern pip

## 🤝 Contributing

Contributions are welcome! See [docs/developer_guide.md](docs/developer_guide.md) for developer documentation and contribution guidelines.

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Thanks to all contributors
- Inspired by the need for better security scanning tools
