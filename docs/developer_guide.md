# SecretHound Developer Guide

Welcome to the developer documentation for SecretHound! This guide will help you understand the project structure, main modules, and how to contribute or extend the tool.

---

## 📁 Project Structure

```
SECRETHOUND/
├── secrethound/              # Python package with all source code
│   ├── __init__.py
│   ├── main.py               # Main entry point and CLI logic
│   └── utils/                # Utility modules (duplicate finder, patterns)
│       ├── __init__.py
│       ├── duplicate_finder.py
│       ├── sensitive_patterns.py
│       └── sensitive_patterns_big.py
├── output/                   # Scan results (auto-generated)
├── docs/                     # Documentation (this file)
├── README.md                 # Project overview and usage
├── pyproject.toml            # Build and packaging config
├── requirements.txt          # Python dependencies (for dev)
└── ...
```

## 🧩 Main Modules

- **secrethound/main.py**: Orchestrates scanning, CLI, and reporting
- **secrethound/utils/**: Contains helper modules:
  - `duplicate_finder.py`: Handles duplicate detection and cleaning
  - `sensitive_patterns.py` / `sensitive_patterns_big.py`: Regex patterns for sensitive data
  - `web_scanner.py`: Downloads and analyzes files from web services

## 🔧 New Features

### Unicode Decoding
The tool now supports decoding Unicode escape sequences in files before scanning. This is useful for:
- Files with encoded Unicode characters (e.g., `\u0041` for 'A')
- Obfuscated sensitive data
- International character support

**Usage:**
```bash
secrethound -t <target-path> -ud
# или
secrethound -t <target-path> --decode-unicode
```

**Implementation:**
- Added `decode_file()` function in `main.py`
- Modified `analyze_file_async()` to decode files before scanning
- Added `-ud, --decode-unicode` CLI argument

### Web Scanning
The tool now supports scanning web services by downloading their files and analyzing them locally. This is useful for:
- JavaScript applications and SPAs
- API documentation and examples
- Web services with exposed configuration files
- Security analysis of web applications

**Usage:**
```bash
secrethound -u https://example.com -ud
secrethound -u https://api.example.com --web-output ./downloaded_files
```

**Implementation:**
- Added `WebScanner` class in `web_scanner.py`
- Supports downloading JS, CSS, HTML, JSON, XML files
- Excludes CDN files (jQuery, Bootstrap, etc.)
- Configurable file size limits and download depth
- Added `-u, --url` and `--web-output` CLI arguments

## ➕ Adding New Patterns

1. Open `secrethound/utils/sensitive_patterns.py` (or the relevant pattern file).
2. Add your new regex pattern to the `PATTERNS` dictionary, using a descriptive key.
3. (Optional) Add a severity level if needed.
4. Test your pattern with sample data.

## 🛠 Extending Functionality

- To add new scanning logic, create a new module in `secrethound/utils/` and import it in `main.py`.
- For new CLI options, update the argument parser in `main.py`.
- To support new file types, add extensions to the `SUPPORTED_EXTENSIONS` set in `main.py`.

## 🧪 Testing

- Tests are written using `pytest` and `pytest-asyncio`.
- Place your test files in a `tests/` directory (create if missing).
- Run tests with:
  ```bash
  pytest
  ```
- Ensure new features are covered by tests.
- For CLI/manual testing, use:
  ```bash
  python -m secrethound.main -t <target-path>
  # or after install:
  secrethound -t <target-path>
  ```

## 💡 Best Practices

- Write clear, concise code and comments
- Use type hints where possible
- Follow PEP8 style guidelines
- Document new features in the README and this guide
- Open a Pull Request for all contributions

## 🤝 Contribution Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit and push your changes
4. Open a Pull Request with a clear description

## 🚀 Publishing & Distribution

- To build and publish a new release:
  ```bash
  # Build wheel and sdist
  python -m build
  # Publish to PyPI (requires twine)
  twine upload dist/*
  ```
- For CLI users, recommend pipx or pip install from PyPI or GitHub.

---

For questions or suggestions, open an issue or contact the maintainer.
