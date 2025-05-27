# SecretHound 🐕‍🦺

[![Python Version](https://img.shields.io/badge/python-3.13.3%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/BigVadya/SECRETHOUND?style=social)](https://github.com/BigVadya/SECRETHOUND/stargazers)

A powerful and efficient tool for scanning files and directories to detect sensitive information such as private keys, passwords, API keys, and other confidential data. Like a trained hound, it sniffs out secrets in your codebase.

## Features

- 🔍 **Comprehensive Scanning**: Detects various types of sensitive data including:

  - Private Keys (PEM format)
  - Passwords
  - Credit Card numbers
  - API Keys
  - JWT Tokens
  - Email addresses
  - Phone numbers
  - URLs
  - Custom domain URLs

- ⚡ **Performance Optimized**:

  - Asynchronous file processing
  - Parallel scanning capabilities
  - Memory-mapped file reading for large files
  - LRU caching for improved performance
  - Chunked file reading for memory efficiency

- 🛠 **Advanced Features**:
  - Custom domain detection
  - Duplicate finding and cleaning
  - Configurable pattern sets
  - Progress tracking with rich console output
  - Results caching
  - Detailed severity levels (critical, high, medium, low)
  - Custom string search functionality

## Installation

1. Clone the repository:

```bash
git clone https://github.com/BigVadya/SECRETHOUND.git
cd SECRETHOUND
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python main.py -t <target-path>
```

Advanced options:

```bash
python main.py -t <target-path> [-d DOMAINS] [-b] [-c CACHE_DIR] [-s SEARCH_TERM]
```

### Command Line Arguments

- `-t, --target`: Path to the directory or file to scan (required)
- `-d, --domains`: Path to a file containing custom domains or comma-separated list of domains
- `-b, --big-patterns`: Use extended pattern set for more comprehensive scanning
- `-c, --cache`: Path to cache directory for storing scan results
- `-s, --search`: Search for a specific string in files

### Usage Examples

Basic scanning:

```bash
python main.py -t /path/to/scan
```

Search for specific text:

```bash
python main.py -t /path/to/scan -s "search_term"
```

Advanced scanning with custom domains:

```bash
python main.py -t /path/to/scan -d domains.txt -b -c ./cache
```

### Output

The scanner generates two output files in the `output` directory:

- `raw_scan_results.json`: Contains all findings before duplicate cleaning
- `scan_results.json`: Contains cleaned results after removing duplicates

Results are also displayed in the console with:

- Color-coded severity levels
- Organized tables by finding type
- Detailed statistics about the scan
- Search results marked with "User Search" type when using -s flag

## Supported File Types

The scanner supports a wide range of file extensions including:

- Programming files: `.py`, `.js`, `.ts`, `.java`, `.c`, `.cpp`, `.rb`, `.php`, `.cs`, `.go`, `.rs`
- Configuration files: `.json`, `.yaml`, `.yml`, `.env`, `.conf`, `.properties`
- Documentation: `.md`, `.txt`
- Web files: `.html`, `.xml`
- Database: `.sql`
- Logs: `.log`

## Excluded Directories

The following directories are automatically excluded from scanning:

- `.git`
- `__pycache__`
- `venv`
- `node_modules`
- `.vscode`

## Performance Considerations

- Files larger than 50MB are automatically skipped
- Uses memory mapping for efficient file reading
- Implements chunked reading for large files
- Supports parallel processing with configurable worker count

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- **BigVadya** - _Initial work_ - [GitHub](https://github.com/BigVadya)

## Acknowledgments

- Thanks to all contributors who have helped improve this project
- Inspired by the need for better security scanning tools
