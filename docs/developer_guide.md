# SecretHound Developer Guide

Welcome to the developer documentation for SecretHound! This guide will help you understand the project structure, main modules, and how to contribute or extend the tool.

---

## 📁 Project Structure

```
SECRETHOUND/
├── main.py               # Main entry point and core logic
├── requirements.txt      # Python dependencies
├── utils/                # Utility modules (e.g., duplicate finder, pattern sets)
├── output/               # Scan results (auto-generated)
├── docs/                 # Documentation (this file)
├── README.md             # Project overview and usage
└── ...
```

## 🧩 Main Modules

- **main.py**: Orchestrates scanning, CLI, and reporting
- **utils/**: Contains helper modules:
  - `duplicate_finder.py`: Handles duplicate detection and cleaning
  - `pattern_sets.py`: Houses regex patterns for sensitive data
  - (Add more utilities as needed)

## ➕ Adding New Patterns

1. Open `utils/pattern_sets.py` (or the relevant pattern file).
2. Add your new regex pattern to the `PATTERNS` dictionary, using a descriptive key.
3. (Optional) Add a severity level if needed.
4. Test your pattern with sample data.

## 🛠 Extending Functionality

- To add new scanning logic, create a new module in `utils/` and import it in `main.py`.
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

---

For questions or suggestions, open an issue or contact the maintainer.
