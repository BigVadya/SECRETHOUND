# Changelog

## [0.1.19] - 2024-12-19

### Added
- **Web scanning arguments**: Added missing command line arguments for web scanning configuration:
  - `--web-depth`: Set search depth for web scanning (default: 3)
  - `--web-delay`: Set delay between requests in seconds (default: 0.1)
  - `--web-max-size`: Set maximum file size for downloading in bytes (default: 10MB)
  - `--no-web-follow-redirects`: Disable following redirects during web scanning
  - `--no-web-respect-robots`: Disable respecting robots.txt during web scanning

### Changed
- **Argument naming**: Changed `--web-follow-redirects` and `--web-respect-robots` to `--no-web-follow-redirects` and `--no-web-respect-robots` for better UX (disabled by default)
- **Documentation**: Updated README.md to reflect the correct argument names and usage examples

### Fixed
- **Missing arguments**: All web scanning arguments mentioned in README are now properly implemented and functional
- **Parameter passing**: Web scanner now receives all configuration parameters from command line arguments

### Technical Details
- Modified `secrethound/main.py` to add argument parsing for web scanning parameters
- Updated `download_and_scan_website()` call to pass all parameters correctly
- Added informative console output showing web scanning configuration
- All arguments are now consistent between README documentation and actual implementation

### Testing
- Verified all new arguments work correctly with test website (httpbin.org)
- Confirmed parameter values are properly passed to WebScanner class
- Tested both enabled and disabled states for boolean flags 