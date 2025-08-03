"""
Configuration of supported file formats for SecretHound
All formats are organized by categories for convenient editing
"""

# Main supported extensions for local scanning
SUPPORTED_EXTENSIONS = {
    # Programming
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp", 
    ".rb", ".php", ".cs", ".go", ".rs", ".swift", ".kt", ".scala", ".clj",
    ".hs", ".ml", ".fs", ".vb", ".pl", ".pm", ".r", ".m", ".mm", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".vbs", ".lua", ".dart", ".nim",
    
    # Web technologies
    ".html", ".htm", ".xml", ".xhtml", ".shtml", ".asp", ".aspx", ".jsp", ".jspx",
    ".php", ".phtml", ".erb", ".haml", ".slim", ".vue", ".svelte", ".astro",
    
    # Configuration files
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".env", ".env.local", ".env.production", ".env.development", ".env.test",
    ".properties", ".xml", ".xaml", ".yaml", ".yml", ".lock", ".lockfile",
    
    # Documentation and text files
    ".md", ".markdown", ".rst", ".txt", ".text", ".log", ".out", ".err",
    ".doc", ".docx", ".pdf", ".rtf", ".odt", ".pages",
    
    # Databases and SQL
    ".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".dbf",
    
    # Archives (for future expansion)
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
    
    # Other formats
    ".csv", ".tsv", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp",
    ".psd", ".ai", ".eps", ".svg", ".ico", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".tiff", ".webp", ".mp4", ".avi", ".mov", ".wmv", ".flv",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma",
    
    # Special formats
    ".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx", ".p7b",
    ".bak", ".backup", ".old", ".orig", ".tmp", ".temp", ".cache",
    ".gitignore", ".gitattributes", ".editorconfig", ".dockerignore",
    ".dockerfile", ".docker-compose.yml", ".docker-compose.yaml",
    ".kubernetes.yml", ".kubernetes.yaml", ".helm.yml", ".helm.yaml",
    
    # CI/CD and DevOps
    ".travis.yml", ".gitlab-ci.yml", ".github/workflows/*.yml", ".github/workflows/*.yaml",
    ".jenkins", ".jenkinsfile", ".bitbucket-pipelines.yml", ".appveyor.yml",
    ".circleci/config.yml", ".drone.yml", ".semaphore.yml",
    
    # Package managers
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "poetry.lock", "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties",
    "go.mod", "go.sum", "mix.exs", "mix.lock", "pubspec.yaml", "pubspec.lock",
    
    # System files
    ".system", ".service", ".socket", ".timer", ".path", ".mount", ".automount",
    ".swap", ".target", ".slice", ".scope", ".device", ".mount", ".automount",
    
    # Network configurations
    ".hosts", ".resolv.conf", ".nsswitch.conf", ".netrc", ".ssh/config",
    ".ssh/known_hosts", ".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_ed25519",
    
    # Security
    ".htaccess", ".htpasswd", ".htgroup", ".htdigest", ".htdbm",
    ".firewall", ".iptables", ".ufw", ".fail2ban", ".modsecurity",
    
    # Monitoring and logs
    ".log", ".out", ".err", ".access", ".error", ".debug", ".info", ".warn",
    ".audit", ".security", ".auth", ".syslog", ".messages", ".kern", ".daemon",
    
    # Virtualization and containers
    ".vbox", ".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow2", ".raw", ".img",
    ".iso", ".ova", ".ovf", ".vapp", ".vappx", ".vhd", ".vhdx",
    
    # Cloud services
    ".tf", ".tfvars", ".tfstate", ".tfstate.backup", ".terraform.lock.hcl",
    ".aws", ".azure", ".gcp", ".cloudformation", ".serverless", ".sam",
    
    # Special formats for security
    ".pcap", ".pcapng", ".cap", ".dump", ".core", ".crash", ".minidump",
    ".hprof", ".heap", ".thread", ".gc", ".jfr", ".jstack", ".jmap",
    
    # Additional formats
    ".rpm", ".deb", ".apk", ".ipa", ".dmg", ".pkg", ".msi", ".exe",
    ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj", ".class",
    ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".app", ".bundle"
}

# File extensions for web scanning
WEB_TARGET_EXTENSIONS = {
    # Web technologies
    '.js', '.ts', '.jsx', '.tsx', '.json', '.xml', '.html', '.htm', 
    '.css', '.scss', '.sass', '.less', '.txt', '.md', '.yaml', '.yml',
    '.vue', '.svelte', '.astro', '.php', '.asp', '.aspx', '.jsp',
    
    # Configuration files
    '.env', '.env.local', '.env.production', '.env.development',
    '.config', '.conf', '.ini', '.toml', '.properties', '.lock',
    '.lockfile', '.gitignore', '.dockerignore', '.editorconfig',
    
    # Package managers
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'requirements.txt', 'Pipfile', 'poetry.lock', 'Cargo.toml',
    'composer.json', 'Gemfile', 'pom.xml', 'build.gradle',
    'go.mod', 'pubspec.yaml', 'mix.exs',
    
    # CI/CD files
    '.travis.yml', '.gitlab-ci.yml', '.github/workflows/*.yml',
    '.jenkins', '.jenkinsfile', '.circleci/config.yml',
    
    # Documentation
    '.rst', '.adoc', '.tex', '.latex', '.doc', '.docx', '.pdf',
    
    # API and schemas
    '.swagger', '.openapi', '.graphql', '.gql', '.wsdl', '.xsd',
    
    # Security
    '.pem', '.key', '.crt', '.cer', '.p12', '.pfx',
    '.htaccess', '.htpasswd', '.htgroup', '.htdigest',
    
    # Logs and debugging
    '.log', '.out', '.err', '.debug', '.trace', '.profile',
    
    # Special formats
    '.map', '.min.js', '.min.css', '.bundle.js', '.chunk.js',
    '.manifest', '.webmanifest', '.service-worker.js',
    
    # Additional formats
    '.csv', '.tsv', '.xls', '.xlsx', '.ods', '.sql', '.db',
    '.bak', '.backup', '.old', '.orig', '.tmp', '.temp',
    '.cache', '.session', '.cookie', '.localstorage'
}

# CDN domains to exclude during web scanning
CDN_DOMAINS = {
    'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net',
    'code.jquery.com', 'cdn.jsdelivr.net', 'stackpath.bootstrapcdn.com',
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
    'cdn.skypack.dev', 'esm.sh', 'cdn.esm.sh', 'jspm.dev',
    'unpkg.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
    'maps.googleapis.com', 'www.google-analytics.com',
    'www.googletagmanager.com', 'www.gstatic.com',
    'cdn.rawgit.com', 'raw.githubusercontent.com',
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com'
}

# Excluded directories
EXCLUDE_DIRS = {
    ".git", "__pycache__", "venv", "node_modules", ".vscode",
    ".idea", ".vscode", ".DS_Store", "Thumbs.db", ".Trash",
    "node_modules", "bower_components", "vendor", "dist", "build",
    "target", "bin", "obj", ".gradle", ".mvn", ".sass-cache",
    "coverage", ".nyc_output", ".nyc_output", ".nyc_output",
    "tmp", "temp", "cache", ".cache", "logs", "log"
} 