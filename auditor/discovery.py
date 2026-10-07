from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from .models import Asset, AssetType

_WEB_EXTENSIONS = {
    ".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte",
    ".ejs", ".hbs", ".pug", ".blade.php",
}

_CONFIG_FILES = {
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test", ".env.example",
    "config.yml", "config.yaml", "config.json", "config.toml",
    "settings.py", "settings.json", "settings.yml",
    "appsettings.json", "appsettings.Development.json",
    "web.config", "application.properties", "application.yml",
    ".htaccess", "nginx.conf", "httpd.conf",
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", "Vagrantfile",
    "serverless.yml", "serverless.yaml",
    "firebase.json", "vercel.json", "netlify.toml",
    "now.json",
}

_DEPENDENCY_FILES = {
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "pyproject.toml", "setup.py", "setup.cfg",
    "poetry.lock", "conda.yaml",
    "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lockb",
    "Gemfile", "Gemfile.lock",
    "Cargo.toml", "Cargo.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "composer.lock",
    "*.csproj", "*.fsproj", "packages.config",
}

_API_INDICATORS = {
    "routes", "router", "endpoint", "controller",
    "views", "handlers", "middleware", "api",
}

_AUTH_INDICATORS = {
    "auth", "login", "signup", "register", "session",
    "token", "jwt", "oauth", "passport", "password",
    "credentials", "permission", "rbac", "acl",
}

_DB_INDICATORS = {
    "migration", "model", "schema", "database",
    "sequelize", "typeorm", "prisma", "alembic",
    "knex", "mongoose", "sqlalchemy",
}

_SECRET_PATTERNS = [
    (r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "API Key"),
    (r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Password/Secret"),
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}", "AWS Credential"),
    (r"(?i)(token|bearer)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]", "Token"),
    (r"(?i)-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----", "Private Key"),
    (r"(?i)(mongodb(\+srv)?://)[^\s'\"]+", "MongoDB Connection String"),
    (r"(?i)(postgresql?://)[^\s'\"]+", "PostgreSQL Connection String"),
    (r"(?i)(mysql://)[^\s'\"]+", "MySQL Connection String"),
    (r"(?i)(redis://)[^\s'\"]+", "Redis Connection String"),
    (r"ghp_[A-Za-z0-9_]{36,}", "GitHub Personal Access Token"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key"),
    (r"(?i)(slack_token|xox[bprs]-[A-Za-z0-9\-]+)", "Slack Token"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)(stripe_secret_key|sk_live_)[A-Za-z0-9]+", "Stripe Secret Key"),
]

_SKIP_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", "node_modules",
    ".tox", ".mypy_cache", ".pytest_cache", "venv", ".venv",
    "env", "dist", "build", ".next", ".nuxt",
    ".terraform", ".serverless",
}

_BINARY_EXTENSIONS = {
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib",
    ".o", ".a", ".lib", ".class", ".jar", ".war",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".svg", ".webp", ".mp3", ".mp4", ".avi", ".mkv",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".db", ".sqlite", ".sqlite3",
}

class AssetDiscovery:

    def __init__(self, project_path: str, excluded_dirs: Optional[list[str]] = None):
        self.project_path = os.path.abspath(project_path)
        self.excluded_dirs = set(excluded_dirs or [])
        self.assets: list[Asset] = []
        self._file_count = 0
        self._dir_count = 0

    def scan(self) -> list[Asset]:

        self.assets.clear()
        self._file_count = 0
        self._dir_count = 0

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_DIRS and d not in self.excluded_dirs
            ]
            self._dir_count += len(dirs)

            rel_root = os.path.relpath(root, self.project_path)

            for fname in files:
                self._file_count += 1
                fpath = os.path.join(root, fname)
                rel_path = os.path.join(rel_root, fname) if rel_root != "." else fname

                self._classify_file(fname, fpath, rel_path, rel_root)

        return self.assets

    def _classify_file(self, fname: str, fpath: str, rel_path: str, rel_dir: str):

        ext = os.path.splitext(fname)[1].lower()
        fname_lower = fname.lower()
        dir_parts = set(rel_dir.replace("\\", "/").split("/"))

        if ext in _BINARY_EXTENSIONS:
            return

        if fname_lower in ("dockerfile", "docker-compose.yml", "docker-compose.yaml",
                           ".dockerignore"):
            self._add_asset(fname, AssetType.DOCKER, rel_path, {"type": "docker"})

        if fname_lower in _CONFIG_FILES or fname_lower.startswith(".env"):
            asset = self._add_asset(fname, AssetType.CONFIG, rel_path, {})
            self._scan_secrets(fpath, rel_path, asset)

        if fname_lower in _DEPENDENCY_FILES or (ext == ".csproj"):
            self._add_asset(fname, AssetType.DEPENDENCY, rel_path, {
                "ecosystem": self._detect_ecosystem(fname_lower, ext)
            })

        if ext in _WEB_EXTENSIONS:
            self._add_asset(fname, AssetType.WEB_APP, rel_path, {"extension": ext})

        if dir_parts & _API_INDICATORS:
            self._add_asset(fname, AssetType.API, rel_path, {
                "indicator_dir": dir_parts & _API_INDICATORS
            })

        if dir_parts & _AUTH_INDICATORS or any(
            ind in fname_lower for ind in _AUTH_INDICATORS
        ):
            self._add_asset(fname, AssetType.AUTH_SYSTEM, rel_path, {})

        if dir_parts & _DB_INDICATORS or any(
            ind in fname_lower for ind in _DB_INDICATORS
        ):
            self._add_asset(fname, AssetType.DATABASE, rel_path, {})

        if ext in (".py", ".js", ".ts", ".php", ".rb", ".java", ".go",
                   ".cs", ".rs", ".c", ".cpp", ".h", ".sh", ".bash",
                   ".yml", ".yaml", ".json", ".xml", ".toml", ".ini",
                   ".cfg", ".conf"):
            src_asset = self._add_asset(fname, AssetType.SOURCE_CODE, rel_path, {
                "language": self._detect_language(ext)
            })
            self._scan_secrets(fpath, rel_path, src_asset)

    def _scan_secrets(self, fpath: str, rel_path: str, parent_asset: Optional[Asset] = None):

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(50_000)
        except (OSError, UnicodeDecodeError):
            return

        for pattern, secret_type in _SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                matched_text = match.group(0)
                redacted = self._redact(matched_text)

                line_num = content[:match.start()].count("\n") + 1

                asset = self._add_asset(
                    f"[SECRET] {secret_type}",
                    AssetType.SECRET,
                    rel_path,
                    {
                        "secret_type": secret_type,
                        "line": line_num,
                        "redacted_match": redacted,
                    },
                )
                asset.risk_notes.append(
                    f"Potential {secret_type} found at line {line_num}"
                )

                if parent_asset:
                    parent_asset.risk_notes.append(
                        f"Contains potential {secret_type} at line {line_num}"
                    )

    def _redact(self, text: str) -> str:

        for sep in ("=", ":"):
            if sep in text:
                key, _, val = text.partition(sep)
                val = val.strip().strip("'\"")
                if len(val) > 4:
                    redacted_val = val[:2] + "*" * (len(val) - 4) + val[-2:]
                else:
                    redacted_val = "****"
                return f"{key}{sep} {redacted_val}"
        if len(text) > 8:
            return text[:4] + "*" * (len(text) - 8) + text[-4:]
        return "****"

    def _add_asset(self, name: str, atype: AssetType, path: str,
                   details: dict) -> Asset:
        asset = Asset(name=name, asset_type=atype, path=path, details=details)
        self.assets.append(asset)
        return asset

    def _detect_ecosystem(self, fname: str, ext: str) -> str:
        ecosystems = {
            "requirements.txt": "python-pip",
            "pipfile": "python-pipenv",
            "pyproject.toml": "python",
            "setup.py": "python-setuptools",
            "poetry.lock": "python-poetry",
            "package.json": "npm",
            "yarn.lock": "yarn",
            "pnpm-lock.yaml": "pnpm",
            "gemfile": "ruby-bundler",
            "cargo.toml": "rust-cargo",
            "go.mod": "go-modules",
            "pom.xml": "java-maven",
            "build.gradle": "java-gradle",
            "composer.json": "php-composer",
        }
        return ecosystems.get(fname, "unknown")

    def _detect_language(self, ext: str) -> str:
        languages = {
            ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
            ".php": "PHP", ".rb": "Ruby", ".java": "Java",
            ".go": "Go", ".cs": "C#", ".rs": "Rust",
            ".c": "C", ".cpp": "C++", ".h": "C/C++ Header",
            ".sh": "Shell", ".bash": "Bash",
        }
        return languages.get(ext, "Unknown")

    @property
    def stats(self) -> dict:
        return {
            "files_scanned": self._file_count,
            "directories_scanned": self._dir_count,
            "assets_discovered": len(self.assets),
            "secrets_found": sum(
                1 for a in self.assets if a.asset_type == AssetType.SECRET
            ),
            "asset_types": {
                at.value: sum(1 for a in self.assets if a.asset_type == at)
                for at in AssetType
                if any(a.asset_type == at for a in self.assets)
            },
        }
