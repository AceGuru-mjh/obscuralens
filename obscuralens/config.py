"""
Configuration Management Module

Resolution order (highest priority first):
    1. Environment variables (OBSCURALENS_*)
    2. config/secrets.yaml  - API keys, kept out of version control
    3. config/config.yaml   - non-sensitive settings
    4. Built-in defaults

The config directory is resolved as: OBSCURALENS_CONFIG_DIR, then ./config
when running from a project checkout, then a per-user directory
(%APPDATA%/ObscuraLens on Windows, ~/.config/obscuralens elsewhere).
"""

import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from . import __version__

# Services that accept an API key. The slug matches the YAML/env naming.
SERVICES = (
    'shodan',
    'haveibeenpwned',
    'hunter',
    'virustotal',
    'ipinfo',
    'numverify',
    'abuseipdb',
    'google_maps',
)

ENV_PREFIX = 'OBSCURALENS_'


@dataclass
class APIConfig:
    """API keys for optional keyed data sources."""
    shodan_api_key: str = ""
    haveibeenpwned_api_key: str = ""
    hunter_api_key: str = ""
    virustotal_api_key: str = ""
    ipinfo_api_key: str = ""
    numverify_api_key: str = ""
    abuseipdb_api_key: str = ""
    google_maps_api_key: str = ""


@dataclass
class DatabaseConfig:
    """Database configuration."""
    db_type: str = "sqlite"  # sqlite (postgres/mysql planned)
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "obscuralens"
    db_user: str = ""
    db_password: str = ""
    sqlite_path: str = "data/obscuralens.db"


@dataclass
class AppConfig:
    """Runtime behaviour settings."""
    debug: bool = False
    log_level: str = "INFO"
    output_format: str = "table"  # table, json, csv
    save_history: bool = True
    max_history_entries: int = 1000
    request_timeout: int = 30
    user_agent: str = f"ObscuraLens/{__version__}"
    deep_username_scan: bool = True   # extract profile details on username hits
    parallel_sources: bool = True     # query independent sources concurrently
    max_workers: int = 12             # ceiling for per-lookup thread pools
    requests_per_second: float = 8.0  # per-host rate limit (0 disables)
    cache_enabled: bool = True        # cache successful HTTP GET responses
    cache_ttl: int = 900              # seconds a cached response stays fresh
    cache_path: str = "data/http_cache.db"
    proxy: str = ""                   # optional proxy URL for all requests
    disabled_sources: List[str] = field(default_factory=list)
    report_dir: str = "reports"
    chart_dir: str = "reports/charts"


class ConfigManager:
    """Loads, merges and persists ObscuraLens configuration."""

    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = Path(config_dir) if config_dir else self._default_config_dir()
        self.config_file = self.config_dir / "config.yaml"
        self.secrets_file = self.config_dir / "secrets.yaml"

        self.api_config = APIConfig()
        self.db_config = DatabaseConfig()
        self.app_config = AppConfig()

        self._load()

    # -- loading ----------------------------------------------------------

    @staticmethod
    def _default_config_dir() -> Path:
        env = os.getenv(ENV_PREFIX + 'CONFIG_DIR')
        if env:
            return Path(env)
        local = Path('config')
        if local.exists():
            return local

        if os.name == 'nt':
            base = Path(os.getenv('APPDATA') or Path.home()) / 'ObscuraLens'
        else:
            base = Path(os.getenv('XDG_CONFIG_HOME') or (Path.home() / '.config')) / 'obscuralens'
        return base

    def _load(self) -> None:
        data = self._read_yaml(self.config_file) or {}
        secrets = self._read_yaml(self.secrets_file) or {}

        self._apply(data)
        self._apply_secrets(secrets)
        self._load_from_env()

    @staticmethod
    def _read_yaml(path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            return None

    def _apply(self, data: Dict[str, Any]) -> None:
        for section, target in (
            ('api', self.api_config),
            ('database', self.db_config),
            ('app', self.app_config),
        ):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for key, value in block.items():
                if hasattr(target, key):
                    setattr(target, key, value)

    def _apply_secrets(self, secrets: Dict[str, Any]) -> None:
        # secrets.yaml is flat: shodan_api_key: "..."
        for key, value in secrets.items():
            if hasattr(self.api_config, key) and value:
                setattr(self.api_config, key, value)
        # Also accept a nested `api:` block for symmetry with config.yaml.
        if isinstance(secrets.get('api'), dict):
            for key, value in secrets['api'].items():
                if hasattr(self.api_config, key) and value:
                    setattr(self.api_config, key, value)

    @staticmethod
    def _coerce(current: Any, raw: str) -> Any:
        """Convert an environment string to the type of the current value."""
        if isinstance(current, bool):
            return raw.strip().lower() in ('1', 'true', 'yes', 'on')
        if isinstance(current, int):
            try:
                return int(raw)
            except ValueError:
                return current
        if isinstance(current, float):
            try:
                return float(raw)
            except ValueError:
                return current
        if isinstance(current, list):
            return [item.strip() for item in raw.split(',') if item.strip()]
        return raw

    def _load_from_env(self) -> None:
        for target in (self.app_config, self.db_config):
            for key, current in vars(target).items():
                raw = os.getenv(ENV_PREFIX + key.upper())
                if raw is not None:
                    setattr(target, key, self._coerce(current, raw))

        for service in SERVICES:
            raw = os.getenv(ENV_PREFIX + service.upper() + '_API_KEY')
            if raw:
                setattr(self.api_config, f'{service}_api_key', raw)

    # -- accessors --------------------------------------------------------

    def get_api_key(self, service: str) -> Optional[str]:
        """Get the configured API key for a service, or None."""
        service = service.lower()
        if service not in SERVICES:
            return None
        return getattr(self.api_config, f'{service}_api_key', '') or None

    def set_api_key(self, service: str, value: str) -> None:
        """Store an API key in memory (persisted by save_secrets)."""
        service = service.lower()
        if service in SERVICES:
            setattr(self.api_config, f'{service}_api_key', value or '')

    def is_configured(self, service: str) -> bool:
        return bool(self.get_api_key(service))

    def configured_services(self) -> Dict[str, bool]:
        return {s: self.is_configured(s) for s in SERVICES}

    def is_source_enabled(self, source: str) -> bool:
        """Whether a data source is allowed to run (see disabled_sources)."""
        disabled = {s.lower() for s in self.app_config.disabled_sources}
        return source.lower() not in disabled

    # -- persistence ------------------------------------------------------

    def save_config(self) -> None:
        """Write non-sensitive settings to config.yaml."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        data = {
            'api': {},  # keys live in secrets.yaml
            'database': asdict(self.db_config),
            'app': asdict(self.app_config),
        }
        with open(self.config_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def save_secrets(self) -> None:
        """Write API keys to secrets.yaml with owner-only permissions."""
        self.config_dir.mkdir(parents=True, exist_ok=True)

        secrets = {
            key: value
            for key, value in asdict(self.api_config).items()
            if value
        }

        if secrets:
            with open(self.secrets_file, 'w', encoding='utf-8') as f:
                yaml.dump(secrets, f, default_flow_style=False, sort_keys=False)
            try:
                os.chmod(self.secrets_file, stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, NotImplementedError):
                pass  # non-POSIX filesystems do not support this
        elif self.secrets_file.exists():
            self.secrets_file.unlink()


# Shared instance used across the package.
config = ConfigManager()
