import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDED_FILES = {
    "build_swarm_package.py",
    "swarm_enterprise.py",
    "sast_engine.py",
    "sandbox.py",
    "swarm_bulletproof.py",
    "swarm_pro_cli.py",
    "swarm_multi_scanner.py",
    "liquidity_pool.py",
}

DEFAULT_EXCLUDED_DIRS = {
    "tests",
    "exploits",
    "patches",
    "swarm_auditor",
    "build",
    "dist",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
}

CONFIG_TEMPLATE = """# Конфигурация AI Swarm Security Auditor (.swarm.toml)
[audit]
# Режим автопатчинга модульных SAST-уязвимостей (функции и глобальные переменные)
auto_patch_sast = true
# Количество параллельных потоков сканирования
max_workers = 4
# Таймаут изолированной песочницы в секундах
sandbox_timeout = 15

# Дополнительные папки и файлы, которые нужно пропустить
exclude_dirs = ["migrations", "node_modules"]
exclude_files = ["setup.py"]

# Отключение правил по ID (например, "SWARM-005") или по коду CWE (например, "CWE-328")
ignore_rules = []
"""


@dataclass
class SwarmConfig:
    auto_patch_sast: bool = True
    max_workers: int = 4
    sandbox_timeout: int = 15
    exclude_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_DIRS))
    exclude_files: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUDED_FILES))
    ignore_rules: set[str] = field(default_factory=set)
    source_path: str = "встроенные настройки"


def load_config(root_dir: Path) -> SwarmConfig:
    cfg = SwarmConfig()
    cfg_file = root_dir / ".swarm.toml"
    if not cfg_file.exists():
        return cfg

    try:
        raw = tomllib.loads(cfg_file.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[!] Ошибка чтения {cfg_file.name}: {exc}. Используются настройки по умолчанию.")
        return cfg

    section = raw.get("audit", raw)
    if isinstance(section.get("auto_patch_sast"), bool):
        cfg.auto_patch_sast = section["auto_patch_sast"]
    if isinstance(section.get("max_workers"), int) and section["max_workers"] > 0:
        cfg.max_workers = section["max_workers"]
    if isinstance(section.get("sandbox_timeout"), int) and section["sandbox_timeout"] > 0:
        cfg.sandbox_timeout = section["sandbox_timeout"]

    cfg.exclude_dirs.update(str(d) for d in section.get("exclude_dirs", []))
    cfg.exclude_files.update(str(f) for f in section.get("exclude_files", []))
    cfg.ignore_rules = {str(r).strip().upper() for r in section.get("ignore_rules", []) if str(r).strip()}
    cfg.source_path = cfg_file.name
    return cfg


def init_config_file(root_dir: Path) -> Path:
    cfg_file = root_dir / ".swarm.toml"
    cfg_file.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    return cfg_file
