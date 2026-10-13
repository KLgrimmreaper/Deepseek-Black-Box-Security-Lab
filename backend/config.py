import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / ".env")

# public demo accounts of the default lab target. override with LAB_CREDENTIALS in .env
DEFAULT_CREDENTIALS = [
    "admin@juice-sh.op:admin123",
    "jim@juice-sh.op:ncc-1701",
    "admin:admin",
    "test@example.com:password",
    "user@example.com:123456",
]


def _int(name, default):
    value = os.getenv(name, "").strip()
    return int(value) if value else default


def _list(name, default):
    value = os.getenv(name, "").strip()
    if not value:
        return list(default)
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config(overrides=None):
    config = {
        "allowed_targets": _list("ALLOWED_TARGETS", ["http://localhost:3000"]),
        "deepseek_api_key": os.getenv("DEEPSEEK_API_KEY", "").strip(),
        "deepseek_model": os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip(),
        "max_requests_per_run": _int("MAX_REQUESTS_PER_RUN", 120),
        "request_delay_ms": _int("REQUEST_DELAY_MS", 200),
        "request_timeout": _int("REQUEST_TIMEOUT", 10),
        "mock_agent": os.getenv("MOCK_AGENT", "0").strip() == "1",
        "login_path": os.getenv("LOGIN_PATH", "/rest/user/login").strip(),
        "search_path": os.getenv("SEARCH_PATH", "/rest/products/search").strip(),
        "credentials": _list("LAB_CREDENTIALS", DEFAULT_CREDENTIALS),
        "max_checks_per_run": _int("MAX_CHECKS_PER_RUN", 13),
        "rate_limit_attempts": _int("RATE_LIMIT_ATTEMPTS", 10),
        "db_path": BASE_DIR / "data" / "lab.db",
        "evidence_dir": BASE_DIR / "evidence",
        "reports_dir": BASE_DIR / "reports",
    }
    if overrides:
        config.update(overrides)
    config["allowed_targets"] = [target.rstrip("/") for target in config["allowed_targets"]]
    return config
