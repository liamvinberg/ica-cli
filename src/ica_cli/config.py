from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


APP_DIR = Path.home() / ".config" / "ica-cli"
CONFIG_PATH = APP_DIR / "config.json"
KEYCHAIN_SERVICE = "ica-cli"


class ConfigError(RuntimeError):
    pass


@dataclass
class AppConfig:
    provider: str = "ica-current"
    username: str | None = None
    default_list_name: str | None = None
    store_id: str | None = None


def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    if not CONFIG_PATH.exists():
        return AppConfig()

    try:
        payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError(f"Invalid JSON in {CONFIG_PATH}: {error}") from error

    return AppConfig(
        provider=payload.get("provider", "ica-current"),
        username=payload.get("username"),
        default_list_name=payload.get("default_list_name"),
        store_id=payload.get("store_id"),
    )


def save_config(config: AppConfig) -> None:
    ensure_app_dir()
    CONFIG_PATH.write_text(
        json.dumps(
            {
                "provider": config.provider,
                "username": config.username,
                "default_list_name": config.default_list_name,
                "store_id": config.store_id,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def keychain_set(account: str, value: str) -> None:
    cmd = [
        "security",
        "add-generic-password",
        "-U",
        "-a",
        account,
        "-s",
        KEYCHAIN_SERVICE,
        "-w",
        value,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ConfigError(
            result.stderr.strip() or "Unable to store secret in macOS Keychain"
        )


def keychain_get(account: str) -> str | None:
    cmd = [
        "security",
        "find-generic-password",
        "-a",
        account,
        "-s",
        KEYCHAIN_SERVICE,
        "-w",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def keychain_delete(account: str) -> None:
    cmd = ["security", "delete-generic-password", "-a", account, "-s", KEYCHAIN_SERVICE]
    subprocess.run(cmd, capture_output=True, text=True, check=False)
