from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


APP_DIR = Path.home() / ".config" / "ica-cli"
CONFIG_PATH = APP_DIR / "config.json"
KEYCHAIN_SERVICE = "ica-cli"
SECRETS_PATH = APP_DIR / "secrets.json"


class ConfigError(RuntimeError):
    pass


@dataclass
class AppConfig:
    provider: str = "ica-current"
    username: str | None = None
    default_list_name: str | None = None
    store_id: str | None = None
    store_ids: list[str] | None = None


def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    if not CONFIG_PATH.exists():
        return AppConfig()

    try:
        payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError(f"Invalid JSON in {CONFIG_PATH}: {error}") from error

    store_ids_raw = payload.get("store_ids")
    store_ids: list[str] | None = None
    if isinstance(store_ids_raw, list):
        parsed = [str(item).strip() for item in store_ids_raw if str(item).strip()]
        store_ids = parsed if parsed else None

    legacy_store_id = payload.get("store_id")
    if (
        store_ids is None
        and isinstance(legacy_store_id, str)
        and legacy_store_id.strip()
    ):
        store_ids = [legacy_store_id.strip()]

    return AppConfig(
        provider=payload.get("provider", "ica-current"),
        username=payload.get("username"),
        default_list_name=payload.get("default_list_name"),
        store_id=legacy_store_id,
        store_ids=store_ids,
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
                "store_ids": config.store_ids,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _can_use_macos_keychain() -> bool:
    return os.uname().sysname == "Darwin"


def _load_file_secrets() -> dict[str, str]:
    if not SECRETS_PATH.exists():
        return {}
    try:
        payload = json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in payload.items()
        if isinstance(key, str) and isinstance(value, str)
    }


def _write_file_secrets(payload: dict[str, str]) -> None:
    ensure_app_dir()
    SECRETS_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    SECRETS_PATH.chmod(0o600)


def _file_secret_set(account: str, value: str) -> None:
    payload = _load_file_secrets()
    payload[account] = value
    _write_file_secrets(payload)


def _file_secret_get(account: str) -> str | None:
    return _load_file_secrets().get(account)


def _file_secret_delete(account: str) -> None:
    payload = _load_file_secrets()
    if account in payload:
        del payload[account]
        _write_file_secrets(payload)


def keychain_set(account: str, value: str) -> None:
    if not _can_use_macos_keychain():
        _file_secret_set(account, value)
        return

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
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        _file_secret_set(account, value)
        return
    if result.returncode != 0:
        _file_secret_set(account, value)


def keychain_get(account: str) -> str | None:
    if not _can_use_macos_keychain():
        return _file_secret_get(account)

    cmd = [
        "security",
        "find-generic-password",
        "-a",
        account,
        "-s",
        KEYCHAIN_SERVICE,
        "-w",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return _file_secret_get(account)
    if result.returncode != 0:
        return _file_secret_get(account)
    return result.stdout.strip()


def keychain_delete(account: str) -> None:
    if not _can_use_macos_keychain():
        _file_secret_delete(account)
        return

    cmd = ["security", "delete-generic-password", "-a", account, "-s", KEYCHAIN_SERVICE]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        _file_secret_delete(account)
        return
    if result.returncode != 0:
        _file_secret_delete(account)
