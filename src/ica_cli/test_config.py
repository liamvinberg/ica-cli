from __future__ import annotations

import subprocess
import tempfile
import unittest
import json
from pathlib import Path
from unittest import mock

from ica_cli import config


class TestConfigSecretStorage(unittest.TestCase):
    tempdir: tempfile.TemporaryDirectory[str] | None = None
    original_app_dir: Path | None = None
    original_config_path: Path | None = None
    original_secrets_path: Path | None = None

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

        self.original_app_dir = config.APP_DIR
        self.original_config_path = config.CONFIG_PATH
        self.original_secrets_path = config.SECRETS_PATH
        self.addCleanup(self._restore_paths)

        app_dir = Path(self.tempdir.name)
        config.APP_DIR = app_dir
        config.CONFIG_PATH = app_dir / "config.json"
        config.SECRETS_PATH = app_dir / "secrets.json"

    def _restore_paths(self) -> None:
        assert self.original_app_dir is not None
        assert self.original_config_path is not None
        assert self.original_secrets_path is not None
        config.APP_DIR = self.original_app_dir
        config.CONFIG_PATH = self.original_config_path
        config.SECRETS_PATH = self.original_secrets_path

    def test_non_darwin_uses_file_secret_store(self) -> None:
        with mock.patch("ica_cli.config._can_use_macos_keychain", return_value=False):
            config.keychain_set("current-session:test-user", "sess-123")
            secret = config.keychain_get("current-session:test-user")

        self.assertEqual(secret, "sess-123")
        self.assertTrue(config.SECRETS_PATH.exists())

    def test_darwin_missing_security_cli_falls_back_to_file_store(self) -> None:
        with (
            mock.patch("ica_cli.config._can_use_macos_keychain", return_value=True),
            mock.patch(
                "ica_cli.config.subprocess.run",
                side_effect=FileNotFoundError,
            ),
        ):
            config.keychain_set("current-access-token:test-user", "token-abc")

        stored = config._file_secret_get("current-access-token:test-user")
        self.assertEqual(stored, "token-abc")

    def test_darwin_nonzero_security_exit_reads_file_fallback(self) -> None:
        with (
            mock.patch("ica_cli.config._can_use_macos_keychain", return_value=True),
            mock.patch(
                "ica_cli.config.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["security"],
                    returncode=1,
                    stdout="",
                    stderr="not found",
                ),
            ),
        ):
            config._file_secret_set("legacy-access-token:test-user", "legacy-token")
            secret = config.keychain_get("legacy-access-token:test-user")

        self.assertEqual(secret, "legacy-token")

    def test_delete_removes_file_secret_when_non_darwin(self) -> None:
        with mock.patch("ica_cli.config._can_use_macos_keychain", return_value=False):
            config.keychain_set("legacy-refresh-token:test-user", "refresh-1")
            config.keychain_delete("legacy-refresh-token:test-user")
            secret = config.keychain_get("legacy-refresh-token:test-user")

        self.assertIsNone(secret)

    def test_load_config_migrates_single_store_id_to_store_ids(self) -> None:
        config.CONFIG_PATH.write_text(
            json.dumps(
                {
                    "provider": "ica-current",
                    "username": "199001010000",
                    "store_id": "1004394",
                }
            ),
            encoding="utf-8",
        )

        loaded = config.load_config()
        self.assertEqual(loaded.store_id, "1004394")
        self.assertEqual(loaded.store_ids, ["1004394"])

    def test_save_config_persists_store_ids(self) -> None:
        to_save = config.AppConfig(
            provider="ica-current",
            username="199001010000",
            default_list_name="Min lista",
            store_id="1004394",
            store_ids=["1004394", "1001234"],
        )
        config.save_config(to_save)

        payload = json.loads(config.CONFIG_PATH.read_text(encoding="utf-8"))
        self.assertEqual(payload["store_id"], "1004394")
        self.assertEqual(payload["store_ids"], ["1004394", "1001234"])
