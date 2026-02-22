from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import re
import secrets
import sys
import webbrowser
from urllib.parse import parse_qs, urlencode, urlparse

from ica_cli.config import (
    AppConfig,
    keychain_delete,
    keychain_get,
    keychain_set,
    load_config,
    save_config,
)
from ica_cli.provider_factory import build_provider
from ica_cli.providers import IcaCurrentProvider, IcaLegacyProvider, ProviderError


SUPPORTED_PROVIDERS = ("ica-current", "ica-legacy")
ICA_REDIRECT_URI = "https://www.ica.se/logga-in/sso/callback"


def _kc_current_session(username: str) -> str:
    return f"current-session:{username}"


def _kc_current_access(username: str) -> str:
    return f"current-access-token:{username}"


def _kc_current_refresh(username: str) -> str:
    return f"current-refresh-token:{username}"


def _kc_current_pkce_verifier(username: str) -> str:
    return f"current-pkce-verifier:{username}"


def _kc_current_pkce_state(username: str) -> str:
    return f"current-pkce-state:{username}"


def _kc_legacy_auth_ticket(username: str) -> str:
    return f"legacy-auth-ticket:{username}"


def _kc_legacy_access(username: str) -> str:
    return f"legacy-access-token:{username}"


def _kc_legacy_refresh(username: str) -> str:
    return f"legacy-refresh-token:{username}"


def _kc_legacy_oauth_client_id(username: str) -> str:
    return f"legacy-oauth-client-id:{username}"


def _kc_legacy_oauth_client_secret(username: str) -> str:
    return f"legacy-oauth-client-secret:{username}"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def generate_oauth_scaffold() -> dict[str, str]:
    verifier = _base64url(secrets.token_bytes(48))
    challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    params = {
        "client_id": "ica.se",
        "response_type": "code",
        "scope": "openid ica-se-scope ica-se-scope-hard",
        "prompt": "login",
        "redirect_uri": ICA_REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "nonce": nonce,
    }
    authorize_url = "https://ims.icagruppen.se/oauth/v2/authorize?" + urlencode(params)
    return {
        "authorize_url": authorize_url,
        "code_verifier": verifier,
        "code_challenge": challenge,
        "state": state,
        "nonce": nonce,
    }


def _normalize_callback_url(callback_url: str) -> str:
    normalized = callback_url.strip().strip('"').strip("'")
    normalized = re.sub(r"\\([?&=])", r"\1", normalized)
    return normalized


def _parse_callback_url(callback_url: str) -> tuple[str, str]:
    normalized = _normalize_callback_url(callback_url)
    parsed = urlparse(normalized)
    query = parse_qs(parsed.query)
    code_values = query.get("code", [])
    state_values = query.get("state", [])
    if not code_values or not state_values:
        raise ProviderError("Callback URL is missing required code/state query values")
    code = code_values[0].strip()
    state = state_values[0].strip()
    if not code or not state:
        raise ProviderError("Callback URL contained empty code/state values")
    return code, state


def _extract_raw_payload(payload: object) -> object:
    if not isinstance(payload, dict):
        return payload

    if "result" in payload:
        return payload["result"]
    if "lists" in payload:
        return payload["lists"]
    if "items" in payload:
        return payload["items"]
    if "profile" in payload:
        return payload["profile"]
    return payload


def _list_name(item: dict[str, object]) -> str:
    value = item.get("name") or item.get("Title") or item.get("OfflineName")
    if isinstance(value, str) and value:
        return value
    return "<unnamed list>"


def _list_item_count(item: dict[str, object]) -> int | None:
    rows = item.get("rows")
    if isinstance(rows, list):
        return len(rows)
    rows = item.get("Rows")
    if isinstance(rows, list):
        return len(rows)
    count = item.get("rowCount")
    if isinstance(count, int):
        return count
    return None


def _list_rows(item: dict[str, object]) -> list[dict[str, object]]:
    rows = item.get("rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    rows = item.get("Rows")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def _row_name(row: dict[str, object]) -> str:
    value = row.get("text") or row.get("name") or row.get("ProductName")
    if isinstance(value, str) and value:
        return value
    return "<unnamed item>"


def _row_is_done(row: dict[str, object]) -> bool:
    value = row.get("isStriked")
    if isinstance(value, bool):
        return value
    value = row.get("IsStrikedOver")
    if isinstance(value, bool):
        return value
    return False


def _find_list_by_name(
    lists: list[dict[str, object]],
    list_name: str,
) -> dict[str, object] | None:
    normalized_target = list_name.strip().lower()
    for item in lists:
        name = _list_name(item)
        if name.strip().lower() == normalized_target:
            return item
    return None


def _format_human(payload: object, args: argparse.Namespace) -> str:
    command = getattr(args, "command", None)
    if isinstance(payload, str):
        return payload

    if command == "config" and isinstance(payload, dict):
        config_cmd = getattr(args, "config_cmd", None)
        if config_cmd == "show":
            lines = ["Config:"]
            lines.append(f"- provider: {payload.get('provider') or '-'}")
            lines.append(f"- username: {payload.get('username') or '-'}")
            lines.append(
                f"- default_list_name: {payload.get('default_list_name') or '-'}"
            )
            lines.append(f"- store_id: {payload.get('store_id') or '-'}")
            return "\n".join(lines)

        updates = [
            f"{key}={value}"
            for key, value in payload.items()
            if key != "ok" and value is not None
        ]
        if updates:
            return "Updated " + ", ".join(updates)

    if command == "auth" and isinstance(payload, dict):
        auth_cmd = getattr(args, "auth_cmd", None)
        if auth_cmd == "status":
            provider = payload.get("provider", "unknown")
            username = payload.get("username", "-")
            if provider == "ica-current":
                return (
                    f"Auth status for {username}: provider=ica-current, "
                    f"session={'yes' if payload.get('has_session') else 'no'}, "
                    f"access_token={'yes' if payload.get('has_access_token') else 'no'}, "
                    f"refresh_token={'yes' if payload.get('has_refresh_token') else 'no'}"
                )
            if provider == "ica-legacy":
                return (
                    f"Auth status for {username}: provider=ica-legacy, "
                    f"authenticated={'yes' if payload.get('authenticated') else 'no'}, "
                    f"auth_ticket={'yes' if payload.get('has_auth_ticket') else 'no'}, "
                    f"access_token={'yes' if payload.get('has_access_token') else 'no'}"
                )

        if auth_cmd == "login" and payload.get("mode") == "agentic":
            return (
                "Agentic auth prepared. Open this URL and then pass callback URL:\n"
                f"{payload.get('authorize_url')}"
            )

        if payload.get("ok"):
            method = payload.get("method")
            if method == "callback-session":
                return "Login successful using callback session handoff."
            if method == "authorization-code":
                return "Login successful using authorization-code exchange."
            if method == "session-id":
                return "Login successful using imported session id."
            if method == "session-id-fallback":
                return "Login successful using thSessionId fallback."
            if method == "legacy-ticket":
                return "Login successful using legacy authentication ticket."
            if method == "current-oauth-fallback":
                return "Login successful using legacy fallback OAuth flow."
            return "Authentication data saved."

    if command == "list" and isinstance(payload, dict):
        list_cmd = getattr(args, "list_cmd", None)
        if list_cmd == "ls":
            lists = payload.get("lists")
            if not isinstance(lists, list) or len(lists) == 0:
                return "No shopping lists found."
            lines = [f"Shopping lists ({len(lists)}):"]
            for item in lists:
                if not isinstance(item, dict):
                    continue
                name = _list_name(item)
                count = _list_item_count(item)
                if count is None:
                    lines.append(f"- {name}")
                else:
                    lines.append(f"- {name} ({count} items)")
            return "\n".join(lines)

        if list_cmd == "add":
            list_name = payload.get("list")
            item_name = payload.get("item")
            if isinstance(list_name, str) and isinstance(item_name, str):
                return f'Added "{item_name}" to "{list_name}".'

        if list_cmd == "items":
            list_name = payload.get("list")
            items = payload.get("items")
            if isinstance(list_name, str) and isinstance(items, list):
                if len(items) == 0:
                    return f'No items in "{list_name}".'
                lines = [f'Items in "{list_name}" ({len(items)}):']
                for row in items:
                    if not isinstance(row, dict):
                        continue
                    marker = "[x]" if _row_is_done(row) else "[ ]"
                    lines.append(f"- {marker} {_row_name(row)}")
                return "\n".join(lines)

    if command == "products" and isinstance(payload, dict):
        result = payload.get("result")
        query = payload.get("query", "")
        if isinstance(result, dict):
            entries = result.get("documents")
            if not isinstance(entries, list):
                entries = result.get("products")
            if isinstance(entries, list):
                if len(entries) == 0:
                    return f'No product matches for "{query}".'
                lines = [f'Product matches for "{query}" ({len(entries)}):']
                for entry in entries[:10]:
                    if not isinstance(entry, dict):
                        continue
                    name = (
                        entry.get("name")
                        or entry.get("productName")
                        or entry.get("title")
                    )
                    if not isinstance(name, str) or not name:
                        name = str(entry.get("id", "<unknown>"))
                    lines.append(f"- {name}")
                if len(entries) > 10:
                    lines.append(f"...and {len(entries) - 10} more")
                return "\n".join(lines)

    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)


def _emit(payload: object, args: argparse.Namespace) -> None:
    if args.raw:
        raw_payload = _extract_raw_payload(payload)
        print(json.dumps(raw_payload, ensure_ascii=True, separators=(",", ":")))
        return

    if args.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))
        return

    print(_format_human(payload, args))


def _require_username(config: AppConfig) -> str:
    if not config.username:
        raise ProviderError(
            "No username configured. Run: ica config set-username <value>"
        )
    return config.username


def _resolve_auth_username(config: AppConfig, args: argparse.Namespace) -> str:
    cli_username = getattr(args, "username", None)
    if isinstance(cli_username, str):
        cli_username = cli_username.strip()
    if cli_username:
        if config.username != cli_username:
            config.username = cli_username
            save_config(config)
        return cli_username

    if config.username:
        return config.username

    if getattr(args, "agentic", False) or getattr(args, "non_interactive", False):
        raise ProviderError(
            "No username configured. Pass --username (or --user) in non-interactive mode."
        )

    username = input("ICA username/personnummer: ").strip()
    if not username:
        raise ProviderError("No username provided")

    config.username = username
    save_config(config)
    return username


def _store_current_auth(
    username: str,
    session_id: str | None = None,
    access_token: str | None = None,
    refresh_token: str | None = None,
) -> None:
    if session_id:
        keychain_set(_kc_current_session(username), session_id)
    if access_token:
        keychain_set(_kc_current_access(username), access_token)
    if refresh_token:
        keychain_set(_kc_current_refresh(username), refresh_token)


def _store_legacy_auth(
    username: str,
    auth_ticket: str | None = None,
    access_token: str | None = None,
    refresh_token: str | None = None,
    oauth_client_id: str | None = None,
    oauth_client_secret: str | None = None,
) -> None:
    if auth_ticket:
        keychain_set(_kc_legacy_auth_ticket(username), auth_ticket)
    if access_token:
        keychain_set(_kc_legacy_access(username), access_token)
    if refresh_token:
        keychain_set(_kc_legacy_refresh(username), refresh_token)
    if oauth_client_id:
        keychain_set(_kc_legacy_oauth_client_id(username), oauth_client_id)
    if oauth_client_secret:
        keychain_set(_kc_legacy_oauth_client_secret(username), oauth_client_secret)


def _ensure_current_provider(config: AppConfig) -> None:
    if config.provider != "ica-current":
        config.provider = "ica-current"
        save_config(config)


def _complete_current_auth_from_callback(
    username: str,
    callback_url: str,
    allow_state_mismatch: bool,
    code_verifier: str | None,
) -> dict[str, object]:
    normalized_callback = _normalize_callback_url(callback_url)
    code, state = _parse_callback_url(normalized_callback)

    provider = IcaCurrentProvider()
    callback_session_error: str | None = None
    try:
        session_id = provider.bootstrap_session_from_callback(normalized_callback)
        access_token = provider.refresh_access_token()
        _store_current_auth(username, session_id=session_id, access_token=access_token)
        keychain_delete(_kc_current_pkce_verifier(username))
        keychain_delete(_kc_current_pkce_state(username))
        return {
            "ok": True,
            "provider": "ica-current",
            "username": username,
            "method": "callback-session",
            "access_token_length": len(access_token),
        }
    except ProviderError as error:
        callback_session_error = str(error)

    expected_state = keychain_get(_kc_current_pkce_state(username))
    if expected_state and state != expected_state and not allow_state_mismatch:
        raise ProviderError(
            "State mismatch. Run auth current-begin again, then retry with fresh callback URL. "
            "Use --allow-state-mismatch only if you intentionally bypass this check."
        )

    verifier = code_verifier or keychain_get(_kc_current_pkce_verifier(username))
    if not verifier:
        raise ProviderError(
            "ICA callback did not yield a session cookie and no code_verifier is available for code exchange. "
            f"Callback session error: {callback_session_error}"
        )

    try:
        token_payload = provider.exchange_authorization_code(
            code=code,
            code_verifier=verifier,
            state=state,
        )
    except ProviderError as code_error:
        raise ProviderError(
            "ICA callback completion failed. "
            f"Session bootstrap error: {callback_session_error}. "
            f"Authorization-code exchange error: {code_error}. "
            "This usually means the callback code was already consumed in browser. "
            "Use auth session import with thSessionId or run auth login and complete immediately."
        ) from code_error
    access_token = token_payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise ProviderError(
            "Token response did not include access_token. "
            f"Callback session error: {callback_session_error}"
        )

    refresh_token = token_payload.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token:
        _store_current_auth(
            username, access_token=access_token, refresh_token=refresh_token
        )
    else:
        _store_current_auth(username, access_token=access_token)

    keychain_delete(_kc_current_pkce_verifier(username))
    keychain_delete(_kc_current_pkce_state(username))

    return {
        "ok": True,
        "provider": "ica-current",
        "username": username,
        "method": "authorization-code",
        "has_refresh_token": isinstance(refresh_token, str) and bool(refresh_token),
        "token_type": token_payload.get("token_type", "Bearer"),
    }


def cmd_config_set_provider(args: argparse.Namespace, config: AppConfig) -> object:
    config.provider = args.provider
    save_config(config)
    return {"ok": True, "provider": config.provider}


def cmd_config_set_username(args: argparse.Namespace, config: AppConfig) -> object:
    config.username = args.username
    save_config(config)
    return {"ok": True, "username": config.username}


def cmd_config_set_default_list(args: argparse.Namespace, config: AppConfig) -> object:
    config.default_list_name = args.list_name
    save_config(config)
    return {"ok": True, "default_list_name": config.default_list_name}


def cmd_config_show(_: argparse.Namespace, config: AppConfig) -> object:
    return {
        "provider": config.provider,
        "username": config.username,
        "default_list_name": config.default_list_name,
        "store_id": config.store_id,
    }


def cmd_config_set_store_id(args: argparse.Namespace, config: AppConfig) -> object:
    config.store_id = args.store_id
    save_config(config)
    return {"ok": True, "store_id": config.store_id}


def cmd_auth_login(args: argparse.Namespace, config: AppConfig) -> object:
    username = _resolve_auth_username(config, args)
    if config.provider == "ica-legacy":
        if args.password_stdin:
            password = sys.stdin.read().strip()
        elif args.password:
            password = args.password
        else:
            password = getpass.getpass("ICA password: ")
        if not password:
            raise ProviderError("Password is required")

        provider = IcaLegacyProvider()
        login_result = provider.login(username=username, password=password)
        method = login_result.get("method")
        auth_ticket = login_result.get("auth_ticket")
        access_token = login_result.get("access_token")
        refresh_token = login_result.get("refresh_token")
        oauth_client_id = login_result.get("oauth_client_id")
        oauth_client_secret = login_result.get("oauth_client_secret")

        if isinstance(auth_ticket, str) and auth_ticket:
            _store_legacy_auth(username=username, auth_ticket=auth_ticket)

        if isinstance(access_token, str) and access_token:
            _store_legacy_auth(
                username=username,
                access_token=access_token,
                refresh_token=refresh_token if isinstance(refresh_token, str) else None,
                oauth_client_id=oauth_client_id
                if isinstance(oauth_client_id, str)
                else None,
                oauth_client_secret=(
                    oauth_client_secret
                    if isinstance(oauth_client_secret, str)
                    else None
                ),
            )

        if isinstance(login_result.get("session_id"), str) and login_result.get(
            "session_id"
        ):
            _store_current_auth(
                username=username,
                session_id=login_result["session_id"],
            )

        return {
            "ok": True,
            "provider": "ica-legacy",
            "method": method,
            "has_auth_ticket": isinstance(auth_ticket, str) and bool(auth_ticket),
            "has_access_token": isinstance(access_token, str) and bool(access_token),
            "profile": login_result.get("profile", {}),
        }

    if args.callback_url:
        result = _complete_current_auth_from_callback(
            username=username,
            callback_url=args.callback_url,
            allow_state_mismatch=args.allow_state_mismatch,
            code_verifier=args.code_verifier,
        )
        _ensure_current_provider(config)
        return result

    if args.session_id:
        provider = IcaCurrentProvider(session_id=args.session_id)
        access_token = provider.refresh_access_token()
        _store_current_auth(
            username=username,
            session_id=args.session_id,
            access_token=access_token,
        )
        _ensure_current_provider(config)
        return {
            "ok": True,
            "provider": "ica-current",
            "username": username,
            "method": "session-id",
            "access_token_length": len(access_token),
        }

    scaffold = generate_oauth_scaffold()
    keychain_set(_kc_current_pkce_verifier(username), scaffold["code_verifier"])
    keychain_set(_kc_current_pkce_state(username), scaffold["state"])

    if args.agentic:
        return {
            "ok": True,
            "provider": "ica-current",
            "username": username,
            "mode": "agentic",
            "authorize_url": scaffold["authorize_url"],
            "next": "Run: ica --json auth login --agentic --callback-url '<full callback URL>'",
        }

    if args.non_interactive:
        raise ProviderError(
            "Non-interactive mode requires --callback-url or --session-id for ica-current."
        )

    if not args.no_open_browser:
        input("Press Enter to open ICA login in your browser...")
        opened = webbrowser.open(scaffold["authorize_url"])
        if not opened:
            print("Could not open browser automatically. Open this URL manually:")
            print(scaffold["authorize_url"])
    else:
        print("Open this URL in your browser and complete ICA login:")
        print(scaffold["authorize_url"])

    callback_url = input("Paste full callback URL: ").strip()
    if not callback_url:
        raise ProviderError("No callback URL provided")

    try:
        result = _complete_current_auth_from_callback(
            username=username,
            callback_url=callback_url,
            allow_state_mismatch=args.allow_state_mismatch,
            code_verifier=args.code_verifier,
        )
        _ensure_current_provider(config)
        return result
    except ProviderError as callback_error:
        if "invalid_client" not in str(callback_error):
            raise
        print(
            "Callback code appears consumed by browser. You can finish login by pasting thSessionId."
        )
        session_id = input("Paste thSessionId (leave empty to abort): ").strip()
        if not session_id:
            raise
        provider = IcaCurrentProvider(session_id=session_id)
        access_token = provider.refresh_access_token()
        _store_current_auth(
            username=username,
            session_id=session_id,
            access_token=access_token,
        )
        _ensure_current_provider(config)
        return {
            "ok": True,
            "provider": "ica-current",
            "username": username,
            "method": "session-id-fallback",
            "access_token_length": len(access_token),
        }


def cmd_auth_session_import(args: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    _store_current_auth(username=username, session_id=args.session_id)
    _ensure_current_provider(config)
    return {"ok": True, "provider": "ica-current", "username": username}


def cmd_auth_token_import(args: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    _store_current_auth(
        username=username,
        access_token=args.access_token,
        refresh_token=args.refresh_token,
    )
    _ensure_current_provider(config)
    return {
        "ok": True,
        "provider": "ica-current",
        "username": username,
        "has_refresh_token": bool(args.refresh_token),
    }


def cmd_auth_current_begin(_: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    scaffold = generate_oauth_scaffold()
    keychain_set(_kc_current_pkce_verifier(username), scaffold["code_verifier"])
    keychain_set(_kc_current_pkce_state(username), scaffold["state"])
    return {
        "ok": True,
        "provider": "ica-current",
        "username": username,
        "authorize_url": scaffold["authorize_url"],
        "state": scaffold["state"],
        "next": "Run: ica --json auth current-complete --callback-url '<full callback URL>'",
    }


def cmd_auth_current_complete(args: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    if args.callback_url:
        result = _complete_current_auth_from_callback(
            username=username,
            callback_url=args.callback_url,
            allow_state_mismatch=args.allow_state_mismatch,
            code_verifier=args.code_verifier,
        )
        _ensure_current_provider(config)
        return result

    code = args.code
    state = args.state
    if not code:
        raise ProviderError(
            "No authorization code found. Provide --callback-url or --code"
        )
    if not state:
        raise ProviderError("No state found. Provide --callback-url or --state")

    expected_state = keychain_get(_kc_current_pkce_state(username))
    if expected_state and state != expected_state and not args.allow_state_mismatch:
        raise ProviderError(
            "State mismatch. Run auth current-begin again, then retry with fresh callback URL. "
            "Use --allow-state-mismatch only if you intentionally bypass this check."
        )

    code_verifier = args.code_verifier or keychain_get(
        _kc_current_pkce_verifier(username)
    )
    if not code_verifier:
        raise ProviderError(
            "No code_verifier available. Run auth current-begin first or pass --code-verifier"
        )

    provider = IcaCurrentProvider()
    token_payload = provider.exchange_authorization_code(
        code=code,
        code_verifier=code_verifier,
        state=state,
    )
    access_token = token_payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise ProviderError("Token response did not include access_token")

    refresh_token = token_payload.get("refresh_token")
    _store_current_auth(
        username=username,
        access_token=access_token,
        refresh_token=refresh_token if isinstance(refresh_token, str) else None,
    )
    keychain_delete(_kc_current_pkce_verifier(username))
    keychain_delete(_kc_current_pkce_state(username))
    _ensure_current_provider(config)

    return {
        "ok": True,
        "provider": "ica-current",
        "username": username,
        "method": "authorization-code",
        "has_refresh_token": isinstance(refresh_token, str) and bool(refresh_token),
        "token_type": token_payload.get("token_type", "Bearer"),
    }


def cmd_auth_login_current(args: argparse.Namespace, config: AppConfig) -> object:
    alias_args = argparse.Namespace(
        password_stdin=False,
        callback_url=None,
        session_id=args.session_id,
        code_verifier=None,
        allow_state_mismatch=False,
        agentic=args.show_authorize_url,
        non_interactive=args.non_interactive,
        no_open_browser=False,
    )
    return cmd_auth_login(alias_args, config)


def cmd_auth_logout(_: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    keychain_delete(_kc_legacy_auth_ticket(username))
    keychain_delete(_kc_legacy_access(username))
    keychain_delete(_kc_legacy_refresh(username))
    keychain_delete(_kc_legacy_oauth_client_id(username))
    keychain_delete(_kc_legacy_oauth_client_secret(username))
    keychain_delete(_kc_current_session(username))
    keychain_delete(_kc_current_access(username))
    keychain_delete(_kc_current_refresh(username))
    keychain_delete(_kc_current_pkce_verifier(username))
    keychain_delete(_kc_current_pkce_state(username))
    return {"ok": True, "username": username}


def cmd_auth_status(_: argparse.Namespace, config: AppConfig) -> object:
    provider = build_provider(config)
    username = _require_username(config)
    if isinstance(provider, IcaLegacyProvider):
        has_auth_ticket = provider.auth_ticket is not None
        has_access_token = provider.access_token is not None
        return {
            "provider": "ica-legacy",
            "username": username,
            "authenticated": has_auth_ticket or has_access_token,
            "has_auth_ticket": has_auth_ticket,
            "has_access_token": has_access_token,
        }
    if isinstance(provider, IcaCurrentProvider):
        return {
            "provider": "ica-current",
            "username": username,
            "has_session": provider.session_id is not None,
            "has_access_token": provider.access_token is not None,
            "has_refresh_token": provider.refresh_token is not None,
        }
    return {"provider": config.provider, "username": username, "authenticated": False}


def cmd_list_ls(_: argparse.Namespace, config: AppConfig) -> object:
    provider = build_provider(config)
    data = provider.list_lists()
    return {"provider": config.provider, "lists": data}


def cmd_list_add(args: argparse.Namespace, config: AppConfig) -> object:
    provider = build_provider(config)
    list_name = args.list_name or config.default_list_name
    if not list_name:
        raise ProviderError(
            "No list name provided. Use --list-name or set default with: ica config set-default-list <name>"
        )
    return provider.add_item(
        list_name=list_name, item_name=args.item, quantity=args.quantity
    )


def cmd_list_items(args: argparse.Namespace, config: AppConfig) -> object:
    provider = build_provider(config)
    raw_lists = provider.list_lists()
    lists = [item for item in raw_lists if isinstance(item, dict)]

    list_name = args.list_name or config.default_list_name
    if not list_name:
        if len(lists) == 1:
            selected = lists[0]
            list_name = _list_name(selected)
        else:
            raise ProviderError(
                "No list name provided. Use --list-name or set default with: ica config set-default-list <name>"
            )

    selected = _find_list_by_name(lists, list_name)
    if not selected:
        raise ProviderError(
            f"List '{list_name}' not found. Existing lists: "
            + ", ".join(_list_name(item) for item in lists)
        )

    rows = _list_rows(selected)
    resolved_name = _list_name(selected)
    return {
        "provider": config.provider,
        "list": resolved_name,
        "items": rows,
        "count": len(rows),
    }


def cmd_products_search(args: argparse.Namespace, config: AppConfig) -> object:
    provider = build_provider(config)
    store_id = args.store_id or config.store_id
    if not store_id:
        raise ProviderError(
            "No store id provided. Use --store-id or set default with: ica config set-store-id <id>"
        )
    result = provider.search_products(store_id=store_id, query=args.query)
    return {
        "provider": config.provider,
        "store_id": store_id,
        "query": args.query,
        "result": result,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ica", description="ICA CLI")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--json", action="store_true", help="Output JSON")
    output_group.add_argument(
        "--raw",
        action="store_true",
        help="Output raw API payload only",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    config_parser = subparsers.add_parser("config")
    config_sub = config_parser.add_subparsers(dest="config_cmd", required=True)

    config_set_provider = config_sub.add_parser("set-provider")
    config_set_provider.add_argument("provider", choices=SUPPORTED_PROVIDERS)
    config_set_provider.set_defaults(handler=cmd_config_set_provider)

    config_set_username = config_sub.add_parser("set-username")
    config_set_username.add_argument("username")
    config_set_username.set_defaults(handler=cmd_config_set_username)

    config_set_default_list = config_sub.add_parser("set-default-list")
    config_set_default_list.add_argument("list_name")
    config_set_default_list.set_defaults(handler=cmd_config_set_default_list)

    config_set_store_id = config_sub.add_parser("set-store-id")
    config_set_store_id.add_argument("store_id")
    config_set_store_id.set_defaults(handler=cmd_config_set_store_id)

    config_show = config_sub.add_parser("show")
    config_show.set_defaults(handler=cmd_config_show)

    auth_parser = subparsers.add_parser("auth")
    auth_sub = auth_parser.add_subparsers(dest="auth_cmd", required=True)

    auth_login = auth_sub.add_parser("login")
    auth_login.add_argument("--username", "--user", dest="username")
    auth_login.add_argument("--password", "--pass", dest="password")
    auth_login.add_argument("--password-stdin", action="store_true")
    auth_login.add_argument("--callback-url")
    auth_login.add_argument("--session-id")
    auth_login.add_argument("--code-verifier")
    auth_login.add_argument("--allow-state-mismatch", action="store_true")
    auth_login.add_argument("--agentic", action="store_true")
    auth_login.add_argument("--non-interactive", action="store_true")
    auth_login.add_argument("--no-open-browser", action="store_true")
    auth_login.set_defaults(handler=cmd_auth_login)

    auth_token = auth_sub.add_parser("token")
    auth_token_sub = auth_token.add_subparsers(dest="auth_token_cmd", required=True)
    auth_token_import = auth_token_sub.add_parser("import")
    auth_token_import.add_argument("--access-token", required=True)
    auth_token_import.add_argument("--refresh-token")
    auth_token_import.set_defaults(handler=cmd_auth_token_import)

    auth_current_begin = auth_sub.add_parser("current-begin")
    auth_current_begin.set_defaults(handler=cmd_auth_current_begin)

    auth_current_complete = auth_sub.add_parser("current-complete")
    auth_current_complete.add_argument("--callback-url")
    auth_current_complete.add_argument("--code")
    auth_current_complete.add_argument("--state")
    auth_current_complete.add_argument("--code-verifier")
    auth_current_complete.add_argument("--allow-state-mismatch", action="store_true")
    auth_current_complete.set_defaults(handler=cmd_auth_current_complete)

    auth_login_current = auth_sub.add_parser("login-current")
    auth_login_current.add_argument("--session-id")
    auth_login_current.add_argument("--show-authorize-url", action="store_true")
    auth_login_current.add_argument("--non-interactive", action="store_true")
    auth_login_current.set_defaults(handler=cmd_auth_login_current)

    auth_session = auth_sub.add_parser("session")
    auth_session_sub = auth_session.add_subparsers(
        dest="auth_session_cmd", required=True
    )
    auth_session_import = auth_session_sub.add_parser("import")
    auth_session_import.add_argument("--session-id", required=True)
    auth_session_import.set_defaults(handler=cmd_auth_session_import)

    auth_logout = auth_sub.add_parser("logout")
    auth_logout.set_defaults(handler=cmd_auth_logout)

    auth_status = auth_sub.add_parser("status")
    auth_status.set_defaults(handler=cmd_auth_status)

    list_parser = subparsers.add_parser("list")
    list_sub = list_parser.add_subparsers(dest="list_cmd", required=True)

    list_ls = list_sub.add_parser("ls")
    list_ls.set_defaults(handler=cmd_list_ls)

    list_add = list_sub.add_parser("add")
    list_add.add_argument("item")
    list_add.add_argument("--list-name")
    list_add.add_argument("--quantity")
    list_add.set_defaults(handler=cmd_list_add)

    list_items = list_sub.add_parser("items")
    list_items.add_argument("--list-name")
    list_items.set_defaults(handler=cmd_list_items)

    products_parser = subparsers.add_parser("products")
    products_sub = products_parser.add_subparsers(dest="products_cmd", required=True)
    products_search = products_sub.add_parser("search")
    products_search.add_argument("query")
    products_search.add_argument("--store-id")
    products_search.set_defaults(handler=cmd_products_search)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    try:
        result = args.handler(args, config)
    except ProviderError as error:
        if args.json or args.raw:
            _emit({"ok": False, "error": str(error)}, args)
        else:
            print(f"Error: {error}")
        return 1

    _emit(result, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
