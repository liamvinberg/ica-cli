from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import secrets
import sys
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


def _parse_callback_url(callback_url: str) -> tuple[str, str]:
    parsed = urlparse(callback_url)
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


def _emit(payload: object, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))
        return
    if isinstance(payload, str):
        print(payload)
        return
    print(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True))


def _require_username(config: AppConfig) -> str:
    if not config.username:
        raise ProviderError(
            "No username configured. Run: ica config set-username <value>"
        )
    return config.username


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
    username = _require_username(config)
    if args.password_stdin:
        password = sys.stdin.read().strip()
    else:
        password = getpass.getpass("ICA password: ")
    if not password:
        raise ProviderError("Password is required")

    if config.provider != "ica-legacy":
        raise ProviderError(
            "Password login is only available for ica-legacy. "
            "For ica-current, import thSessionId with: ica auth session import --session-id <value>"
        )

    provider = IcaLegacyProvider()
    login_result = provider.login(username=username, password=password)
    keychain_set(f"legacy-auth-ticket:{username}", login_result["auth_ticket"])
    return {
        "ok": True,
        "provider": "ica-legacy",
        "profile": login_result.get("profile", {}),
    }


def cmd_auth_session_import(args: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    keychain_set(_kc_current_session(username), args.session_id)
    if config.provider != "ica-current":
        config.provider = "ica-current"
        save_config(config)
    return {"ok": True, "provider": "ica-current", "username": username}


def cmd_auth_token_import(args: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    keychain_set(_kc_current_access(username), args.access_token)
    if args.refresh_token:
        keychain_set(_kc_current_refresh(username), args.refresh_token)
    if config.provider != "ica-current":
        config.provider = "ica-current"
        save_config(config)
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

    callback_url = args.callback_url
    code = args.code
    state = args.state

    if callback_url:
        code, state = _parse_callback_url(callback_url)

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
        raise ProviderError(
            "Token response did not include access_token. Current login flow may require session-cookie fallback."
        )

    refresh_token = token_payload.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token:
        keychain_set(_kc_current_refresh(username), refresh_token)

    keychain_set(_kc_current_access(username), access_token)
    keychain_delete(_kc_current_pkce_verifier(username))
    keychain_delete(_kc_current_pkce_state(username))

    if config.provider != "ica-current":
        config.provider = "ica-current"
        save_config(config)

    return {
        "ok": True,
        "provider": "ica-current",
        "username": username,
        "has_refresh_token": isinstance(refresh_token, str) and bool(refresh_token),
        "token_type": token_payload.get("token_type", "Bearer"),
    }


def cmd_auth_login_current(args: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    scaffold = generate_oauth_scaffold()
    session_id = args.session_id

    if not session_id:
        if args.non_interactive:
            raise ProviderError(
                "No session id provided. Pass --session-id in non-interactive mode."
            )
        print("Open this URL in your browser and complete ICA login:")
        print(scaffold["authorize_url"])
        session_id = input("Paste thSessionId: ").strip()

    if not session_id:
        raise ProviderError("No thSessionId provided")

    provider = IcaCurrentProvider(session_id=session_id)
    access_token = provider.refresh_access_token()
    keychain_set(_kc_current_session(username), session_id)
    keychain_set(_kc_current_access(username), access_token)
    if config.provider != "ica-current":
        config.provider = "ica-current"
        save_config(config)

    result = {
        "ok": True,
        "provider": "ica-current",
        "username": username,
        "access_token_length": len(access_token),
    }
    if args.show_authorize_url:
        result["authorize_url"] = scaffold["authorize_url"]
    return result


def cmd_auth_logout(_: argparse.Namespace, config: AppConfig) -> object:
    username = _require_username(config)
    keychain_delete(f"legacy-auth-ticket:{username}")
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
        return {
            "provider": "ica-legacy",
            "username": username,
            "authenticated": provider.auth_ticket is not None,
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
    parser.add_argument("--json", action="store_true", help="Output JSON")

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
    auth_login.add_argument("--password-stdin", action="store_true")
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
        _emit({"ok": False, "error": str(error)}, as_json=True)
        return 1

    _emit(result, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
