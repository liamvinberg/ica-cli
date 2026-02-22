from __future__ import annotations

import os

from ica_cli.config import AppConfig, keychain_get
from ica_cli.providers import (
    IcaCurrentProvider,
    IcaLegacyProvider,
    IcaProvider,
    ProviderError,
)


def build_provider(config: AppConfig) -> IcaProvider:
    username = config.username
    if not username:
        raise ProviderError(
            "No username configured. Run: ica config set-username <value>"
        )

    if config.provider == "ica-current":
        session_id = os.getenv("ICA_CURRENT_SESSION_ID") or keychain_get(
            f"current-session:{username}"
        )
        access_token = os.getenv("ICA_CURRENT_ACCESS_TOKEN") or keychain_get(
            f"current-access-token:{username}"
        )
        refresh_token = os.getenv("ICA_CURRENT_REFRESH_TOKEN") or keychain_get(
            f"current-refresh-token:{username}"
        )
        return IcaCurrentProvider(
            session_id=session_id,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    if config.provider == "ica-legacy":
        auth_ticket = os.getenv("ICA_LEGACY_AUTH_TICKET") or keychain_get(
            f"legacy-auth-ticket:{username}"
        )
        access_token = os.getenv("ICA_LEGACY_ACCESS_TOKEN") or keychain_get(
            f"legacy-access-token:{username}"
        )
        refresh_token = os.getenv("ICA_LEGACY_REFRESH_TOKEN") or keychain_get(
            f"legacy-refresh-token:{username}"
        )
        oauth_client_id = os.getenv("ICA_LEGACY_OAUTH_CLIENT_ID") or keychain_get(
            f"legacy-oauth-client-id:{username}"
        )
        oauth_client_secret = os.getenv(
            "ICA_LEGACY_OAUTH_CLIENT_SECRET"
        ) or keychain_get(f"legacy-oauth-client-secret:{username}")
        return IcaLegacyProvider(
            auth_ticket=auth_ticket,
            access_token=access_token,
            refresh_token=refresh_token,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
        )

    raise ProviderError(
        f"Unknown provider '{config.provider}'. Supported providers: ica-current, ica-legacy"
    )
