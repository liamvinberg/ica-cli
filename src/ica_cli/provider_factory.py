from __future__ import annotations

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
        session_id = keychain_get(f"current-session:{username}")
        return IcaCurrentProvider(session_id=session_id)

    if config.provider == "ica-legacy":
        auth_ticket = keychain_get(f"legacy-auth-ticket:{username}")
        return IcaLegacyProvider(auth_ticket=auth_ticket)

    raise ProviderError(
        f"Unknown provider '{config.provider}'. Supported providers: ica-current, ica-legacy"
    )
