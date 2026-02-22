from __future__ import annotations

import base64
import json
from typing import Any
from urllib import error, parse, request

from ica_cli.providers.base import IcaProvider, ProviderError


class IcaLegacyProvider(IcaProvider):
    name = "ica-legacy"

    def __init__(
        self,
        base_url: str = "https://handla.api.ica.se/api",
        auth_ticket: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_ticket: str | None = auth_ticket

    def login(self, username: str, password: str) -> dict[str, Any]:
        basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode(
            "ascii"
        )
        req = request.Request(
            f"{self.base_url}/login",
            headers={"Authorization": f"Basic {basic}"},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                ticket = response.headers.get("AuthenticationTicket")
                body = response.read().decode("utf-8")
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Legacy login failed: HTTP {http_error.code}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Legacy login failed: {url_error.reason}"
            ) from url_error

        if not ticket:
            raise ProviderError("Legacy login did not return AuthenticationTicket")
        self.auth_ticket = ticket
        parsed = json.loads(body) if body else {}
        return {
            "auth_ticket": ticket,
            "profile": parsed,
        }

    def list_lists(self) -> list[dict[str, Any]]:
        if not self.auth_ticket:
            raise ProviderError("Not authenticated")
        req = request.Request(
            f"{self.base_url}/user/offlineshoppinglists",
            headers={"AuthenticationTicket": self.auth_ticket},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"List retrieval failed: HTTP {http_error.code}"
            ) from http_error
        return data

    def add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        if not self.auth_ticket:
            raise ProviderError("Not authenticated")

        lists = self.list_lists()
        selected = next(
            (item for item in lists if item.get("OfflineName") == list_name), None
        )
        if not selected:
            raise ProviderError(
                f"List '{list_name}' not found in legacy API response. Existing lists: "
                + ", ".join(item.get("OfflineName", "?") for item in lists)
            )

        offline_id = selected.get("OfflineId")
        if not offline_id:
            raise ProviderError("Selected list has no OfflineId")

        payload = {
            "CreatedRows": [
                {
                    "ProductName": item_name,
                    "SourceId": -1,
                    "ArticleGroupId": 12,
                    "Quantity": float(quantity) if quantity else 1.0,
                    "IsStrikedOver": False,
                }
            ]
        }
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/user/offlineshoppinglists/{parse.quote(str(offline_id))}/sync",
            headers={
                "AuthenticationTicket": self.auth_ticket,
                "Content-Type": "application/json",
            },
            data=body,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                synced = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Legacy add item failed: HTTP {http_error.code}"
            ) from http_error

        return {
            "list": list_name,
            "item": item_name,
            "result": synced,
        }

    def search_products(self, store_id: str, query: str) -> dict[str, Any]:
        url = (
            f"https://handlaprivatkund.ica.se/stores/{parse.quote(store_id)}/api/v5/products/search"
            f"?term={parse.quote(query)}&limit=30&offset=0"
        )
        req = request.Request(url, method="GET")
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Product search failed for store {store_id}: HTTP {http_error.code}"
            ) from http_error
        return payload
