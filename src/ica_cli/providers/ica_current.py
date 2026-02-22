from __future__ import annotations

import json
from typing import Any
from urllib import error, parse, request

from ica_cli.providers.base import IcaProvider, ProviderError


class IcaCurrentProvider(IcaProvider):
    name = "ica-current"

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id
        self.access_token: str | None = None
        self.base_url = "https://apimgw-pub.ica.se/sverige/digx"
        self.catalog_url = "https://handlaprivatkund.ica.se"

    def login(self, username: str, password: str) -> dict[str, Any]:
        raise ProviderError(
            "Current ICA API requires authenticated session cookie flow. "
            "Use 'ica auth session import --session-id <thSessionId>' to continue."
        )

    def refresh_access_token(self) -> str:
        if not self.session_id:
            raise ProviderError(
                "No thSessionId available. Import one with 'ica auth session import'."
            )

        req = request.Request(
            "https://www.ica.se/api/user/information",
            headers={"Cookie": f"thSessionId={self.session_id}"},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Could not exchange session for access token: HTTP {http_error.code}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Could not exchange session for access token: {url_error.reason}"
            ) from url_error

        access_token = payload.get("accessToken")
        if not access_token:
            raise ProviderError(
                "No accessToken found in /api/user/information response"
            )
        self.access_token = access_token
        return access_token

    def _auth_headers(self) -> dict[str, str]:
        token = self.access_token or self.refresh_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def list_lists(self) -> list[dict[str, Any]]:
        req = request.Request(
            f"{self.base_url}/shopping-list/v1/api/list/all",
            headers=self._auth_headers(),
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Current API list retrieval failed: HTTP {http_error.code}"
            ) from http_error

        if isinstance(payload, list):
            return payload
        return payload.get("lists", [])

    def add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        lists = self.list_lists()
        selected = next((item for item in lists if item.get("name") == list_name), None)
        if not selected:
            raise ProviderError(
                f"List '{list_name}' not found in current API response. Existing lists: "
                + ", ".join(item.get("name", "?") for item in lists)
            )

        list_id = selected.get("id")
        if not list_id:
            raise ProviderError("Selected list has no id")

        body_payload: dict[str, Any] = {
            "text": item_name,
            "isStriked": False,
        }
        if quantity:
            body_payload["quantity"] = quantity

        req = request.Request(
            f"{self.base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}/row",
            headers=self._auth_headers(),
            data=json.dumps(body_payload).encode("utf-8"),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                created = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Current API add item failed: HTTP {http_error.code}"
            ) from http_error

        return {
            "list": list_name,
            "item": item_name,
            "result": created,
        }

    def search_products(self, store_id: str, query: str) -> dict[str, Any]:
        url = (
            f"{self.catalog_url}/stores/{parse.quote(store_id)}/api/v5/products/search"
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
