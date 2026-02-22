from __future__ import annotations

import base64
import json
import os
from http import cookiejar
from typing import Any
from urllib import error, parse, request

from ica_cli.providers.base import IcaProvider, ProviderError


class IcaCurrentProvider(IcaProvider):
    name = "ica-current"

    def __init__(
        self,
        session_id: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.access_token = access_token
        self.refresh_token = refresh_token

        self.base_url = "https://apimgw-pub.ica.se/sverige/digx"
        self.catalog_url = "https://handlaprivatkund.ica.se"
        self.token_url = "https://ims.icagruppen.se/oauth/v2/token"

        self.oauth_client_id = os.getenv("ICA_OAUTH_CLIENT_ID", "ica.se")
        self.oauth_client_secret = os.getenv("ICA_OAUTH_CLIENT_SECRET")
        self.oauth_redirect_uri = os.getenv(
            "ICA_OAUTH_REDIRECT_URI", "https://www.ica.se/logga-in/sso/callback"
        )

    def login(self, username: str, password: str) -> dict[str, Any]:
        raise ProviderError(
            "Current ICA API does not support username/password login in this CLI. "
            "Use auth login interactive callback flow, auth session import, or auth token import."
        )

    def bootstrap_session_from_callback(self, callback_url: str) -> str:
        jar = cookiejar.CookieJar()
        opener = request.build_opener(request.HTTPCookieProcessor(jar))
        req = request.Request(
            callback_url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/126.0.0.0 Safari/537.36"
                ),
                "Accept": (
                    "text/html,application/xhtml+xml,application/xml;q=0.9,"
                    "image/avif,image/webp,*/*;q=0.8"
                ),
            },
            method="GET",
        )
        try:
            with opener.open(req, timeout=25) as response:
                response.read()
        except error.HTTPError as http_error:
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"ICA callback exchange failed: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"ICA callback exchange failed: {url_error.reason}"
            ) from url_error

        for cookie in jar:
            if cookie.name == "thSessionId" and cookie.value:
                self.session_id = cookie.value
                return cookie.value

        raise ProviderError(
            "ICA callback did not produce a thSessionId cookie. "
            "Complete login in browser and use auth session import as fallback."
        )

    def _session_exchange(self) -> str:
        if not self.session_id:
            raise ProviderError("No thSessionId available")

        req = request.Request(
            "https://www.ica.se/api/user/information",
            headers={
                "Cookie": f"thSessionId={self.session_id}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Could not exchange session for access token: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Could not exchange session for access token: {url_error.reason}"
            ) from url_error

        access_token = payload.get("accessToken")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError(
                "No accessToken found in /api/user/information response"
            )
        return access_token

    def exchange_authorization_code(
        self,
        code: str,
        code_verifier: str,
        state: str | None = None,
    ) -> dict[str, Any]:
        form = {
            "grant_type": "authorization_code",
            "client_id": self.oauth_client_id,
            "code": code,
            "redirect_uri": self.oauth_redirect_uri,
            "code_verifier": code_verifier,
        }
        if state:
            form["state"] = state

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if self.oauth_client_secret:
            basic = base64.b64encode(
                f"{self.oauth_client_id}:{self.oauth_client_secret}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {basic}"

        req = request.Request(
            self.token_url,
            headers=headers,
            data=parse.urlencode(form).encode("utf-8"),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Authorization code exchange failed: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Authorization code exchange failed: {url_error.reason}"
            ) from url_error

        return payload

    def _refresh_token_exchange(self) -> str:
        if not self.refresh_token:
            raise ProviderError("No refresh token available")

        form = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.oauth_client_id,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if self.oauth_client_secret:
            basic = base64.b64encode(
                f"{self.oauth_client_id}:{self.oauth_client_secret}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {basic}"

        req = request.Request(
            self.token_url,
            headers=headers,
            data=parse.urlencode(form).encode("utf-8"),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Refresh token exchange failed: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Refresh token exchange failed: {url_error.reason}"
            ) from url_error

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError("Refresh response did not include access_token")

        new_refresh = payload.get("refresh_token")
        if isinstance(new_refresh, str) and new_refresh:
            self.refresh_token = new_refresh

        return access_token

    def refresh_access_token(self) -> str:
        if self.access_token:
            return self.access_token

        if self.session_id:
            self.access_token = self._session_exchange()
            return self.access_token

        if self.refresh_token:
            self.access_token = self._refresh_token_exchange()
            return self.access_token

        raise ProviderError(
            "No ICA current auth material found. Provide ICA_CURRENT_ACCESS_TOKEN, "
            "ICA_CURRENT_REFRESH_TOKEN, ICA_CURRENT_SESSION_ID, or run auth login flow."
        )

    def _auth_headers(self) -> dict[str, str]:
        token = self.refresh_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request_json(self, req: request.Request) -> Any:
        try:
            with request.urlopen(req, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            if http_error.code == 401 and (self.session_id or self.refresh_token):
                self.access_token = None
                return None
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Current API request failed: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Current API request failed: {url_error.reason}"
            ) from url_error

    def list_lists(self) -> list[dict[str, Any]]:
        req = request.Request(
            f"{self.base_url}/shopping-list/v1/api/list/all",
            headers=self._auth_headers(),
            method="GET",
        )
        payload = self._request_json(req)
        if payload is None:
            req = request.Request(
                f"{self.base_url}/shopping-list/v1/api/list/all",
                headers=self._auth_headers(),
                method="GET",
            )
            payload = self._request_json(req)
        if payload is None:
            raise ProviderError("Current API list retrieval failed after retry")

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            if "items" in payload and isinstance(payload.get("items"), list):
                return payload["items"]
            lists = payload.get("lists")
            if isinstance(lists, list):
                return lists
        raise ProviderError("Unexpected current API list response format")

    def add_item(
        self,
        list_name: str,
        item_name: str,
        quantity: str | None = None,
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
        created = self._request_json(req)
        if created is None:
            req = request.Request(
                f"{self.base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}/row",
                headers=self._auth_headers(),
                data=json.dumps(body_payload).encode("utf-8"),
                method="POST",
            )
            created = self._request_json(req)
        if created is None:
            raise ProviderError("Current API add item failed after retry")

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
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Product search failed for store {store_id}: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Product search failed for store {store_id}: {url_error.reason}"
            ) from url_error
        return payload
