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

    def add_items(
        self,
        list_name: str,
        item_names: list[str],
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

        added: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for item_name in item_names:
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
                errors.append(
                    {
                        "item": item_name,
                        "error": "Current API add item failed after retry",
                    }
                )
                continue

            added.append({"item": item_name, "result": created})

        if len(added) == 0 and len(errors) > 0:
            first = errors[0]
            raise ProviderError(
                f"Failed to add items to '{list_name}'. First error for '{first['item']}': {first['error']}"
            )

        return {
            "list": list_name,
            "count": len(added),
            "added": added,
            "errors": errors,
        }

    def _request_json_or_empty(self, req: request.Request) -> Any:
        try:
            with request.urlopen(req, timeout=20) as response:
                raw = response.read().decode("utf-8")
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

        if not raw:
            return {}

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _row_id(row: dict[str, Any]) -> str | None:
        for key in ("id", "rowId", "RowId", "OfflineId"):
            value = row.get(key)
            if isinstance(value, int):
                return str(value)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _row_name(row: dict[str, Any]) -> str:
        value = row.get("text") or row.get("name") or row.get("ProductName")
        if isinstance(value, str) and value:
            return value
        return "<unnamed item>"

    @staticmethod
    def _row_is_striked(row: dict[str, Any]) -> bool:
        value = row.get("isStriked")
        if isinstance(value, bool):
            return value
        value = row.get("IsStrikedOver")
        if isinstance(value, bool):
            return value
        return False

    def _resolve_list_with_rows(
        self, list_name: str
    ) -> tuple[str, str, list[dict[str, Any]]]:
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

        rows = selected.get("rows")
        if not isinstance(rows, list):
            rows = selected.get("Rows")
        if not isinstance(rows, list):
            raise ProviderError(
                "List rows are not present in current API list response; cannot mutate items by name"
            )
        return (
            str(selected.get("name", list_name)),
            str(list_id),
            [row for row in rows if isinstance(row, dict)],
        )

    def _delete_row(self, list_id: str, row_id: str) -> None:
        url = (
            f"{self.base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}"
            f"/row/{parse.quote(str(row_id))}"
        )
        req = request.Request(url, headers=self._auth_headers(), method="DELETE")
        payload = self._request_json_or_empty(req)
        if payload is None:
            req = request.Request(url, headers=self._auth_headers(), method="DELETE")
            payload = self._request_json_or_empty(req)
        if payload is None:
            raise ProviderError("Current API delete row failed after retry")

    def _set_row_striked(self, list_id: str, row_id: str, striked: bool) -> Any:
        url = (
            f"{self.base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}"
            f"/row/{parse.quote(str(row_id))}"
        )
        body = json.dumps({"isStriked": striked}).encode("utf-8")
        methods = ["PUT", "PATCH"]
        errors_seen: list[str] = []

        for method in methods:
            req = request.Request(
                url,
                headers=self._auth_headers(),
                data=body,
                method=method,
            )
            try:
                payload = self._request_json_or_empty(req)
                if payload is None:
                    req = request.Request(
                        url,
                        headers=self._auth_headers(),
                        data=body,
                        method=method,
                    )
                    payload = self._request_json_or_empty(req)
                if payload is None:
                    errors_seen.append(f"{method}: unauthorized after retry")
                    continue
                return payload
            except ProviderError as error:
                errors_seen.append(f"{method}: {error}")

        raise ProviderError(
            "Current API strike update failed. Tried PUT/PATCH on row endpoint. "
            + " | ".join(errors_seen)
        )

    def remove_item(
        self,
        list_name: str,
        item_name: str,
        all_matches: bool = False,
    ) -> dict[str, Any]:
        resolved_name, list_id, rows = self._resolve_list_with_rows(list_name)
        needle = item_name.strip().lower()
        matched = [row for row in rows if self._row_name(row).strip().lower() == needle]
        if len(matched) == 0:
            raise ProviderError(
                f"Item '{item_name}' not found in list '{resolved_name}'"
            )

        target = matched if all_matches else matched[:1]
        deleted_ids: list[str] = []
        for row in target:
            row_id = self._row_id(row)
            if not row_id:
                raise ProviderError(
                    f"Matched item '{item_name}' has no row id; cannot delete"
                )
            self._delete_row(list_id=list_id, row_id=row_id)
            deleted_ids.append(row_id)

        return {
            "list": resolved_name,
            "item": item_name,
            "removed": len(deleted_ids),
            "all_matches": all_matches,
            "row_ids": deleted_ids,
        }

    def set_item_striked(
        self,
        list_name: str,
        item_name: str,
        striked: bool,
        all_matches: bool = False,
    ) -> dict[str, Any]:
        resolved_name, list_id, rows = self._resolve_list_with_rows(list_name)
        needle = item_name.strip().lower()
        matched = [row for row in rows if self._row_name(row).strip().lower() == needle]
        if len(matched) == 0:
            raise ProviderError(
                f"Item '{item_name}' not found in list '{resolved_name}'"
            )

        target = matched if all_matches else matched[:1]
        updated: list[dict[str, Any]] = []
        for row in target:
            row_id = self._row_id(row)
            if not row_id:
                raise ProviderError(
                    f"Matched item '{item_name}' has no row id; cannot update strike state"
                )
            result = self._set_row_striked(
                list_id=list_id,
                row_id=row_id,
                striked=striked,
            )
            updated.append({"row_id": row_id, "result": result})

        return {
            "list": resolved_name,
            "item": item_name,
            "striked": striked,
            "updated": len(updated),
            "all_matches": all_matches,
            "rows": updated,
        }

    def clear_striked(self, list_name: str) -> dict[str, Any]:
        resolved_name, list_id, rows = self._resolve_list_with_rows(list_name)
        targets = [row for row in rows if self._row_is_striked(row)]
        deleted_ids: list[str] = []
        for row in targets:
            row_id = self._row_id(row)
            if not row_id:
                continue
            self._delete_row(list_id=list_id, row_id=row_id)
            deleted_ids.append(row_id)

        return {
            "list": resolved_name,
            "removed": len(deleted_ids),
            "row_ids": deleted_ids,
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

    def search_deals(
        self,
        store_id: str,
        query: str | None = None,
    ) -> dict[str, Any]:
        raise ProviderError(
            "Deals endpoint is not mapped for ica-current yet. "
            "Use provider ica-legacy for offers: ica config set-provider ica-legacy"
        )

    def search_stores(self, query: str) -> dict[str, Any]:
        phrase = query.strip()
        if not phrase:
            raise ProviderError("Store search query cannot be empty")

        token = self.refresh_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        ids: list[str] = []
        search_error: str | None = None

        search_req = request.Request(
            f"https://apimgw-pub.ica.se/stores/search?Filters&Phrase={parse.quote(phrase)}",
            headers=headers,
            method="GET",
        )
        try:
            with request.urlopen(search_req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if isinstance(payload, dict):
                raw_ids = payload.get("Stores")
                if isinstance(raw_ids, list):
                    ids = [str(item).strip() for item in raw_ids if str(item).strip()]
        except (error.HTTPError, error.URLError) as endpoint_error:
            search_error = str(endpoint_error)

        stores = self._hydrate_stores_by_ids(ids, headers)
        if len(stores) > 0:
            return {
                "query": phrase,
                "source": "current-store-search",
                "store_ids": ids,
                "stores": stores,
            }

        favorites_ids: list[str] = []
        favorites_req = request.Request(
            "https://apimgw-pub.ica.se/sverige/digx/mobile/storeservice/v1/favorites",
            headers=headers,
            method="GET",
        )
        try:
            with request.urlopen(favorites_req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if isinstance(payload, dict):
                raw_favorites = payload.get("favoriteStores")
                if isinstance(raw_favorites, list):
                    favorites_ids = [
                        str(item).strip() for item in raw_favorites if str(item).strip()
                    ]
        except (error.HTTPError, error.URLError):
            favorites_ids = []

        favorites = self._hydrate_stores_by_ids(favorites_ids, headers)
        needle = phrase.lower()
        filtered = [
            store
            for store in favorites
            if needle
            in " ".join(
                [
                    str(store.get("marketingName", "")),
                    str((store.get("address") or {}).get("city", ""))
                    if isinstance(store.get("address"), dict)
                    else "",
                    str((store.get("address") or {}).get("street", ""))
                    if isinstance(store.get("address"), dict)
                    else "",
                ]
            ).lower()
        ]
        if len(filtered) > 0:
            return {
                "query": phrase,
                "source": "current-favorites-filter",
                "store_ids": [
                    str(item.get("id"))
                    for item in filtered
                    if isinstance(item.get("id"), (int, str))
                ],
                "stores": filtered,
            }

        if search_error:
            raise ProviderError(
                "Current provider store discovery could not find matches. "
                f"Current store-search endpoint error: {search_error}"
            )

        raise ProviderError("Current provider store discovery returned no matches")

    def _hydrate_stores_by_ids(
        self,
        store_ids: list[str],
        headers: dict[str, str],
    ) -> list[dict[str, Any]]:
        stores: list[dict[str, Any]] = []
        for store_id in store_ids:
            req = request.Request(
                f"https://apimgw-pub.ica.se/sverige/digx/mobile/storeservice/v1/stores/{parse.quote(store_id)}",
                headers=headers,
                method="GET",
            )
            try:
                with request.urlopen(req, timeout=20) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except (error.HTTPError, error.URLError):
                continue
            if isinstance(payload, dict):
                stores.append(payload)
        return stores

    def get_store(self, store_id: str) -> dict[str, Any]:
        trimmed = store_id.strip()
        if not trimmed:
            raise ProviderError("Store id cannot be empty")

        token = self.refresh_access_token()
        req = request.Request(
            f"https://apimgw-pub.ica.se/sverige/digx/mobile/storeservice/v1/stores/{parse.quote(trimmed)}",
            headers={
                "Authorization": f"Bearer {token}",
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
                f"Store fetch failed for id '{trimmed}': HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Store fetch failed for id '{trimmed}': {url_error.reason}"
            ) from url_error

        if not isinstance(payload, dict):
            raise ProviderError("Unexpected current store response format")
        return payload

    def list_favorite_stores(self) -> dict[str, Any]:
        token = self.refresh_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        req = request.Request(
            "https://apimgw-pub.ica.se/sverige/digx/mobile/storeservice/v1/favorites",
            headers=headers,
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Favorite stores fetch failed: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Favorite stores fetch failed: {url_error.reason}"
            ) from url_error

        ids: list[str] = []
        if isinstance(payload, dict):
            raw_ids = payload.get("favoriteStores")
            if isinstance(raw_ids, list):
                ids = [str(item).strip() for item in raw_ids if str(item).strip()]

        stores = self._hydrate_stores_by_ids(ids, headers)
        return {
            "store_ids": ids,
            "stores": stores,
        }
