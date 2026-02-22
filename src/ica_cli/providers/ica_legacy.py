from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from http import cookiejar
from typing import Any
from urllib import error, parse, request
from urllib.parse import parse_qs, urljoin, urlparse

from ica_cli.providers.base import IcaProvider, ProviderError


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class IcaLegacyProvider(IcaProvider):
    name = "ica-legacy"

    def __init__(
        self,
        base_url: str = "https://handla.api.ica.se/api",
        auth_ticket: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        oauth_client_id: str | None = None,
        oauth_client_secret: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_ticket = auth_ticket
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.oauth_client_id = oauth_client_id
        self.oauth_client_secret = oauth_client_secret

        self.digx_base_url = "https://apimgw-pub.ica.se/sverige/digx"
        self.oauth_token_url = "https://ims.icagruppen.se/oauth/v2/token"
        self.oauth_authorize_url = "https://ims.icagruppen.se/oauth/v2/authorize"
        self.login_form_url = (
            "https://ims.icagruppen.se/authn/authenticate/IcaCustomers"
        )
        self.register_url = "https://ims.icagruppen.se/register"

        self.dcr_client_id = os.getenv("ICA_DCR_CLIENT_ID", "ica-app-dcr-registration")
        self.dcr_client_secret = os.getenv(
            "ICA_DCR_CLIENT_SECRET",
            "uxLHTBvZ-Z2fV-SbrHl1E-tz7vB3jQFrwAdSLlbVMMu1rxDdvJU0s8KGu9d1wLS4",
        )
        self.app_redirect_uri = os.getenv(
            "ICA_OAUTH_APP_REDIRECT_URI", "icacurity://app"
        )
        self.auth_acr = "urn:se:curity:authentication:html-form:IcaCustomers"

    def _open(self, opener, req: request.Request, timeout: int = 30):
        try:
            return opener.open(req, timeout=timeout)
        except error.HTTPError as http_error:
            return http_error

    def _response_text(self, response, allowed: tuple[int, ...], context: str) -> str:
        status = response.getcode()
        body = response.read().decode("utf-8", errors="replace")
        if status not in allowed:
            raise ProviderError(f"{context}: HTTP {status}: {body}")
        return body

    def _response_json(
        self, response, allowed: tuple[int, ...], context: str
    ) -> dict[str, Any]:
        body = self._response_text(response, allowed, context)
        if not body:
            return {}
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as decode_error:
            raise ProviderError(f"{context}: invalid JSON response") from decode_error
        if isinstance(payload, dict):
            return payload
        raise ProviderError(f"{context}: expected JSON object response")

    def _extract_hidden_value(self, html: str, field_name: str) -> str:
        pattern = rf'name=["\']{re.escape(field_name)}["\']\s+value=["\']([^"\']+)["\']'
        match = re.search(pattern, html)
        if not match:
            raise ProviderError(
                f"Could not extract '{field_name}' from ICA login response"
            )
        return match.group(1)

    def _extract_cookie_value(self, jar: cookiejar.CookieJar, name: str) -> str | None:
        for cookie in jar:
            if cookie.name == name and cookie.value:
                return cookie.value
        return None

    def _generate_pkce(self) -> tuple[str, str]:
        verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        verifier = re.sub(r"[^a-zA-Z0-9]", "", verifier)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("utf-8")).digest()
        ).decode("utf-8")
        challenge = challenge.replace("=", "")
        return challenge, verifier

    def _request_dcr_access_token(self, opener) -> str:
        req = request.Request(
            self.oauth_token_url,
            data=parse.urlencode(
                {
                    "client_id": self.dcr_client_id,
                    "client_secret": self.dcr_client_secret,
                    "grant_type": "client_credentials",
                    "scope": "dcr",
                    "response_type": "token",
                }
            ).encode("utf-8"),
            method="POST",
        )
        payload = self._response_json(
            self._open(opener, req),
            (200, 201),
            "Legacy fallback DCR token request failed",
        )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ProviderError(
                "Legacy fallback DCR token response missing access_token"
            )
        return token

    def _register_dynamic_client(self, opener) -> dict[str, Any]:
        dcr_token = self._request_dcr_access_token(opener)
        req = request.Request(
            self.register_url,
            headers={
                "Authorization": f"Bearer {dcr_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            data=json.dumps({"software_id": "dcr-ica-app-template"}).encode("utf-8"),
            method="POST",
        )
        payload = self._response_json(
            self._open(opener, req),
            (200, 201),
            "Legacy fallback dynamic client registration failed",
        )
        for key in ("client_id", "client_secret", "scope"):
            value = payload.get(key)
            if not isinstance(value, str) or not value:
                raise ProviderError(
                    f"Legacy fallback client registration missing required field '{key}'"
                )
        return payload

    def _init_oauth(
        self, no_redirect_opener, opener, client: dict[str, Any], code_challenge: str
    ) -> str:
        authorize_params = {
            "client_id": client["client_id"],
            "scope": client["scope"],
            "redirect_uri": self.app_redirect_uri,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            "acr": self.auth_acr,
        }
        authorize_url = (
            self.oauth_authorize_url + "?" + parse.urlencode(authorize_params)
        )
        authorize_req = request.Request(authorize_url, method="GET")
        authorize_resp = self._open(no_redirect_opener, authorize_req)

        location = authorize_resp.headers.get("Location")
        if location:
            absolute_location = urljoin(self.oauth_authorize_url, location)
            page_req = request.Request(absolute_location, method="GET")
            page_resp = self._open(opener, page_req)
            self._response_text(
                page_resp, (200, 201), "Legacy fallback OAuth login page fetch failed"
            )
        else:
            absolute_location = authorize_resp.geturl()

        state_values = parse_qs(urlparse(absolute_location).query).get("state", [])
        if not state_values or not state_values[0]:
            raise ProviderError("Legacy fallback OAuth init did not return state")
        return state_values[0]

    def _submit_login(
        self, opener, username: str, password: str, expected_state: str
    ) -> tuple[str, str]:
        req = request.Request(
            self.login_form_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml",
            },
            data=parse.urlencode({"userName": username, "password": password}).encode(
                "utf-8"
            ),
            method="POST",
        )
        resp = self._open(opener, req)
        if resp.getcode() == 400:
            raise ProviderError("Legacy fallback login rejected credentials (HTTP 400)")
        html = self._response_text(resp, (200, 201), "Legacy fallback login failed")

        state = self._extract_hidden_value(html, "state")
        token = self._extract_hidden_value(html, "token")
        if state != expected_state:
            expected_state = state
        return expected_state, token

    def _exchange_login_token_for_code(
        self,
        no_redirect_opener,
        client_id: str,
        state: str,
        token: str,
    ) -> str:
        params = parse.urlencode(
            {
                "client_id": client_id,
                "forceAuthN": "true",
                "acr": self.auth_acr,
            }
        )
        req = request.Request(
            self.oauth_authorize_url + "?" + params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=parse.urlencode({"token": token, "state": state}).encode("utf-8"),
            method="POST",
        )
        resp = self._open(no_redirect_opener, req)
        status = resp.getcode()
        if status not in (302, 303):
            body = resp.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Legacy fallback token->code exchange failed: HTTP {status}: {body}"
            )

        location = resp.headers.get("Location")
        if not location:
            raise ProviderError("Legacy fallback token->code exchange missing redirect")
        callback_url = urljoin(self.oauth_authorize_url, location)
        code_values = parse_qs(urlparse(callback_url).query).get("code", [])
        if not code_values or not code_values[0]:
            raise ProviderError(
                "Legacy fallback token->code exchange did not return code"
            )
        return code_values[0]

    def _exchange_code_for_tokens(
        self,
        opener,
        client: dict[str, Any],
        code: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        req = request.Request(
            self.oauth_token_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=parse.urlencode(
                {
                    "code": code,
                    "client_id": client["client_id"],
                    "client_secret": client["client_secret"],
                    "grant_type": "authorization_code",
                    "scope": client["scope"],
                    "response_type": "token",
                    "code_verifier": code_verifier,
                    "redirect_uri": self.app_redirect_uri,
                }
            ).encode("utf-8"),
            method="POST",
        )
        payload = self._response_json(
            self._open(opener, req),
            (200, 201),
            "Legacy fallback authorization code exchange failed",
        )
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError("Legacy fallback token exchange missing access_token")
        return payload

    def _login_via_current_oauth(self, username: str, password: str) -> dict[str, Any]:
        jar = cookiejar.CookieJar()
        opener = request.build_opener(request.HTTPCookieProcessor(jar))
        no_redirect_opener = request.build_opener(
            request.HTTPCookieProcessor(jar),
            _NoRedirect(),
        )

        client = self._register_dynamic_client(opener)
        challenge, verifier = self._generate_pkce()
        state = self._init_oauth(no_redirect_opener, opener, client, challenge)
        state, token = self._submit_login(opener, username, password, state)
        code = self._exchange_login_token_for_code(
            no_redirect_opener,
            client_id=client["client_id"],
            state=state,
            token=token,
        )
        token_payload = self._exchange_code_for_tokens(opener, client, code, verifier)

        access_token = token_payload.get("access_token")
        refresh_token = token_payload.get("refresh_token")
        session_id = self._extract_cookie_value(jar, "thSessionId")

        if isinstance(access_token, str) and access_token:
            self.access_token = access_token
        if isinstance(refresh_token, str) and refresh_token:
            self.refresh_token = refresh_token
        self.oauth_client_id = client["client_id"]
        self.oauth_client_secret = client["client_secret"]

        return {
            "method": "current-oauth-fallback",
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "oauth_client_id": self.oauth_client_id,
            "oauth_client_secret": self.oauth_client_secret,
            "session_id": session_id,
        }

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
        except (error.HTTPError, error.URLError, ProviderError) as legacy_error:
            try:
                fallback = self._login_via_current_oauth(username, password)
                fallback["legacy_error"] = str(legacy_error)
                return fallback
            except ProviderError as fallback_error:
                raise ProviderError(
                    f"Legacy login failed: {legacy_error}. Current OAuth fallback failed: {fallback_error}"
                ) from fallback_error

        if not ticket:
            raise ProviderError("Legacy login did not return AuthenticationTicket")
        self.auth_ticket = ticket
        parsed = json.loads(body) if body else {}
        return {
            "method": "legacy-ticket",
            "auth_ticket": ticket,
            "profile": parsed,
        }

    def _refresh_fallback_access_token(self) -> str:
        if not self.refresh_token:
            raise ProviderError("No refresh token available for legacy fallback")
        if not self.oauth_client_id or not self.oauth_client_secret:
            raise ProviderError(
                "Missing OAuth client credentials for legacy fallback refresh"
            )

        basic = base64.b64encode(
            f"{self.oauth_client_id}:{self.oauth_client_secret}".encode("utf-8")
        ).decode("ascii")
        req = request.Request(
            self.oauth_token_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": f"Basic {basic}",
            },
            data=parse.urlencode(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                }
            ).encode("utf-8"),
            method="POST",
        )
        payload = self._response_json(
            self._open(request.build_opener(), req),
            (200, 201),
            "Legacy fallback refresh token exchange failed",
        )
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ProviderError("Legacy fallback refresh response missing access_token")
        self.access_token = access_token
        new_refresh = payload.get("refresh_token")
        if isinstance(new_refresh, str) and new_refresh:
            self.refresh_token = new_refresh
        return access_token

    def _legacy_list_lists(self) -> list[dict[str, Any]]:
        auth_ticket = self.auth_ticket
        if not auth_ticket:
            raise ProviderError("Not authenticated")
        req = request.Request(
            f"{self.base_url}/user/offlineshoppinglists",
            headers={"AuthenticationTicket": auth_ticket},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"List retrieval failed: HTTP {http_error.code}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"List retrieval failed: {url_error.reason}"
            ) from url_error
        return data

    def _fallback_auth_headers(self) -> dict[str, str]:
        if not self.access_token:
            if self.refresh_token:
                self._refresh_fallback_access_token()
            else:
                raise ProviderError("Not authenticated")
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _fallback_get_lists(self) -> list[dict[str, Any]]:
        req = request.Request(
            f"{self.digx_base_url}/shopping-list/v1/api/list/all",
            headers=self._fallback_auth_headers(),
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            if http_error.code == 401 and self.refresh_token:
                self.access_token = None
                req = request.Request(
                    f"{self.digx_base_url}/shopping-list/v1/api/list/all",
                    headers=self._fallback_auth_headers(),
                    method="GET",
                )
                with request.urlopen(req, timeout=20) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            else:
                raise ProviderError(
                    f"Fallback list retrieval failed: HTTP {http_error.code}"
                ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Fallback list retrieval failed: {url_error.reason}"
            ) from url_error

        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            items = payload.get("items")
            if isinstance(items, list):
                return items
            lists = payload.get("lists")
            if isinstance(lists, list):
                return lists
        raise ProviderError("Unexpected fallback list response format")

    def list_lists(self) -> list[dict[str, Any]]:
        if self.auth_ticket:
            return self._legacy_list_lists()
        return self._fallback_get_lists()

    def _legacy_add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        auth_ticket = self.auth_ticket
        if not auth_ticket:
            raise ProviderError("Not authenticated")
        lists = self._legacy_list_lists()
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
        req = request.Request(
            f"{self.base_url}/user/offlineshoppinglists/{parse.quote(str(offline_id))}/sync",
            headers={
                "AuthenticationTicket": auth_ticket,
                "Content-Type": "application/json",
            },
            data=json.dumps(payload).encode("utf-8"),
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

    def _fallback_add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        lists = self._fallback_get_lists()
        selected = next((item for item in lists if item.get("name") == list_name), None)
        if not selected:
            raise ProviderError(
                f"List '{list_name}' not found in fallback API response. Existing lists: "
                + ", ".join(item.get("name", "?") for item in lists)
            )

        list_id = selected.get("id")
        if not list_id:
            raise ProviderError("Selected list has no id")

        body_payload: dict[str, Any] = {"text": item_name, "isStriked": False}
        if quantity:
            body_payload["quantity"] = quantity

        req = request.Request(
            f"{self.digx_base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}/row",
            headers=self._fallback_auth_headers(),
            data=json.dumps(body_payload).encode("utf-8"),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                created = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            if http_error.code == 401 and self.refresh_token:
                self.access_token = None
                req = request.Request(
                    f"{self.digx_base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}/row",
                    headers=self._fallback_auth_headers(),
                    data=json.dumps(body_payload).encode("utf-8"),
                    method="POST",
                )
                with request.urlopen(req, timeout=20) as response:
                    created = json.loads(response.read().decode("utf-8"))
            else:
                raise ProviderError(
                    f"Fallback add item failed: HTTP {http_error.code}"
                ) from http_error

        return {
            "list": list_name,
            "item": item_name,
            "result": created,
        }

    def _legacy_add_items(
        self,
        list_name: str,
        item_names: list[str],
        quantity: str | None = None,
    ) -> dict[str, Any]:
        auth_ticket = self.auth_ticket
        if not auth_ticket:
            raise ProviderError("Not authenticated")

        lists = self._legacy_list_lists()
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

        created_rows = [
            {
                "ProductName": item_name,
                "SourceId": -1,
                "ArticleGroupId": 12,
                "Quantity": float(quantity) if quantity else 1.0,
                "IsStrikedOver": False,
            }
            for item_name in item_names
        ]
        payload = {"CreatedRows": created_rows}
        req = request.Request(
            f"{self.base_url}/user/offlineshoppinglists/{parse.quote(str(offline_id))}/sync",
            headers={
                "AuthenticationTicket": auth_ticket,
                "Content-Type": "application/json",
            },
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                synced = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Legacy add items failed: HTTP {http_error.code}"
            ) from http_error

        added = [{"item": item_name, "result": synced} for item_name in item_names]
        return {
            "list": list_name,
            "count": len(added),
            "added": added,
            "errors": [],
        }

    def _fallback_add_items(
        self,
        list_name: str,
        item_names: list[str],
        quantity: str | None = None,
    ) -> dict[str, Any]:
        lists = self._fallback_get_lists()
        selected = next((item for item in lists if item.get("name") == list_name), None)
        if not selected:
            raise ProviderError(
                f"List '{list_name}' not found in fallback API response. Existing lists: "
                + ", ".join(item.get("name", "?") for item in lists)
            )

        list_id = selected.get("id")
        if not list_id:
            raise ProviderError("Selected list has no id")

        added: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        for item_name in item_names:
            body_payload: dict[str, Any] = {"text": item_name, "isStriked": False}
            if quantity:
                body_payload["quantity"] = quantity

            req = request.Request(
                f"{self.digx_base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}/row",
                headers=self._fallback_auth_headers(),
                data=json.dumps(body_payload).encode("utf-8"),
                method="POST",
            )
            try:
                with request.urlopen(req, timeout=20) as response:
                    created = json.loads(response.read().decode("utf-8"))
            except error.HTTPError as http_error:
                if http_error.code == 401 and self.refresh_token:
                    self.access_token = None
                    req = request.Request(
                        f"{self.digx_base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}/row",
                        headers=self._fallback_auth_headers(),
                        data=json.dumps(body_payload).encode("utf-8"),
                        method="POST",
                    )
                    with request.urlopen(req, timeout=20) as response:
                        created = json.loads(response.read().decode("utf-8"))
                else:
                    errors.append(
                        {
                            "item": item_name,
                            "error": f"Fallback add item failed: HTTP {http_error.code}",
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

    def add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        if self.auth_ticket:
            return self._legacy_add_item(list_name, item_name, quantity)
        return self._fallback_add_item(list_name, item_name, quantity)

    def add_items(
        self,
        list_name: str,
        item_names: list[str],
        quantity: str | None = None,
    ) -> dict[str, Any]:
        if self.auth_ticket:
            return self._legacy_add_items(list_name, item_names, quantity)
        return self._fallback_add_items(list_name, item_names, quantity)

    @staticmethod
    def _row_id(row: dict[str, Any]) -> str | None:
        for key in ("OfflineId", "id", "rowId", "RowId"):
            value = row.get(key)
            if isinstance(value, int):
                return str(value)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _row_name(row: dict[str, Any]) -> str:
        value = row.get("ProductName") or row.get("text") or row.get("name")
        if isinstance(value, str) and value:
            return value
        return "<unnamed item>"

    @staticmethod
    def _row_is_striked(row: dict[str, Any]) -> bool:
        value = row.get("IsStrikedOver")
        if isinstance(value, bool):
            return value
        value = row.get("isStriked")
        if isinstance(value, bool):
            return value
        return False

    def _resolve_list_with_rows(
        self, list_name: str
    ) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        lists = self.list_lists()
        if self.auth_ticket:
            selected = next(
                (item for item in lists if item.get("OfflineName") == list_name),
                None,
            )
            if not selected:
                raise ProviderError(
                    f"List '{list_name}' not found in legacy API response. Existing lists: "
                    + ", ".join(item.get("OfflineName", "?") for item in lists)
                )
            list_id = selected.get("OfflineId")
            if not list_id:
                raise ProviderError("Selected list has no OfflineId")
            rows = selected.get("Rows")
            if not isinstance(rows, list):
                rows = []
            return (
                selected,
                str(list_id),
                [row for row in rows if isinstance(row, dict)],
            )

        selected = next((item for item in lists if item.get("name") == list_name), None)
        if not selected:
            raise ProviderError(
                f"List '{list_name}' not found in fallback API response. Existing lists: "
                + ", ".join(item.get("name", "?") for item in lists)
            )
        list_id = selected.get("id")
        if not list_id:
            raise ProviderError("Selected list has no id")
        rows = selected.get("rows")
        if not isinstance(rows, list):
            rows = selected.get("Rows")
        if not isinstance(rows, list):
            rows = []
        return selected, str(list_id), [row for row in rows if isinstance(row, dict)]

    def _legacy_sync_mutation(
        self, offline_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        auth_ticket = self.auth_ticket
        if not auth_ticket:
            raise ProviderError("Not authenticated")

        req = request.Request(
            f"{self.base_url}/user/offlineshoppinglists/{parse.quote(str(offline_id))}/sync",
            headers={
                "AuthenticationTicket": auth_ticket,
                "Content-Type": "application/json",
            },
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Legacy sync mutation failed: HTTP {http_error.code}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Legacy sync mutation failed: {url_error.reason}"
            ) from url_error

        if not raw:
            return {}
        try:
            payload_data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(payload_data, dict):
            return payload_data
        return {}

    def _fallback_request_json_or_empty(self, req: request.Request) -> Any:
        try:
            with request.urlopen(req, timeout=20) as response:
                raw = response.read().decode("utf-8")
        except error.HTTPError as http_error:
            if http_error.code == 401 and self.refresh_token:
                self.access_token = None
                return None
            body = http_error.read().decode("utf-8", errors="replace")
            raise ProviderError(
                f"Fallback row mutation failed: HTTP {http_error.code}: {body}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Fallback row mutation failed: {url_error.reason}"
            ) from url_error

        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _fallback_delete_row(self, list_id: str, row_id: str) -> None:
        url = (
            f"{self.digx_base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}"
            f"/row/{parse.quote(str(row_id))}"
        )
        req = request.Request(
            url, headers=self._fallback_auth_headers(), method="DELETE"
        )
        payload = self._fallback_request_json_or_empty(req)
        if payload is None:
            req = request.Request(
                url, headers=self._fallback_auth_headers(), method="DELETE"
            )
            payload = self._fallback_request_json_or_empty(req)
        if payload is None:
            raise ProviderError("Fallback delete row failed after retry")

    def _fallback_set_row_striked(
        self, list_id: str, row_id: str, striked: bool
    ) -> Any:
        url = (
            f"{self.digx_base_url}/shopping-list/v1/api/list/{parse.quote(str(list_id))}"
            f"/row/{parse.quote(str(row_id))}"
        )
        body = json.dumps({"isStriked": striked}).encode("utf-8")
        errors_seen: list[str] = []
        for method in ("PUT", "PATCH"):
            req = request.Request(
                url,
                headers=self._fallback_auth_headers(),
                data=body,
                method=method,
            )
            try:
                payload = self._fallback_request_json_or_empty(req)
                if payload is None:
                    req = request.Request(
                        url,
                        headers=self._fallback_auth_headers(),
                        data=body,
                        method=method,
                    )
                    payload = self._fallback_request_json_or_empty(req)
                if payload is None:
                    errors_seen.append(f"{method}: unauthorized after retry")
                    continue
                return payload
            except ProviderError as error:
                errors_seen.append(f"{method}: {error}")

        raise ProviderError(
            "Fallback strike update failed. Tried PUT/PATCH on row endpoint. "
            + " | ".join(errors_seen)
        )

    def remove_item(
        self,
        list_name: str,
        item_name: str,
        all_matches: bool = False,
    ) -> dict[str, Any]:
        selected, list_id, rows = self._resolve_list_with_rows(list_name)
        resolved_list_name = str(
            selected.get("OfflineName") or selected.get("name") or list_name
        )
        needle = item_name.strip().lower()
        matched = [row for row in rows if self._row_name(row).strip().lower() == needle]
        if len(matched) == 0:
            raise ProviderError(
                f"Item '{item_name}' not found in list '{resolved_list_name}'"
            )

        target = matched if all_matches else matched[:1]
        row_ids: list[str] = []
        for row in target:
            row_id = self._row_id(row)
            if not row_id:
                raise ProviderError(
                    f"Matched item '{item_name}' has no row id; cannot delete"
                )
            row_ids.append(row_id)

        if self.auth_ticket:
            self._legacy_sync_mutation(list_id, {"DeletedRows": row_ids})
        else:
            for row_id in row_ids:
                self._fallback_delete_row(list_id=list_id, row_id=row_id)

        return {
            "list": resolved_list_name,
            "item": item_name,
            "removed": len(row_ids),
            "all_matches": all_matches,
            "row_ids": row_ids,
        }

    def set_item_striked(
        self,
        list_name: str,
        item_name: str,
        striked: bool,
        all_matches: bool = False,
    ) -> dict[str, Any]:
        selected, list_id, rows = self._resolve_list_with_rows(list_name)
        resolved_list_name = str(
            selected.get("OfflineName") or selected.get("name") or list_name
        )
        needle = item_name.strip().lower()
        matched = [row for row in rows if self._row_name(row).strip().lower() == needle]
        if len(matched) == 0:
            raise ProviderError(
                f"Item '{item_name}' not found in list '{resolved_list_name}'"
            )

        target = matched if all_matches else matched[:1]
        row_ids: list[str] = []
        for row in target:
            row_id = self._row_id(row)
            if not row_id:
                raise ProviderError(
                    f"Matched item '{item_name}' has no row id; cannot update strike state"
                )
            row_ids.append(row_id)

        if self.auth_ticket:
            changed_rows = [
                {
                    "OfflineId": row_id,
                    "IsStrikedOver": striked,
                    "SourceId": -1,
                }
                for row_id in row_ids
            ]
            self._legacy_sync_mutation(list_id, {"ChangedRows": changed_rows})
        else:
            for row_id in row_ids:
                self._fallback_set_row_striked(
                    list_id=list_id,
                    row_id=row_id,
                    striked=striked,
                )

        return {
            "list": resolved_list_name,
            "item": item_name,
            "striked": striked,
            "updated": len(row_ids),
            "all_matches": all_matches,
            "row_ids": row_ids,
        }

    def clear_striked(self, list_name: str) -> dict[str, Any]:
        selected, list_id, rows = self._resolve_list_with_rows(list_name)
        resolved_list_name = str(
            selected.get("OfflineName") or selected.get("name") or list_name
        )
        row_ids = [
            row_id
            for row in rows
            if self._row_is_striked(row)
            for row_id in [self._row_id(row)]
            if isinstance(row_id, str) and row_id
        ]

        if len(row_ids) == 0:
            return {
                "list": resolved_list_name,
                "removed": 0,
                "row_ids": [],
            }

        if self.auth_ticket:
            self._legacy_sync_mutation(list_id, {"DeletedRows": row_ids})
        else:
            for row_id in row_ids:
                self._fallback_delete_row(list_id=list_id, row_id=row_id)

        return {
            "list": resolved_list_name,
            "removed": len(row_ids),
            "row_ids": row_ids,
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
        auth_ticket = self.auth_ticket
        if not auth_ticket:
            raise ProviderError(
                "Deals search requires legacy AuthenticationTicket. "
                "Run legacy login first: ica config set-provider ica-legacy && ica auth login"
            )

        req = request.Request(
            f"{self.base_url}/offers?Stores={parse.quote(store_id)}",
            headers={"AuthenticationTicket": auth_ticket},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Deals retrieval failed for store {store_id}: HTTP {http_error.code}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Deals retrieval failed for store {store_id}: {url_error.reason}"
            ) from url_error

        offers_raw = payload.get("Offers") if isinstance(payload, dict) else None
        if not isinstance(offers_raw, list):
            return {"offers": [], "store_id": store_id}

        offers = [item for item in offers_raw if isinstance(item, dict)]
        if query:
            needle = query.strip().lower()
            offers = [
                item
                for item in offers
                if needle
                in " ".join(
                    [
                        str(item.get("ProductName", "")),
                        str(item.get("OfferTypeTitle", "")),
                        str(item.get("OfferCondition", "")),
                        str(item.get("SizeOrQuantity", "")),
                    ]
                ).lower()
            ]

        return {
            "store_id": store_id,
            "query": query,
            "offers": offers,
        }

    def search_stores(self, query: str) -> dict[str, Any]:
        phrase = query.strip()
        if not phrase:
            raise ProviderError("Store search query cannot be empty")

        if not self.auth_ticket:
            headers = self._fallback_auth_headers()
            ids: list[str] = []
            search_error: str | None = None

            req = request.Request(
                f"https://apimgw-pub.ica.se/stores/search?Filters&Phrase={parse.quote(phrase)}",
                headers=headers,
                method="GET",
            )
            try:
                with request.urlopen(req, timeout=20) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                if isinstance(payload, dict):
                    raw_ids = payload.get("Stores")
                    if isinstance(raw_ids, list):
                        ids = [
                            str(item).strip() for item in raw_ids if str(item).strip()
                        ]
            except (error.HTTPError, error.URLError) as endpoint_error:
                search_error = str(endpoint_error)

            stores = self._fallback_hydrate_stores_by_ids(ids, headers)
            if len(stores) > 0:
                return {
                    "query": phrase,
                    "source": "legacy-oauth-store-search",
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
                            str(item).strip()
                            for item in raw_favorites
                            if str(item).strip()
                        ]
            except (error.HTTPError, error.URLError):
                favorites_ids = []

            favorites = self._fallback_hydrate_stores_by_ids(favorites_ids, headers)
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
                    "source": "legacy-oauth-favorites-filter",
                    "store_ids": [
                        str(item.get("id"))
                        for item in filtered
                        if isinstance(item.get("id"), (int, str))
                    ],
                    "stores": filtered,
                }

            if search_error:
                raise ProviderError(
                    "Store search with legacy OAuth fallback returned no matches. "
                    f"Store-search endpoint error: {search_error}"
                )

            raise ProviderError(
                "Store search with legacy OAuth fallback returned no matches"
            )

        auth_ticket = self.auth_ticket
        assert auth_ticket is not None

        search_req = request.Request(
            f"{self.base_url}/stores/search?Filters&Phrase={parse.quote(phrase)}",
            headers={"AuthenticationTicket": auth_ticket},
            method="GET",
        )
        try:
            with request.urlopen(search_req, timeout=20) as response:
                search_payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as http_error:
            raise ProviderError(
                f"Store search failed for query '{phrase}': HTTP {http_error.code}"
            ) from http_error
        except error.URLError as url_error:
            raise ProviderError(
                f"Store search failed for query '{phrase}': {url_error.reason}"
            ) from url_error

        ids_raw = (
            search_payload.get("Stores") if isinstance(search_payload, dict) else None
        )
        if not isinstance(ids_raw, list):
            return {"query": phrase, "stores": []}

        stores: list[dict[str, Any]] = []
        for candidate in ids_raw:
            store_id = str(candidate).strip()
            if not store_id:
                continue
            detail_req = request.Request(
                f"{self.base_url}/stores/{parse.quote(store_id)}",
                headers={"AuthenticationTicket": auth_ticket},
                method="GET",
            )
            try:
                with request.urlopen(detail_req, timeout=20) as response:
                    detail_payload = json.loads(response.read().decode("utf-8"))
            except (error.HTTPError, error.URLError):
                continue
            if isinstance(detail_payload, dict):
                stores.append(detail_payload)

        return {
            "query": phrase,
            "store_ids": [str(item).strip() for item in ids_raw if str(item).strip()],
            "stores": stores,
        }

    def get_store(self, store_id: str) -> dict[str, Any]:
        trimmed = store_id.strip()
        if not trimmed:
            raise ProviderError("Store id cannot be empty")

        if not self.auth_ticket:
            req = request.Request(
                f"https://apimgw-pub.ica.se/sverige/digx/mobile/storeservice/v1/stores/{parse.quote(trimmed)}",
                headers=self._fallback_auth_headers(),
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
                raise ProviderError("Unexpected store response format")
            return payload

        auth_ticket = self.auth_ticket
        assert auth_ticket is not None

        req = request.Request(
            f"{self.base_url}/stores/{parse.quote(trimmed)}",
            headers={"AuthenticationTicket": auth_ticket},
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
            raise ProviderError("Unexpected legacy store response format")
        return payload

    def list_favorite_stores(self) -> dict[str, Any]:
        if not self.auth_ticket:
            req = request.Request(
                "https://apimgw-pub.ica.se/sverige/digx/mobile/storeservice/v1/favorites",
                headers=self._fallback_auth_headers(),
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

            stores = self._fallback_hydrate_stores_by_ids(
                ids,
                self._fallback_auth_headers(),
            )
            return {
                "store_ids": ids,
                "stores": stores,
            }

        auth_ticket = self.auth_ticket
        assert auth_ticket is not None

        req = request.Request(
            f"{self.base_url}/user/stores",
            headers={"AuthenticationTicket": auth_ticket},
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
            raw_ids = payload.get("FavoriteStores")
            if isinstance(raw_ids, list):
                ids = [str(item).strip() for item in raw_ids if str(item).strip()]

        stores: list[dict[str, Any]] = []
        for store_id in ids:
            try:
                detail = self.get_store(store_id)
            except ProviderError:
                continue
            stores.append(detail)

        return {
            "store_ids": ids,
            "stores": stores,
        }

    def _fallback_hydrate_stores_by_ids(
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
