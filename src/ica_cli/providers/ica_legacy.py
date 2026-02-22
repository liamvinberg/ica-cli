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

    def add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        if self.auth_ticket:
            return self._legacy_add_item(list_name, item_name, quantity)
        return self._fallback_add_item(list_name, item_name, quantity)

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
