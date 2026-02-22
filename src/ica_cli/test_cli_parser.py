import unittest

from ica_cli.cli import (
    _extract_raw_payload,
    _format_human,
    _parse_callback_url,
    _resolve_list_add_items,
    build_parser,
)


class CliParserTests(unittest.TestCase):
    def test_parser_accepts_list_add(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "add", "mjolk", "--list-name", "Min lista"])
        self.assertEqual(args.command, "list")
        self.assertEqual(args.list_cmd, "add")
        self.assertEqual(args.items, ["mjolk"])
        self.assertEqual(args.list_name, "Min lista")

    def test_parser_accepts_config_set_store_ids(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["config", "set-store-ids", "1001", "1002", "1003"])
        self.assertEqual(args.command, "config")
        self.assertEqual(args.config_cmd, "set-store-ids")
        self.assertEqual(args.store_ids, ["1001", "1002", "1003"])

    def test_parser_accepts_list_add_multiple_styles(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "list",
                "add",
                "mjolk",
                "brod",
                "--item",
                "smor",
                "--items",
                "aggg, ost",
                "--dedupe",
            ]
        )
        self.assertEqual(args.items, ["mjolk", "brod"])
        self.assertEqual(args.extra_items, ["smor"])
        self.assertEqual(args.items_csv, ["aggg, ost"])
        self.assertTrue(args.dedupe)

    def test_resolve_list_add_items_dedupes_case_insensitive(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "list",
                "add",
                "mjolk",
                "MJOLK",
                "--item",
                "brod",
                "--items",
                "brod, ost",
                "--dedupe",
            ]
        )
        self.assertEqual(_resolve_list_add_items(args), ["mjolk", "brod", "ost"])

    def test_parser_accepts_list_items(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "items", "--list-name", "Min lista"])
        self.assertEqual(args.command, "list")
        self.assertEqual(args.list_cmd, "items")
        self.assertEqual(args.list_name, "Min lista")

    def test_parser_accepts_list_alias_for_list_name(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "add", "mjolk", "--list", "Handla"])
        self.assertEqual(args.list_name, "Handla")

    def test_parser_accepts_auth_session_import(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["auth", "session", "import", "--session-id", "abc123"]
        )
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "session")
        self.assertEqual(args.auth_session_cmd, "import")
        self.assertEqual(args.session_id, "abc123")

    def test_parser_accepts_products_search(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["products", "search", "ost", "--store-id", "1004394"])
        self.assertEqual(args.command, "products")
        self.assertEqual(args.products_cmd, "search")
        self.assertEqual(args.query, "ost")
        self.assertEqual(args.store_id, "1004394")

    def test_parser_accepts_deals_search(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["deals", "search", "kaffe", "--store-id", "1004394"])
        self.assertEqual(args.command, "deals")
        self.assertEqual(args.deals_cmd, "search")
        self.assertEqual(args.query, "kaffe")
        self.assertEqual(args.store_id, "1004394")

    def test_parser_accepts_deals_search_without_query(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["deals", "search", "--store-id", "1004394"])
        self.assertEqual(args.command, "deals")
        self.assertEqual(args.deals_cmd, "search")
        self.assertIsNone(args.query)
        self.assertEqual(args.store_id, "1004394")

    def test_parser_accepts_stores_search(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "search", "stockholm"])
        self.assertEqual(args.command, "stores")
        self.assertEqual(args.stores_cmd, "search")
        self.assertEqual(args.query, "stockholm")

    def test_parser_accepts_stores_get(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "get", "1004394"])
        self.assertEqual(args.command, "stores")
        self.assertEqual(args.stores_cmd, "get")
        self.assertEqual(args.store_id, "1004394")

    def test_parser_accepts_stores_favorites(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "favorites"])
        self.assertEqual(args.command, "stores")
        self.assertEqual(args.stores_cmd, "favorites")

    def test_parser_accepts_auth_login_current(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "auth",
                "login-current",
                "--session-id",
                "sess123",
                "--show-authorize-url",
                "--non-interactive",
            ]
        )
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "login-current")
        self.assertEqual(args.session_id, "sess123")
        self.assertTrue(args.show_authorize_url)
        self.assertTrue(args.non_interactive)

    def test_parser_accepts_auth_current_complete(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "auth",
                "current-complete",
                "--callback-url",
                "https://www.ica.se/logga-in/sso/callback/?code=abc&state=def",
            ]
        )
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "current-complete")
        self.assertEqual(
            args.callback_url,
            "https://www.ica.se/logga-in/sso/callback/?code=abc&state=def",
        )

    def test_parser_accepts_auth_current_begin(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["auth", "current-begin"])
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "current-begin")

    def test_parser_accepts_auth_token_import(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "auth",
                "token",
                "import",
                "--access-token",
                "abc",
                "--refresh-token",
                "def",
            ]
        )
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "token")
        self.assertEqual(args.auth_token_cmd, "import")
        self.assertEqual(args.access_token, "abc")
        self.assertEqual(args.refresh_token, "def")

    def test_parser_accepts_auth_login_agentic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "auth",
                "login",
                "--agentic",
                "--callback-url",
                "https://www.ica.se/logga-in/sso/callback/?code=abc&state=def",
                "--allow-state-mismatch",
            ]
        )
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "login")
        self.assertTrue(args.agentic)
        self.assertTrue(args.allow_state_mismatch)
        self.assertEqual(
            args.callback_url,
            "https://www.ica.se/logga-in/sso/callback/?code=abc&state=def",
        )

    def test_parser_accepts_auth_login_user_pass(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["auth", "login", "--user", "199001011234", "--pass", "secret"]
        )
        self.assertEqual(args.command, "auth")
        self.assertEqual(args.auth_cmd, "login")
        self.assertEqual(args.username, "199001011234")
        self.assertEqual(args.password, "secret")

    def test_parse_callback_url(self) -> None:
        code, state = _parse_callback_url(
            "https://www.ica.se/logga-in/sso/callback/?iss=x&code=abc123&state=st-1"
        )
        self.assertEqual(code, "abc123")
        self.assertEqual(state, "st-1")

    def test_parse_callback_url_with_shell_escapes(self) -> None:
        code, state = _parse_callback_url(
            "https://www.ica.se/logga-in/sso/callback/\\?iss\\=x\\&code\\=abc123\\&state\\=st-1"
        )
        self.assertEqual(code, "abc123")
        self.assertEqual(state, "st-1")

    def test_parser_accepts_raw_output_flag(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--raw", "config", "show"])
        self.assertTrue(args.raw)
        self.assertFalse(args.json)

    def test_extract_raw_payload_prefers_result_field(self) -> None:
        payload = {"list": "Min lista", "item": "mjolk", "result": {"id": "r1"}}
        raw = _extract_raw_payload(payload)
        self.assertEqual(raw, {"id": "r1"})

    def test_extract_raw_payload_prefers_offers_field(self) -> None:
        payload = {"offers": [{"OfferId": "1"}], "store_id": "1004394"}
        raw = _extract_raw_payload(payload)
        self.assertEqual(raw, [{"OfferId": "1"}])

    def test_human_format_list_add(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "add", "mjolk", "--list-name", "Min lista"])
        payload = {"list": "Min lista", "item": "mjolk", "result": {"id": "r1"}}
        text = _format_human(payload, args)
        self.assertEqual(text, 'Added "mjolk" to "Min lista".')

    def test_human_format_list_add_bulk(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["list", "add", "mjolk", "brod", "--list-name", "Min lista"]
        )
        payload = {
            "list": "Min lista",
            "count": 2,
            "added": [
                {"item": "mjolk", "result": {"id": "r1"}},
                {"item": "brod", "result": {"id": "r2"}},
            ],
            "errors": [],
        }
        text = _format_human(payload, args)
        self.assertIn('Added 2 items to "Min lista"', text)
        self.assertIn('"mjolk"', text)
        self.assertIn('"brod"', text)

    def test_human_format_list_ls(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "ls"])
        payload = {
            "provider": "ica-current",
            "lists": [
                {"name": "Min lista", "rows": [{}, {}]},
                {"OfflineName": "Helg", "Rows": [{}]},
            ],
        }
        text = _format_human(payload, args)
        self.assertIn("Shopping lists (2):", text)
        self.assertIn("- Min lista (2 items)", text)
        self.assertIn("- Helg (1 items)", text)

    def test_human_format_list_items(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "items", "--list-name", "Min lista"])
        payload = {
            "provider": "ica-current",
            "list": "Min lista",
            "items": [
                {"text": "mjolk", "isStriked": False},
                {"text": "brod", "isStriked": True},
            ],
            "count": 2,
        }
        text = _format_human(payload, args)
        self.assertIn('Items in "Min lista" (2):', text)
        self.assertIn("- [ ] mjolk", text)
        self.assertIn("- [x] brod", text)

    def test_human_format_deals(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["deals", "search", "kaffe", "--store-id", "1004394"])
        payload = {
            "provider": "ica-legacy",
            "store_id": "1004394",
            "query": "kaffe",
            "result": {
                "offers": [
                    {"ProductName": "Bryggkaffe", "OfferCondition": "2 for 59 kr"},
                    {"ProductName": "Espresso", "OfferCondition": "20% cheaper"},
                ]
            },
        }
        text = _format_human(payload, args)
        self.assertIn('Deals for "kaffe" (2):', text)
        self.assertIn("- Bryggkaffe (2 for 59 kr)", text)
        self.assertIn("- Espresso (20% cheaper)", text)

    def test_human_format_stores(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "search", "stockholm"])
        payload = {
            "provider": "ica-legacy",
            "query": "stockholm",
            "result": {
                "stores": [
                    {
                        "Id": 658,
                        "MarketingName": "ICA Supermarket Kupolen",
                        "Address": {"City": "BORLANGE"},
                    },
                    {
                        "Id": 603,
                        "MarketingName": "ICA Nara Gagnefhallen",
                        "Address": {"City": "GAGNEF"},
                    },
                ]
            },
        }
        text = _format_human(payload, args)
        self.assertIn('Stores for "stockholm" (2):', text)
        self.assertIn("- ICA Supermarket Kupolen (id: 658, city: BORLANGE)", text)
        self.assertIn("- ICA Nara Gagnefhallen (id: 603, city: GAGNEF)", text)

    def test_human_format_stores_current_shape(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "search", "stockholm"])
        payload = {
            "provider": "ica-current",
            "query": "stockholm",
            "result": {
                "stores": [
                    {
                        "id": 1004394,
                        "marketingName": "ICA Kvantum Kungens Kurva",
                        "address": {"city": "NORSBORG"},
                    }
                ]
            },
        }
        text = _format_human(payload, args)
        self.assertIn('Stores for "stockholm" (1):', text)
        self.assertIn(
            "- ICA Kvantum Kungens Kurva (id: 1004394, city: NORSBORG)",
            text,
        )

    def test_human_format_stores_favorites(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "favorites"])
        payload = {
            "provider": "ica-current",
            "stores_cmd": "favorites",
            "result": {
                "stores": [
                    {
                        "id": 1004394,
                        "marketingName": "ICA Kvantum Kungens Kurva",
                        "address": {"city": "NORSBORG"},
                    }
                ]
            },
        }
        text = _format_human(payload, args)
        self.assertIn("Favorite stores (1):", text)
        self.assertIn(
            "- ICA Kvantum Kungens Kurva (id: 1004394, city: NORSBORG)",
            text,
        )

    def test_human_format_stores_get(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["stores", "get", "1004394"])
        payload = {
            "provider": "ica-current",
            "stores_cmd": "get",
            "store_id": "1004394",
            "result": {
                "stores": [
                    {
                        "id": 1004394,
                        "marketingName": "ICA Kvantum Kungens Kurva",
                        "address": {"city": "NORSBORG"},
                    }
                ]
            },
        }
        text = _format_human(payload, args)
        self.assertIn("Store details:", text)
        self.assertIn(
            "- ICA Kvantum Kungens Kurva (id: 1004394, city: NORSBORG)",
            text,
        )


if __name__ == "__main__":
    unittest.main()
