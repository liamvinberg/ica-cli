import unittest

from ica_cli.cli import _parse_callback_url, build_parser


class CliParserTests(unittest.TestCase):
    def test_parser_accepts_list_add(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list", "add", "mjolk", "--list-name", "Min lista"])
        self.assertEqual(args.command, "list")
        self.assertEqual(args.list_cmd, "add")
        self.assertEqual(args.item, "mjolk")
        self.assertEqual(args.list_name, "Min lista")

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


if __name__ == "__main__":
    unittest.main()
