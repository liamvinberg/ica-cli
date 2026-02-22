import unittest

from ica_cli.cli import build_parser


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


if __name__ == "__main__":
    unittest.main()
