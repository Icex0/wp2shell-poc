import contextlib
import io
import unittest
from unittest import mock

from wp2shell import cli


class ShellCommandTests(unittest.TestCase):
    def test_cleanup_runs_when_command_execution_raises(self):
        class FakeSession:
            instance = None

            def __init__(self, *args, **kwargs):
                self.cleaned = False
                type(self).instance = self

            def login(self, username, password):
                return True

            def deploy_webshell(self):
                return "/wp-content/plugins/wp2shell_test/wp2shell_test.php"

            def run(self, path, command):
                raise OSError("connection dropped")

            def cleanup(self, path):
                self.cleaned = True
                return True

        with mock.patch.object(cli, "AdminSession", FakeSession):
            rc = cli.main(
                [
                    "shell",
                    "http://target",
                    "--user",
                    "admin",
                    "--password",
                    "password",
                    "--cmd",
                    "id",
                    "--cleanup",
                ]
            )

        self.assertEqual(rc, 1)
        self.assertTrue(FakeSession.instance.cleaned)

    def test_keep_and_cleanup_are_mutually_exclusive(self):
        parser = cli.build_parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "shell",
                    "http://target",
                    "--user",
                    "admin",
                    "--password",
                    "password",
                    "--cmd",
                    "id",
                    "--keep",
                    "--cleanup",
                ]
            )

    def test_rest_route_is_not_a_shell_option(self):
        parser = cli.build_parser()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "shell",
                    "http://target",
                    "--user",
                    "admin",
                    "--password",
                    "password",
                    "--cmd",
                    "id",
                    "--rest-route",
                ]
            )


if __name__ == "__main__":
    unittest.main()
