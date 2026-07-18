import io
import unittest
import urllib.error
import zipfile
from unittest import mock

from wp2shell.shell import AdminSession


class AdminSessionTests(unittest.TestCase):
    def test_webshell_changes_to_its_plugin_directory(self):
        session = AdminSession("http://target")
        with zipfile.ZipFile(io.BytesIO(session._plugin_zip())) as archive:
            php = archive.read(f"{session._slug}/{session._slug}.php").decode()

        self.assertIn("chdir(__DIR__);", php)

    def test_cleanup_confirms_a_missing_webshell(self):
        session = AdminSession("http://target")
        session.run = mock.Mock(return_value="")
        session._get = mock.Mock(
            side_effect=urllib.error.HTTPError("http://target/shell", 404, "missing", {}, None)
        )

        self.assertTrue(session.cleanup("/shell"))
        command = session.run.call_args.args[1]
        self.assertIn("*/wp-content/plugins/*", command)

    def test_cleanup_handles_a_request_failure(self):
        session = AdminSession("http://target")
        session.run = mock.Mock(side_effect=OSError("connection dropped"))

        self.assertFalse(session.cleanup("/shell"))


if __name__ == "__main__":
    unittest.main()
