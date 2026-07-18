import unittest
from unittest import mock

from wp2shell.sqli import BlindSQLi


class BlindSQLiIntegerTests(unittest.TestCase):
    def test_integer_rejects_failed_extraction(self):
        sqli = BlindSQLi(mock.Mock())
        sqli.extract = mock.Mock(return_value="")

        with self.assertRaisesRegex(ValueError, "expected an integer"):
            sqli.integer("SELECT COUNT(*)")

    def test_integer_accepts_signed_values(self):
        sqli = BlindSQLi(mock.Mock())
        sqli.extract = mock.Mock(return_value=" -12 ")

        self.assertEqual(sqli.integer("SELECT -12"), -12)


if __name__ == "__main__":
    unittest.main()
