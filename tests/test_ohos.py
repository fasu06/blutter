from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from blutter_ohos import main as blutter_ohos_main


class BlutterOhosCliTests(unittest.TestCase):
    @patch('blutter_ohos.blutter_main')
    def test_blutter_ohos_delegates_to_blutter_main(self, mock_blutter_main: MagicMock) -> None:
        test_args = ['blutter_ohos.py', 'app.hap', 'out_dir', '--rebuild', '--no-analysis', '--dart-sdk-commit', 'a' * 40]
        with patch('sys.argv', test_args):
            blutter_ohos_main()
            mock_blutter_main.assert_called_once_with(
                'app.hap', 'out_dir', True, False, True, dart_sdk_commit='a' * 40
            )


if __name__ == '__main__':
    unittest.main()
