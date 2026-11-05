from __future__ import annotations

from contextlib import redirect_stdout
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from blutter_ohos import Snapshot, input_libraries, inspect_libraries, run_analysis, verify_sdk


ROOT: Path = Path(__file__).resolve().parents[1]
SAMPLE: Path = ROOT / 'downloads/PiliPlus_ohos_2.1.6.2-ohos_unsigned.hap'
APP_MEMBER: str = 'entry/libs/arm64-v8a/libapp.so'
ENGINE_MEMBER: str = 'entry/libs/arm64-v8a/libflutter.so'


class InputLibrariesTests(unittest.TestCase):
    def make_hap(self, path: Path, members: dict[str, bytes]) -> None:
        with zipfile.ZipFile(path, 'w') as archive:
            for name, content in members.items():
                archive.writestr(name, content)

    def test_extracts_exactly_one_arm64_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hap = Path(temporary) / 'sample.hap'
            self.make_hap(hap, {
                APP_MEMBER: b'app', ENGINE_MEMBER: b'engine',
                'entry/libs/armeabi-v7a/libapp.so': b'other-arch',
                'entry/libs/armeabi-v7a/libflutter.so': b'other-engine',
            })
            with input_libraries(hap) as (app, engine):
                self.assertEqual(app.read_bytes(), b'app')
                self.assertEqual(engine.read_bytes(), b'engine')
                self.assertEqual(app.name, 'libapp.so')
                self.assertEqual(engine.name, 'libflutter.so')

    def test_rejects_missing_or_ambiguous_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hap = Path(temporary) / 'sample.hap'
            for members in (
                {APP_MEMBER: b'app'},
                {APP_MEMBER: b'app', ENGINE_MEMBER: b'engine',
                 'feature/libs/arm64-v8a/libapp.so': b'app2',
                 'feature/libs/arm64-v8a/libflutter.so': b'engine2'},
            ):
                self.make_hap(hap, members)
                with self.subTest(pair_count=len(members)), self.assertRaises(ValueError):
                    with input_libraries(hap):
                        self.fail('invalid HAP unexpectedly yielded libraries')

    def test_rejects_zip_slip_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hap = root / 'sample.hap'
            self.make_hap(hap, {
                '../escape/libs/arm64-v8a/libapp.so': b'app',
                '../escape/libs/arm64-v8a/libflutter.so': b'engine',
            })
            with self.assertRaises(ValueError):
                with input_libraries(hap):
                    self.fail('unsafe HAP unexpectedly yielded libraries')
            self.assertFalse((root.parent / 'escape').exists())

    def test_accepts_directory_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            app, engine = directory / 'libapp.so', directory / 'libflutter.so'
            app.write_bytes(b'app')
            engine.write_bytes(b'engine')
            with input_libraries(directory) as libraries:
                self.assertEqual(libraries, (app, engine))

    @unittest.skipUnless(SAMPLE.is_file(), 'PiliPlus release sample is not downloaded')
    def test_inspects_downloaded_piliplus_snapshot(self) -> None:
        with input_libraries(SAMPLE) as (app, engine):
            snapshot = inspect_libraries(app, engine)
        self.assertEqual(snapshot.version, '3.12.2')
        self.assertEqual(snapshot.snapshot_hash, 'd36edaec4db7276eb3eaaa2cc8f95ae8')
        self.assertTrue(snapshot.compressed)


class VerifySdkTests(unittest.TestCase):
    def make_sdk(self, directory: Path, version: str, content: bytes) -> None:
        (directory / 'tools').mkdir()
        (directory / 'runtime/vm').mkdir(parents=True)
        (directory / 'tools/VERSION').write_text(
            f'MAJOR {version.split(".")[0]}\nMINOR {version.split(".")[1]}\n'
            f'PATCH {version.split(".")[2]}\n'
        )
        (directory / 'tools/make_version.py').write_text("VM_SNAPSHOT_FILES = ['snapshot.cc']\n")
        (directory / 'runtime/vm/snapshot.cc').write_bytes(content)

    def test_rejects_sdk_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.make_sdk(directory, '3.12.1', b'compatible')
            snapshot = Snapshot('3.12.2', '6fb581c305c260703b77a2b9b1cfb86c', ())
            with self.assertRaisesRegex(ValueError, 'version'):
                verify_sdk(directory, snapshot)

    def test_rejects_snapshot_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.make_sdk(directory, '3.12.2', b'sdk snapshot source')
            snapshot = Snapshot('3.12.2', '6fb581c305c260703b77a2b9b1cfb86c', ())
            with self.assertRaisesRegex(ValueError, 'hash'):
                verify_sdk(directory, snapshot)


class AnalysisFailureTests(unittest.TestCase):
    def test_rejects_zero_exit_with_analysis_error_and_existing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ('pp.txt', 'objs.txt', 'blutter_frida.js'):
                (directory / name).write_text('previous output')
            from subprocess import Popen
            process = Popen([sys.executable, '-c', 'print("Analysis error at line 10")'],
                            stdout=-1, stderr=-2, text=True)
            with patch('blutter_ohos.subprocess.Popen', return_value=process):
                with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'Analysis failed'):
                    run_analysis(Path('unused'), Path('unused.so'), directory)


if __name__ == '__main__':
    unittest.main()
