from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import ohos_sdk
from blutter import extract_libs_from_hap, find_compat_macro
from dartvm_fetch_build import DartLibInfo
from ohos_sdk import (
    OHOS_DART_REVISIONS,
    OHOS_VERSION_BRANCHES,
    load_cached_ohos_branches,
    resolve_ohos_dart_branch,
    save_cached_ohos_branches,
)
from extract_dart_info import extract_dart_info


ROOT: Path = Path(__file__).resolve().parents[1]
SAMPLE_HAP: Path = ROOT / 'downloads/PiliPlus_ohos_2.1.6.2-ohos_unsigned.hap'


class BlutterUnifiedTests(unittest.TestCase):
    def test_extract_libs_from_hap_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hap_path = root / 'sample.hap'
            with zipfile.ZipFile(hap_path, 'w') as archive:
                archive.writestr('libs/arm64-v8a/libapp.so', b'dummy_app')
                archive.writestr('libs/arm64-v8a/libflutter.so', b'dummy_flutter')

            out_dir = root / 'extracted'
            out_dir.mkdir()
            app_file, flutter_file = extract_libs_from_hap(str(hap_path), str(out_dir))
            self.assertTrue(os.path.isfile(app_file))
            self.assertTrue(os.path.isfile(flutter_file))
            self.assertEqual(Path(app_file).read_bytes(), b'dummy_app')
            self.assertEqual(Path(flutter_file).read_bytes(), b'dummy_flutter')

    def test_extract_libs_from_hap_rejects_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hap_path = root / 'unsafe.hap'
            with zipfile.ZipFile(hap_path, 'w') as archive:
                archive.writestr('../libs/arm64-v8a/libapp.so', b'app')
                archive.writestr('../libs/arm64-v8a/libflutter.so', b'engine')

            with self.assertRaises(SystemExit):
                extract_libs_from_hap(str(hap_path), str(root / 'out'))

    def test_extract_libs_from_hap_rejects_missing_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hap_path = root / 'incomplete.hap'
            with zipfile.ZipFile(hap_path, 'w') as archive:
                archive.writestr('libs/arm64-v8a/libapp.so', b'app')

            with self.assertRaises(SystemExit):
                extract_libs_from_hap(str(hap_path), str(root / 'out'))

    def test_dart_lib_info_resolves_ohos_versions_and_revisions(self) -> None:
        # PiliPlus known snapshot hash resolution
        info = DartLibInfo('3.12.2', 'ohos', 'arm64', has_compressed_ptrs=True,
                           snapshot_hash='d36edaec4db7276eb3eaaa2cc8f95ae8')
        expected_commit = OHOS_DART_REVISIONS['d36edaec4db7276eb3eaaa2cc8f95ae8']
        self.assertEqual(info.commit, expected_commit)
        self.assertEqual(info.identity, '3.12.2_ohos')
        self.assertEqual(info.lib_name, 'dartvm3.12.2_ohos_arm64')

        # Branch mapping resolution across all supported OHOS versions
        for dart_ver, branch in OHOS_VERSION_BRANCHES.items():
            branch_info = DartLibInfo(dart_ver, 'ohos', 'arm64')
            self.assertEqual(branch_info.commit, branch)
            self.assertEqual(branch_info.identity, f'{dart_ver}_ohos')
            self.assertEqual(branch_info.lib_name, f'dartvm{dart_ver}_ohos_arm64')

        # Explicit commit override
        override_commit = '0123456789abcdef0123456789abcdef01234567'
        custom_info = DartLibInfo('3.12.2', 'ohos', 'arm64', commit=override_commit)
        self.assertEqual(custom_info.commit, override_commit)
        self.assertEqual(custom_info.identity, f'3.12.2_ohos_{override_commit[:7]}')
        self.assertEqual(custom_info.lib_name, f'dartvm3.12.2_ohos_{override_commit[:7]}_arm64')

    @unittest.skipUnless((ROOT / 'packages/include/dartvm3.12.2_ohos').is_dir(),
                         'built Dart include directory not available')
    def test_find_compat_macro_with_identity(self) -> None:
        identity = '3.12.2_ohos'
        macros = find_compat_macro('3.12.2', no_analysis=False, identity=identity)
        self.assertIsInstance(macros, list)

    def test_ohos_branches_file_cache(self) -> None:
        # keep the developer cache in dartsdk/ untouched
        with tempfile.TemporaryDirectory() as temporary, patch.object(ohos_sdk, 'SDK_DIR', temporary):
            save_cached_ohos_branches({'9.9.9': 'flutter_test_branch_deps'})
            self.assertEqual(load_cached_ohos_branches().get('9.9.9'), 'flutter_test_branch_deps')
            # resolve_ohos_dart_branch should read from cache for previously unmapped versions
            self.assertEqual(resolve_ohos_dart_branch('9.9.9'), 'flutter_test_branch_deps')

    def test_ohos_version_branch_distinguishes_mapped_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.object(ohos_sdk, 'SDK_DIR', temporary):
            for version, branch in OHOS_VERSION_BRANCHES.items():
                self.assertEqual(resolve_ohos_dart_branch(version), branch)

    def test_ohos_branch_sort_key_orders_newest_last(self) -> None:
        branches = ['flutter_3.22.0_deps', 'flutter_3.47.7_deps', 'flutter_3.35.7_deps', 'flutter_3.9.2_deps']
        self.assertEqual(max(branches, key=ohos_sdk.branch_sort_key), 'flutter_3.47.7_deps')

    def test_resolve_ohos_dart_branch_from_engine_commit(self) -> None:
        # PiliPlus engine commit 24497d6833225b0445953e1dd05dc6538c16a8dd
        branch = resolve_ohos_dart_branch('3.12.2', engine_ids=['24497d6833225b0445953e1dd05dc6538c16a8dd'])
        self.assertEqual(branch, 'flutter_3.44.9_deps')

    @unittest.skipUnless(SAMPLE_HAP.is_file(), 'PiliPlus sample HAP not available')
    def test_extract_dart_info_on_sample_hap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            app, engine = extract_libs_from_hap(str(SAMPLE_HAP), temporary)
            dart_version, snapshot_hash, flags, arch, os_name = extract_dart_info(app, engine)
            self.assertEqual(dart_version, '3.12.2')
            self.assertEqual(snapshot_hash, 'd36edaec4db7276eb3eaaa2cc8f95ae8')
            self.assertEqual(arch, 'arm64')
            self.assertEqual(os_name, 'ohos')
            self.assertIn('ohos', flags)
            self.assertIn('compressed-pointers', flags)

            # Test return_engine_ids=True variant
            res = extract_dart_info(app, engine, return_engine_ids=True)
            self.assertEqual(len(res), 6)
            engine_ids = res[5]
            self.assertIn('24497d6833225b0445953e1dd05dc6538c16a8dd', engine_ids)


if __name__ == '__main__':
    unittest.main()
