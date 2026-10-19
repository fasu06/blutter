#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

ROOT: Path = Path(__file__).resolve().parent
DART_REPOSITORY: str = 'https://gitcode.com/CPF-Flutter/fluttertpc_dart_sdk.git'
# Pin source revisions by snapshot format, rather than a moving Flutter branch.
DART_REVISIONS: dict[str, str] = {
    'd36edaec4db7276eb3eaaa2cc8f95ae8': 'e7da8dddd3b32b81a1d83cebbb9109ea3f01fca5',
}


@dataclass(frozen=True)
class Snapshot:
    version: str
    snapshot_hash: str
    flags: tuple[str, ...]

    @property
    def compressed(self) -> bool:
        return 'compressed-pointers' in self.flags


def snapshot_offset(elf: ELFFile) -> int:
    symbols = elf.get_section_by_name('.dynsym')
    if not isinstance(symbols, SymbolTableSection):
        raise ValueError('Missing ELF dynamic symbol table')
    matches = symbols.get_symbol_by_name('_kDartVmSnapshotData')
    if not matches:
        raise ValueError('Missing Dart VM snapshot; an ARM64 AOT release build is required')
    address = int(matches[0]['st_value'])
    for segment in elf.iter_segments():
        start = int(segment['p_vaddr'])
        size = int(segment['p_filesz'])
        if segment['p_type'] == 'PT_LOAD' and start <= address < start + size:
            offset = int(segment['p_offset']) + address - start
            # The shared C++ loader currently uses virtual addresses as file offsets.
            if offset != address:
                raise ValueError('ELF load segments require virtual address mapping; unsupported layout')
            return offset
    raise ValueError('Dart VM snapshot is outside file-backed ELF segments')


def inspect_libraries(app: Path, engine: Path) -> Snapshot:
    with app.open('rb') as stream:
        elf = ELFFile(stream)
        if elf.header['e_machine'] != 'EM_AARCH64' or elf.elfclass != 64 or not elf.little_endian:
            raise ValueError('OHOS analysis currently requires little-endian ARM64 ELF')
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD' and segment['p_offset'] != segment['p_vaddr']:
                raise ValueError('ELF load segments require virtual address mapping; unsupported layout')
        stream.seek(snapshot_offset(elf))
        header = stream.read(4096)
    if header[:4] != b'\xf5\xf5\xdc\xdc':
        raise ValueError('Invalid Dart snapshot magic')
    snapshot_hash = header[20:52].decode('ascii')
    if re.fullmatch(r'[0-9a-f]{32}', snapshot_hash) is None:
        raise ValueError('Invalid Dart snapshot version hash')
    flags = tuple(header[52:].split(b'\0', 1)[0].decode('ascii').split())
    if 'ohos' not in flags or 'arm64' not in flags or 'product' not in flags:
        raise ValueError(f'Expected a product ARM64 OHOS snapshot, found: {" ".join(flags)}')
    with engine.open('rb') as stream:
        elf = ELFFile(stream)
        if elf.header['e_machine'] != 'EM_AARCH64':
            raise ValueError('Engine and application architectures differ')
        section = elf.get_section_by_name('.rodata')
        if section is None:
            raise ValueError('Missing engine .rodata section')
        match = re.search(rb'\x00(\d+\.\d+\.\d+(?:[-\w.]*)?) \((?:stable|beta|dev)\)', section.data())
    if match is None:
        raise ValueError('Cannot determine the Dart version from libflutter.so')
    return Snapshot(match.group(1).decode('ascii'), snapshot_hash, flags)


def copy_member(archive: zipfile.ZipFile, name: str, destination: Path) -> None:
    with archive.open(name) as source, destination.open('xb') as output:
        shutil.copyfileobj(source, output)


@contextmanager
def input_libraries(source: Path) -> Iterator[tuple[Path, Path]]:
    if source.is_dir():
        app, engine = source / 'libapp.so', source / 'libflutter.so'
        if not app.is_file() or not engine.is_file():
            raise ValueError('Input directory must contain libapp.so and libflutter.so')
        yield app, engine
        return
    with zipfile.ZipFile(source) as archive:
        names = set(archive.namelist())
        pairs = [name for name in names if name.endswith('libs/arm64-v8a/libapp.so')
                 and name.removesuffix('libapp.so') + 'libflutter.so' in names]
        if len(pairs) != 1:
            raise ValueError(f'Expected one ARM64 library pair in HAP, found {len(pairs)}')
        member_path = PurePosixPath(pairs[0])
        if member_path.is_absolute() or '..' in member_path.parts or '\\' in pairs[0]:
            raise ValueError('Unsafe HAP library member path')
        with tempfile.TemporaryDirectory(prefix='blutter-ohos-') as directory:
            app, engine = Path(directory) / 'libapp.so', Path(directory) / 'libflutter.so'
            copy_member(archive, pairs[0], app)
            copy_member(archive, pairs[0].removesuffix('libapp.so') + 'libflutter.so', engine)
            yield app, engine


def run(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE)
    return result.stdout.strip()


def checkout_sdk(revision: str) -> Path:
    directory = ROOT / 'dartsdk' / f'ohos-{revision}'
    if not directory.exists():
        directory.mkdir(parents=True)
        run(['git', 'init'], directory)
        run(['git', 'remote', 'add', 'origin', DART_REPOSITORY], directory)
        run(['git', 'sparse-checkout', 'set', 'runtime', 'tools', 'third_party/double-conversion'], directory)
    if not (directory / '.git').is_dir():
        raise ValueError(f'Expected a Git SDK checkout at {directory}')
    if run(['git', 'remote', 'get-url', 'origin'], directory) != DART_REPOSITORY:
        raise ValueError(f'SDK cache has an unexpected origin: {directory}')
    head = subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=directory,
                          text=True, capture_output=True)
    if head.returncode != 0:
        run(['git', 'fetch', '--depth', '1', '--filter=blob:none', 'origin', revision], directory)
        run(['git', 'checkout', '--detach', 'FETCH_HEAD'], directory)
    if run(['git', 'rev-parse', 'HEAD'], directory) != revision:
        raise ValueError(f'SDK cache revision differs: {directory}')
    return directory


def verify_sdk(directory: Path, snapshot: Snapshot) -> None:
    version_values = dict(re.findall(r'^(MAJOR|MINOR|PATCH) (\d+)$',
                                    (directory / 'tools/VERSION').read_text(), re.MULTILINE))
    version = '.'.join(version_values[key] for key in ('MAJOR', 'MINOR', 'PATCH'))
    if snapshot.version != version:
        raise ValueError(f'SDK version {version} differs from engine {snapshot.version}')
    # Use the SDK's own list of files to verify snapshot compatibility before building.
    make_version = (directory / 'tools/make_version.py').read_text()
    match = re.search(r'VM_SNAPSHOT_FILES\s*=\s*\[([^]]+)\]', make_version)
    if match is None:
        raise ValueError('Cannot locate SDK snapshot hash inputs')
    digest = hashlib.md5()
    for name in re.findall(r"['\"]([\w.]+)['\"]", match.group(1)):
        digest.update((directory / 'runtime/vm' / name).read_bytes())
    if digest.hexdigest() != snapshot.snapshot_hash:
        raise ValueError(f'SDK snapshot hash {digest.hexdigest()} differs from {snapshot.snapshot_hash}; '
                         'select the matching fork commit with --dart-sdk-commit')


def build_runtime(directory: Path, snapshot: Snapshot, identity: str, jobs: int) -> str:
    package = 'dartvm' + identity
    library = package + '_ohos_arm64'
    template = (ROOT / 'scripts/CMakeLists.txt').read_text()
    standard_match = re.search(r'-std=c\+\+(\d+)',
                              (directory / 'runtime/tools/run_clang_tidy.dart').read_text())
    standard = standard_match.group(1) if standard_match else '17'
    template = template.replace('VERSION_PLACE_HOLDER', identity).replace('CXX_STD_PLACE_HOLDER', standard)
    template = template.replace('string(SUBSTRING ${PROJECT_NAME} 6 -1 DART_VERSION)',
                                f'set(DART_VERSION "{snapshot.version}")\n'
                                f'set(DART_PACKAGE_ID "{identity}")')
    template = template.replace('dartvm${DART_VERSION}_${TARGET_OS}_${TARGET_ARCH}',
                                'dartvm${DART_PACKAGE_ID}_${TARGET_OS}_${TARGET_ARCH}')
    (directory / 'CMakeLists.txt').write_text(template)
    (directory / 'Config.cmake.in').write_text('@PACKAGE_INIT@\n'
        'include("${CMAKE_CURRENT_LIST_DIR}/dartvmTarget.cmake")\n')
    run([sys.executable, str(ROOT / 'scripts/dartvm_make_version.py'), str(directory),
         snapshot.snapshot_hash], ROOT)
    run([sys.executable, str(ROOT / 'scripts/dartvm_create_srclist.py'), str(directory)], ROOT)
    build = ROOT / 'build' / library
    subprocess.run(['cmake', '-GNinja', '-B', str(build), '-DTARGET_OS=ohos', '-DTARGET_ARCH=arm64',
                    f'-DCOMPRESSED_PTRS={int(snapshot.compressed)}', '-DCMAKE_BUILD_TYPE=Release',
                    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'], cwd=directory, check=True)
    subprocess.run(['cmake', '--build', str(build), '--parallel', str(jobs)], check=True)
    subprocess.run(['cmake', '--install', str(build)], check=True)
    return library


def build_blutter(identity: str, library: str, no_analysis: bool, jobs: int) -> Path:
    from blutter import find_compat_macro

    suffix = '_no-analysis' if no_analysis else ''
    name = f'blutter_{library}{suffix}'
    build = ROOT / 'build' / name
    macros: list[str] = find_compat_macro(identity, no_analysis)
    subprocess.run(['cmake', '-GNinja', '-B', str(build), f'-DDARTLIB={library}',
                    f'-DNAME_SUFFIX={suffix}', '-DCMAKE_BUILD_TYPE=Release',
                    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', *macros], cwd=ROOT / 'blutter', check=True)
    subprocess.run(['cmake', '--build', str(build), '--parallel', str(jobs)], check=True)
    subprocess.run(['cmake', '--install', str(build)], check=True)
    return ROOT / 'bin' / (name + ('.exe' if sys.platform == 'win32' else ''))


def analyze(source: Path, output: Path, revision: str | None, rebuild: bool,
            no_analysis: bool, jobs: int) -> None:
    output = output.resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('Output must be a new or empty directory; choose a new output path')
    with input_libraries(source.resolve()) as (app, engine):
        snapshot = inspect_libraries(app, engine)
        print(f'Dart {snapshot.version}, snapshot {snapshot.snapshot_hash}', flush=True)
        print('Flags: ' + ' '.join(snapshot.flags), flush=True)
        commit = revision or DART_REVISIONS.get(snapshot.snapshot_hash)
        if commit is None or re.fullmatch(r'[0-9a-f]{40}', commit) is None:
            raise ValueError('Supply the matching 40-character OHOS Dart revision with --dart-sdk-commit')
        identity = f'{snapshot.version}_ohos_{commit}_{snapshot.snapshot_hash}'
        if not snapshot.compressed:
            identity += '_uncompressed'
        library = f'dartvm{identity}_ohos_arm64'
        suffix = '_no-analysis' if no_analysis else ''
        executable = ROOT / 'bin' / (f'blutter_{library}{suffix}' +
                                     ('.exe' if sys.platform == 'win32' else ''))
        if rebuild or not executable.is_file():
            directory = checkout_sdk(commit)
            verify_sdk(directory, snapshot)
            library = build_runtime(directory, snapshot, identity, jobs)
            executable = build_blutter(identity, library, no_analysis, jobs)
        output.mkdir(parents=True, exist_ok=True)
        run_analysis(executable, app, output)


def run_analysis(executable: Path, app: Path, output: Path) -> None:
    # The shared executable reports some failures with exit code zero.
    with subprocess.Popen([str(executable), '-i', str(app), '-o', str(output)],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, errors='replace', bufsize=1) as process:
        if process.stdout is None:
            raise RuntimeError('Cannot read analysis diagnostics')
        failed = False
        for line in process.stdout:
            print(line, end='', flush=True)
            failed = failed or line.startswith(('Analysis error', 'exception:'))
        status = process.wait()
    if status != 0 or failed:
        raise RuntimeError(f'Analysis failed (exit code {status}); inspect diagnostics above')
    for name in ('pp.txt', 'objs.txt', 'blutter_frida.js'):
        artifact = output / name
        if not artifact.is_file() or artifact.stat().st_size == 0:
            raise RuntimeError(f'Analysis did not produce {name}')


def main() -> None:
    parser = argparse.ArgumentParser(description='Analyze OHOS Flutter ARM64 AOT snapshots')
    parser.add_argument('input', type=Path, help='HAP or directory containing libapp.so and libflutter.so')
    parser.add_argument('output', type=Path)
    parser.add_argument('--dart-sdk-commit', help='Matching fluttertpc_dart_sdk commit (40 hex characters)')
    parser.add_argument('--rebuild', action='store_true')
    parser.add_argument('--no-analysis', action='store_true', help='Load and dump without ARM64 code analysis')
    parser.add_argument('--jobs', type=int, default=2, help='Parallel compiler jobs (default: 2)')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    try:
        analyze(args.input, args.output, args.dart_sdk_commit, args.rebuild, args.no_analysis, args.jobs)
    except (ValueError, RuntimeError, OSError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        parser.exit(1, f'OHOS analysis failed: {error}\n')


if __name__ == '__main__':
    main()
