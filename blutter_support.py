"""Helpers kept outside upstream files to limit merge conflicts.

`run_blutter` applies to every target: the analysis binary prints a failure and
still exits with code 0, so the caller has to watch its output.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

FAILURE_TOKENS = ('exception:', 'Fatal error:', 'Segmentation fault')
_VS_ENV_INITIALIZED: bool = False


def find_vswhere() -> str | None:
    """Locate vswhere.exe using standard installer locations or PATH."""
    for root in (os.environ.get('ProgramFiles(x86)'), os.environ.get('ProgramFiles')):
        if root:
            candidate = os.path.join(root, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe')
            if os.path.isfile(candidate):
                return candidate
    for fallback in (r'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe',
                     r'C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe'):
        if os.path.isfile(fallback):
            return fallback
    return shutil.which('vswhere')


def find_visual_studio() -> tuple[str, str | None] | None:
    """Find the latest Visual Studio installation path and version.

    Returns (installation_path, version_string) or None if not found.
    """
    vswhere = find_vswhere()
    if vswhere:
        try:
            cmd = [
                vswhere,
                '-latest',
                '-prerelease',
                '-products', '*',
                '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                '-format', 'json',
                '-utf8',
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            entries = json.loads(proc.stdout)
            if entries and isinstance(entries, list):
                entry = entries[0]
                path = entry.get('installationPath')
                ver = entry.get('installationVersion') or entry.get('catalog', {}).get('productDisplayVersion')
                if path and os.path.isdir(path):
                    return str(path), str(ver) if ver else None
        except Exception:
            pass

    for env_var in ('VS2022INSTALLDIR', 'VS2019INSTALLDIR', 'VCINSTALLDIR'):
        val = os.environ.get(env_var)
        if val and os.path.isdir(val):
            return val, None

    prog_roots = [
        r for r in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)'),
                    r'C:\Program Files', r'C:\Program Files (x86)')
        if r
    ]
    editions = ('Enterprise', 'Professional', 'Community', 'BuildTools')
    years = ('2026', '2022', '2019')
    for root in prog_roots:
        for year in years:
            for edition in editions:
                candidate = os.path.join(root, 'Microsoft Visual Studio', year, edition)
                vcvars = os.path.join(candidate, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat')
                if os.path.isfile(vcvars):
                    return candidate, None

    return None


def find_vcvars_script(vs_dir: str) -> str | None:
    vcvarsall = os.path.join(vs_dir, 'VC', 'Auxiliary', 'Build', 'vcvarsall.bat')
    if os.path.isfile(vcvarsall):
        return vcvarsall
    vsdevcmd = os.path.join(vs_dir, 'Common7', 'Tools', 'VsDevCmd.bat')
    if os.path.isfile(vsdevcmd):
        return vsdevcmd
    return None


def query_vs_env(script_path: str, arch: str = 'x64') -> dict[str, str]:
    """Execute vcvarsall.bat or VsDevCmd.bat and capture environment variables."""
    arg = f'-arch={arch}' if script_path.lower().endswith('vsdevcmd.bat') else arch
    sentinel = '__BLUTTER_VS_ENV_START__'
    cmd = f'call "{script_path}" {arg} && echo {sentinel} && set'
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
    out = proc.stdout
    if sentinel not in out:
        raise RuntimeError(f'Failed to extract environment from {script_path}: {proc.stderr or out}')
    _, _, var_section = out.partition(sentinel)
    env: dict[str, str] = {}
    for line in var_section.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if key:
            env[key] = value
    return env


def init_windows_build_env(force: bool = False) -> bool:
    """Detect and activate Visual Studio x64 build environment on Windows.

    If already running in a Developer Command Prompt/PowerShell with cl.exe
    and VSCMD_VER set, does nothing. Otherwise, sniffs Visual Studio installation
    via vswhere or standard directories, extracts x64 environment variables,
    and updates os.environ.
    """
    global _VS_ENV_INITIALIZED
    if sys.platform != 'win32' and os.name != 'nt':
        return False
    if _VS_ENV_INITIALIZED and not force:
        return True

    # Already inside an active VS developer console with compiler on PATH
    if shutil.which('cl') and os.environ.get('VSCMD_VER'):
        _VS_ENV_INITIALIZED = True
        return True

    vs_info = find_visual_studio()
    if not vs_info:
        if shutil.which('cl'):
            _VS_ENV_INITIALIZED = True
            return True
        raise RuntimeError(
            'Visual Studio C++ build environment not found. '
            'Please install Visual Studio with "Desktop development with C++" and "C++ CMake tools".'
        )

    vs_dir, vs_ver = vs_info
    script = find_vcvars_script(vs_dir)
    if not script:
        raise RuntimeError(f'Found Visual Studio at {vs_dir}, but neither vcvarsall.bat nor VsDevCmd.bat exists.')

    print(f'Detected Visual Studio: {vs_dir}')
    env = query_vs_env(script, 'x64')
    os.environ.update(env)

    # Ensure VSCMD_VER is populated for blutter --vs-sln generator detection
    if not os.environ.get('VSCMD_VER') and vs_ver:
        os.environ['VSCMD_VER'] = vs_ver

    # Ensure bundled Ninja and CMake are discoverable if not already in PATH
    path_dirs = os.environ.get('PATH', '').split(os.pathsep)
    ninja_exe = os.path.join(vs_dir, 'Common7', 'IDE', 'CommonExtensions', 'Microsoft', 'CMake', 'Ninja', 'ninja.exe')
    cmake_exe = os.path.join(vs_dir, 'Common7', 'IDE', 'CommonExtensions', 'Microsoft', 'CMake', 'CMake', 'bin', 'cmake.exe')
    extra_paths = []
    if not shutil.which('ninja') and os.path.isfile(ninja_exe):
        extra_paths.append(os.path.dirname(ninja_exe))
    if not shutil.which('cmake') and os.path.isfile(cmake_exe):
        extra_paths.append(os.path.dirname(cmake_exe))
    if extra_paths:
        os.environ['PATH'] = os.pathsep.join(extra_paths + path_dirs)

    _VS_ENV_INITIALIZED = True
    print('Activated Visual Studio x64 build environment.')
    return True


def extract_libs_from_hap(hap_file: str, out_dir: str) -> tuple[str, str]:
    with zipfile.ZipFile(hap_file, 'r') as zf:
        names = set(zf.namelist())
        pairs = [name for name in names if name.endswith('libs/arm64-v8a/libapp.so')
                 and name.removesuffix('libapp.so') + 'libflutter.so' in names]
        if len(pairs) != 1:
            sys.exit(f'Cannot find a unique ARM64 libapp.so and libflutter.so in the HAP, found {len(pairs)}')
        app_name = pairs[0]
        flutter_name = app_name.removesuffix('libapp.so') + 'libflutter.so'
        for member in (app_name, flutter_name):
            member_path = os.path.normpath(member)
            if os.path.isabs(member_path) or member_path.startswith('..'):
                sys.exit(f'Unsafe file path in HAP: {member}')
        zf.extract(app_name, out_dir)
        zf.extract(flutter_name, out_dir)
        return os.path.join(out_dir, app_name), os.path.join(out_dir, flutter_name)


def export_scripts(outdir: str) -> None:
    """Write the Ghidra and radare2 import files next to the IDA script.

    The IDA script is generated by the analysis binary; the other two are pure
    translations of it, so one run can produce all three. Existing targets are
    kept, which makes repeated runs into the same directory harmless.
    """
    ida_dir = Path(outdir) / 'ida_script'
    if not (ida_dir / 'addNames.py').is_file():
        return

    import blutter_ghidra
    import blutter_radare2

    targets = (
        (Path(outdir) / 'ghidra', blutter_ghidra.convert),
        (Path(outdir) / 'blutter.r2', blutter_radare2.convert),
    )
    for target, convert in targets:
        if target.exists():
            print(f'Skipping existing export: {target}')
            continue
        try:
            convert(ida_dir, target)
        except (OSError, ValueError, SyntaxError) as error:
            print(f'Cannot export {target}: {error}', file=sys.stderr)


def run_blutter(executable: str, libapp_path: str, outdir: str) -> None:
    proc = subprocess.Popen([executable, '-i', libapp_path, '-o', outdir],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    failed = False
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        if any(token in line for token in FAILURE_TOKENS):
            failed = True
    status = proc.wait()
    ida_dir = Path(outdir) / 'ida_script'
    if status != 0 or failed or not (ida_dir / 'addNames.py').is_file():
        sys.exit(f'Blutter analysis failed (exit code {status})')
    export_scripts(outdir)
