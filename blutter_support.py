"""Helpers kept outside upstream files to limit merge conflicts.

`run_blutter` applies to every target: the analysis binary prints a failure and
still exits with code 0, so the caller has to watch its output.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile

FAILURE_TOKENS = ('Analysis error', 'exception:')


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
    if status != 0 or failed:
        sys.exit(f'Blutter analysis failed (exit code {status})')
