from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import subprocess

# assume git command is in PATH
GIT_CMD = 'git'

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SDK_DIR = os.path.join(SCRIPT_DIR, 'dartsdk')

OHOS_DART_GIT_URL = 'https://gitcode.com/CPF-Flutter/fluttertpc_dart_sdk.git'

# Known OpenHarmony Flutter snapshot hashes mapped to specific Dart fork commits
OHOS_DART_REVISIONS: dict[str, str] = {
    'd36edaec4db7276eb3eaaa2cc8f95ae8': 'e7da8dddd3b32b81a1d83cebbb9109ea3f01fca5',
}

# Default OpenHarmony Flutter branches for supported Dart versions
OHOS_VERSION_BRANCHES: dict[str, str] = {
    '3.4.0': 'flutter_3.22.0_deps',
    '3.4.4': 'flutter_3.22.3_deps',
    '3.6.2': 'flutter_3.27.4_deps',
    '3.8.1': 'flutter_3.32.4_deps',
    '3.9.2': 'flutter_3.35.7_deps',
    '3.11.5': 'flutter_3.41.9_deps',
    '3.12.2': 'flutter_3.44.9_deps',
    '3.13.5': 'flutter_3.47.7_deps',
}


def load_cached_ohos_branches() -> dict[str, str]:
    cache_file = os.path.join(SDK_DIR, 'ohos_branches.json')
    if os.path.isfile(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return {str(k): str(v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_cached_ohos_branches(mapping: dict[str, str]) -> None:
    cache_file = os.path.join(SDK_DIR, 'ohos_branches.json')
    os.makedirs(SDK_DIR, exist_ok=True)
    try:
        current = load_cached_ohos_branches()
        current.update(mapping)
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(current, f, indent=2)
    except Exception:
        pass


def resolve_branch_from_engine_commits(engine_ids: list[str]) -> str | None:
    try:
        import requests
    except ImportError:
        return None

    for engine_id in engine_ids:
        if not re.fullmatch(r'[0-9a-f]{40}', engine_id):
            continue
        try:
            url = f'https://gitcode.com/api/v5/repos/CPF-Flutter/flutter_flutter/commits/{engine_id}'
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                msg = str(data.get('commit', {}).get('message', ''))
                match = re.search(r'oh-?(\d+\.\d+\.\d+)', msg)
                if match:
                    flutter_ver = match.group(1)
                    return f'flutter_{flutter_ver}_deps'
        except Exception:
            continue
    return None


def fetch_branch_dart_version(branch: str) -> tuple[str, str] | None:
    try:
        import requests
        url = f'https://raw.gitcode.com/CPF-Flutter/fluttertpc_dart_sdk/raw/{branch}/tools/VERSION'
        resp = requests.get(url, timeout=4)
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith('#')]
            vd = dict(l.split(None, 1) for l in lines if len(l.split(None, 1)) == 2)
            maj = vd.get('MAJOR')
            min_ = vd.get('MINOR')
            pat = vd.get('PATCH')
            if maj and min_ and pat:
                return (f'{maj}.{min_}.{pat}', branch)
    except Exception:
        pass
    return None


def probe_remote_ohos_branches(target_version: str) -> str | None:
    try:
        cmd = [GIT_CMD, 'ls-remote', '--heads', OHOS_DART_GIT_URL]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
    except Exception:
        return None

    branches: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].startswith('refs/heads/'):
            name = parts[1].removeprefix('refs/heads/')
            if name.startswith('flutter_') and name.endswith('_deps'):
                branches.append(name)

    if not branches:
        return None

    found_mapping: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(len(branches), 8)) as executor:
        for result in executor.map(fetch_branch_dart_version, branches):
            if result:
                dart_ver, branch_name = result
                found_mapping[dart_ver] = branch_name

    if found_mapping:
        save_cached_ohos_branches(found_mapping)
        return found_mapping.get(target_version)

    return None


def resolve_ohos_dart_branch(version: str, snapshot_hash: str | None = None,
                             engine_ids: list[str] | None = None) -> str:
    if snapshot_hash and snapshot_hash in OHOS_DART_REVISIONS:
        return OHOS_DART_REVISIONS[snapshot_hash]

    if version in OHOS_VERSION_BRANCHES:
        return OHOS_VERSION_BRANCHES[version]

    cached = load_cached_ohos_branches()
    if version in cached:
        return cached[version]

    if engine_ids:
        branch = resolve_branch_from_engine_commits(engine_ids)
        if branch:
            save_cached_ohos_branches({version: branch})
            return branch

    remote_branch = probe_remote_ohos_branches(version)
    if remote_branch:
        return remote_branch

    return f'flutter_{version}_deps'


def checkout_dir(version: str, commit: str | None, is_custom: bool) -> str:
    if is_custom and commit:
        return os.path.join(SDK_DIR, f'ohos-v{version}-{commit[:7]}')
    return os.path.join(SDK_DIR, f'ohos-v{version}')


def clone_sdk(clonedir: str, target: str) -> None:
    # A 40-character target is a commit; anything else is a branch name.
    if re.fullmatch(r'[0-9a-f]{40}', target):
        os.makedirs(clonedir, exist_ok=True)
        subprocess.run([GIT_CMD, 'init'], cwd=clonedir, check=True)
        subprocess.run([GIT_CMD, 'sparse-checkout', 'set', 'runtime', 'tools', 'third_party/double-conversion'], cwd=clonedir, check=True)
        subprocess.run([GIT_CMD, 'remote', 'add', 'origin', OHOS_DART_GIT_URL], cwd=clonedir, check=True)
        subprocess.run([GIT_CMD, 'fetch', '--depth', '1', 'origin', target], cwd=clonedir, check=True)
        subprocess.run([GIT_CMD, 'checkout', 'FETCH_HEAD'], cwd=clonedir, check=True)
    else:
        subprocess.run([GIT_CMD, '-c', 'advice.detachedHead=false', 'clone', '-b', target, '--depth', '1', '--filter=blob:none', '--sparse', '--progress', OHOS_DART_GIT_URL, clonedir], check=True)
        subprocess.run([GIT_CMD, 'sparse-checkout', 'set', 'runtime', 'tools', 'third_party/double-conversion'], cwd=clonedir, check=True)
