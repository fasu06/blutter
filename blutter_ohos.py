#!/usr/bin/env python3
"""OpenHarmony Flutter AOT analysis entry point (delegates to unified blutter pipeline)."""

from __future__ import annotations

import argparse
from pathlib import Path

from blutter import main as blutter_main


def main() -> None:
    parser = argparse.ArgumentParser(description='Analyze OHOS Flutter ARM64 AOT snapshots')
    parser.add_argument('input', type=Path, help='HAP or directory containing libapp.so and libflutter.so')
    parser.add_argument('output', type=Path, help='Output directory')
    parser.add_argument('--dart-sdk-commit', help='Matching fluttertpc_dart_sdk commit (40 hex characters)')
    parser.add_argument('--rebuild', action='store_true', help='Force rebuild blutter executable')
    parser.add_argument('--no-analysis', action='store_true', help='Load and dump without ARM64 code analysis')
    parser.add_argument('--jobs', type=int, default=2, help='Parallel compiler jobs (compatibility option)')
    args = parser.parse_args()

    blutter_main(
        str(args.input),
        str(args.output),
        args.rebuild,
        False,
        args.no_analysis,
        dart_sdk_commit=args.dart_sdk_commit,
    )


if __name__ == '__main__':
    main()
