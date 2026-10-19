from __future__ import annotations

import argparse
import base64
from collections.abc import Iterator
from pathlib import Path
import re

from blutter_ghidra import records


MAX_ADDRESS: int = (1 << 64) - 1
COMMENT_HELPER: str = r'''globalThis.blutterComment = function(address, encoded) {
    const key = 'blutter.annotation.' + address;
    const existing = r2.cmd('CC. @ ' + address).replace(/\n$/, '');
    const previous = r2.cmd('k ' + key).trim();
    const annotation = b64(encoded, true);
    const oldAnnotation = previous ? b64(previous, true) : '';
    let lines = existing ? existing.split('\n') : [];
    if (oldAnnotation) {
        for (let index = lines.length - 1; index >= 0; index--) {
            const position = lines[index].lastIndexOf(oldAnnotation);
            if (position < 0) continue;
            lines[index] = lines[index].slice(0, position) +
                lines[index].slice(position + oldAnnotation.length);
            if (!lines[index]) lines.splice(index, 1);
            break;
        }
    }
    lines.push(annotation);
    const merged = lines.join('\n');
    if (merged !== existing) {
        r2.cmd('CCu base64:' + b64(merged) + ' @ ' + address);
    }
    r2.cmd('k ' + key + '=' + encoded);
};'''


def symbol(name: str, address: int) -> str:
    # Keep command separators, substitutions and Unicode out of r2 command tokens.
    safe = re.sub(r'[^A-Za-z0-9_]', '_', name)[:180]
    return f'blutter.{safe}_{address:x}'


def decode(value: str) -> str:
    return base64.b64decode(value, validate=True).decode('utf-8')


def comment(value: str, address: int) -> str:
    encoded = base64.b64encode(value.encode('utf-8')).decode('ascii')
    return f'js blutterComment("{address:#x}", "{encoded}")\n'


def commands(script: str, header: str, base: int = 0, analyze: bool = True) -> Iterator[str]:
    if not 0 <= base <= MAX_ADDRESS:
        raise ValueError('Load base must be an unsigned 64-bit address')
    members: dict[str, list[tuple[int, str, str]]] = {}
    functions: dict[int, int] = {}
    names: dict[int, str] = {}
    offsets: dict[int, list[tuple[int, str]]] = {}
    for line in records(script, header):
        row = line.rstrip('\n').split('\t')
        if row[0] == 'M':
            members.setdefault(row[1], []).append((int(row[2]), decode(row[3]), row[4]))
        elif row[0] in {'F', 'N', 'O'}:
            relative = int(row[1])
            address = base + relative
            if address > MAX_ADDRESS:
                raise ValueError('Relocated address exceeds 64 bits')
            if row[0] == 'F':
                end = base + int(row[2])
                if end > MAX_ADDRESS:
                    raise ValueError('Relocated function end exceeds 64 bits')
                functions[address] = end
            elif row[0] == 'N':
                names[address] = decode(row[2])
            else:
                offsets.setdefault(address, []).append((int(row[2]), row[3]))
    yield '# Blutter radare2 import; load libapp.so at the base used during conversion.\n'
    yield '# k blutter.pool.<decimal-offset> returns the full UTF-8 comment in Base64.\n'
    yield '?e Blutter: importing Dart structures and object pool comments\n'
    for structure, fields in members.items():
        yield f'tk {structure}=struct\n'
        yield f'tk struct.{structure}=' + ','.join(name for _, name, _ in fields) + '\n'
        for offset, name, encoded in fields:
            yield f'tk struct.{structure}.{name}=uint64_t,{offset},0\n'
            if encoded:
                yield f'k blutter.pool.{offset}={encoded}\n'
    yield '?e Blutter: analyzing functions\n'
    for index, (address, end) in enumerate(functions.items(), 1):
        if index % 5000 == 0:
            yield f'?e Blutter: functions {index}/{len(functions)}\n'
        name = symbol(names.get(address, 'function'), address)
        if analyze:
            yield (f'af {name} {address:#x} '
                   f'@e:anal.limits=true,anal.from={address:#x},anal.to={end:#x}\n')
        yield f'f blutter.range.{address:x} {end - address} {address:#x}\n'
    yield '?e Blutter: importing names\n'
    for address, original in names.items():
        name = symbol(original, address)
        # A label can also describe a shared entry or a stub with no function body.
        yield f'f {name} 1 {address:#x}\n'
        encoded = base64.b64encode(original.encode('utf-8')).decode('ascii')
        yield f'k blutter.name.{address}={encoded}\n'
    yield '?e Blutter: annotating Thread and Object Pool accesses\n'
    helper = base64.b64encode(COMMENT_HELPER.encode('utf-8')).decode('ascii')
    yield f'js base64:{helper}\n'
    for address, references in offsets.items():
        descriptions = [f'{structure} ({"x26" if structure == "DartThread" else "x27"}), operand {operand}'
                        for operand, structure in references]
        yield comment('[Blutter] ' + '; '.join(descriptions), address)
    yield '?e Blutter import complete. Use afl, fj~blutter, tsj DartThread or tsj DartObjectPool.\n'


def convert(source: Path, destination: Path, base: int = 0, analyze: bool = True) -> None:
    if (source / 'ida_script').is_dir():
        source = source / 'ida_script'
    if destination.exists():
        raise ValueError('Output already exists; choose a new .r2 file')
    script = (source / 'addNames.py').read_text(encoding='utf-8')
    header = (source / 'ida_dart_struct.h').read_text(encoding='utf-8')
    # Validate source and relocated addresses before creating output.
    for _command in commands(script, header, base, analyze):
        pass
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x', encoding='utf-8', newline='\n') as stream:
        stream.writelines(commands(script, header, base, analyze))
    print(f'radare2 import script: {destination}; load base: {base:#x}')


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate a radare2 script from Blutter output')
    parser.add_argument('input', type=Path, help='Blutter output directory or its ida_script subdirectory')
    parser.add_argument('output', type=Path, help='New .r2 script file')
    parser.add_argument('--base', type=lambda value: int(value, 0), default=0,
                        help='libapp.so load base used by radare2 (default: 0; accepts 0x...)')
    parser.add_argument('--no-analysis', action='store_true',
                        help='Import flags, types and comments without running af on each function')
    args = parser.parse_args()
    try:
        convert(args.input, args.output, args.base, not args.no_analysis)
    except (OSError, ValueError, SyntaxError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
