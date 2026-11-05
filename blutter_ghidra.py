from __future__ import annotations

import argparse
import ast
import base64
from pathlib import Path
import re
import shutil
from collections.abc import Iterator


ROOT: Path = Path(__file__).resolve().parent


def integer(node: ast.expr) -> int:
    value = ast.literal_eval(node)
    if type(value) is not int or value < 0:
        raise ValueError('Expected a non-negative address or operand')
    return value


def text(node: ast.expr) -> str:
    value = ast.literal_eval(node)
    if not isinstance(value, str):
        raise ValueError('Expected a string literal')
    return value


def encode(value: str) -> str:
    return base64.b64encode(value.encode('utf-8')).decode('ascii')


def read_comments(tree: ast.Module) -> dict[int, str]:
    for function in tree.body:
        if isinstance(function, ast.FunctionDef) and function.name == 'create_Dart_structs':
            for node in function.body:
                if (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                        and node.target.id == 'comments' and isinstance(node.value, ast.Dict)):
                    result: dict[int, str] = {}
                    for key, value in zip(node.value.keys, node.value.values):
                        if key is None:
                            raise ValueError('Expanded comment dictionaries are unsupported')
                        result[integer(key)] = text(value)
                    return result
    raise ValueError('Expected comments dictionary from the current IDA generator; regenerate output')


def order_pool_fields(fields: list[str]) -> list[str]:
    # The C++ header lists pool entries in reverse order; each name encodes its byte offset.
    ordered: dict[int, str] = {}
    for field in fields:
        if field in {'pad0', 'pad1'}:
            offset = int(field[-1]) * 8
        else:
            match = re.match(r'(?:Obj|UnlinkedCall)_0x([0-9a-f]+)(?:_|$)', field)
            if match is None:
                match = re.search(r'_0x([0-9a-f]+)$', field)
            if match is None:
                raise ValueError(f'Cannot determine object pool member offset: {field}')
            offset = int(match.group(1), 16)
        if offset in ordered:
            raise ValueError('Duplicate object pool member offset')
        ordered[offset] = field
    if set(ordered) != set(range(0, len(fields) * 8, 8)):
        raise ValueError('Object pool member offsets do not match its layout')
    return [ordered[offset] for offset in range(0, len(fields) * 8, 8)]


def read_structures(header: str, comments: dict[int, str]) -> Iterator[str]:
    seen: set[str] = set()
    for match in re.finditer(r'typedef struct (DartThread|DartObjectPool)\s*\{([^}]+)\}\s*\1;', header):
        name, body = match.groups()
        fields = re.findall(r'__int64\s+([A-Za-z_][A-Za-z_0-9]*)\s*;', body)
        if re.sub(r'__int64\s+[A-Za-z_][A-Za-z_0-9]*\s*;', '', body).strip() or not fields:
            raise ValueError(f'Unsupported structure declaration: {name}')
        if name in seen:
            raise ValueError(f'Duplicate structure: {name}')
        seen.add(name)
        if name == 'DartObjectPool':
            fields = order_pool_fields(fields)
            if any(offset % 8 or offset >= len(fields) * 8 for offset in comments):
                raise ValueError('Object pool comment offset lies outside its structure')
        for index, field in enumerate(fields):
            offset = index * 8
            comment = comments.get(offset, '') if name == 'DartObjectPool' else ''
            yield f'M\t{name}\t{offset}\t{encode(field)}\t{encode(comment)}\n'
    if seen != {'DartThread', 'DartObjectPool'}:
        raise ValueError('Expected DartThread and DartObjectPool declarations')


def records(script: str, header: str) -> Iterator[str]:
    # Parse literals only: converting an output directory never executes its Python script.
    tree = ast.parse(script)
    yield 'BLUTTER_GHIDRA\t1\n'
    yield from read_structures(header, read_comments(tree))
    found: set[str] = set()
    functions: dict[int, int] = {}
    names: dict[int, str] = {}
    offsets: dict[tuple[int, int], str] = {}
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        if function.name not in {'create_functions', 'apply_offsets'}:
            continue
        found.add(function.name)
        for node in function.body:
            if isinstance(node, ast.Pass):
                continue
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                raise ValueError(f'Unsupported statement in {function.name}')
            call = node.value
            if not isinstance(call.func, ast.Name) or call.keywords:
                raise ValueError('Expected a generated helper call')
            args = call.args
            if function.name == 'create_functions' and call.func.id == 'add_function' and len(args) == 2:
                start, end = integer(args[0]), integer(args[1])
                if end <= start:
                    raise ValueError('Function end must follow its start')
                functions[start] = end
            elif function.name == 'create_functions' and call.func.id == 'set_name' and len(args) == 2:
                names[integer(args[0])] = text(args[1])
            elif function.name == 'apply_offsets' and call.func.id == 'apply_offset' and len(args) == 3:
                if not isinstance(args[2], ast.Name) or args[2].id not in {'thrs', 'pps'}:
                    raise ValueError('Unknown offset structure')
                structure = 'DartThread' if args[2].id == 'thrs' else 'DartObjectPool'
                offsets[integer(args[0]), integer(args[1])] = structure
            else:
                raise ValueError(f'Unsupported generated call: {call.func.id}')
    if found != {'create_functions', 'apply_offsets'}:
        raise ValueError('Expected functions from the current IDA generator; regenerate output')
    for start, end in functions.items():
        yield f'F\t{start}\t{end}\n'
    for address, name in names.items():
        yield f'N\t{address}\t{encode(name)}\n'
    for (address, operand), structure in offsets.items():
        yield f'O\t{address}\t{operand}\t{structure}\n'


def convert(source: Path, destination: Path) -> None:
    if (source / 'ida_script').is_dir():
        source = source / 'ida_script'
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError('Output must be a new or empty directory')
    script = (source / 'addNames.py').read_text(encoding='utf-8')
    header = (source / 'ida_dart_struct.h').read_text(encoding='utf-8')
    # Validate the entire input before creating output files.
    for _record in records(script, header):
        pass
    destination.mkdir(parents=True, exist_ok=True)
    with (destination / 'blutter.tsv').open('w', encoding='utf-8', newline='\n') as stream:
        stream.writelines(records(script, header))
    shutil.copyfile(ROOT / 'scripts/BlutterImport.java', destination / 'BlutterImport.java')
    print(f'Ghidra import files: {destination}')
    print('Add this directory to Ghidra Script Manager and run BlutterImport.java on libapp.so.')
    print('Select blutter.tsv when prompted. Headless script arguments: <blutter.tsv> [load-base].')


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate Ghidra import files from Blutter output')
    parser.add_argument('input', type=Path, help='Blutter output directory or its ida_script subdirectory')
    parser.add_argument('output', type=Path, help='New or empty Ghidra script directory')
    args = parser.parse_args()
    try:
        convert(args.input, args.output)
    except (OSError, ValueError, SyntaxError) as error:
        parser.exit(1, f'Error: {error}\n')


if __name__ == '__main__':
    main()
