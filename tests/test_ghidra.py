from __future__ import annotations

import base64
from pathlib import Path
import tempfile
import unittest

from blutter_ghidra import convert, records


HEADER: str = '''typedef struct DartThread {
    __int64 pad0;
    __int64 stack_limit;
} DartThread;
typedef struct DartObjectPool {
    __int64 pad0;
    __int64 pad1;
    __int64 Obj_0x10;
} DartObjectPool;
'''


def script_with(comment: str) -> str:
    return f'''raise RuntimeError('Conversion must never execute this')
def create_functions() -> None:
    set_name(256, 'old')
    add_function(256, 272)
    set_name(256, 'lib::#fn')
def create_Dart_structs() -> tuple[int, int]:
    comments: dict[int, str] = {{16: {comment!r}}}
def apply_offsets(thrs: int, pps: int) -> None:
    apply_offset(260, 1, thrs)
    apply_offset(260, 1, pps)
'''


class GhidraConversionTests(unittest.TestCase):
    def test_preserves_unicode_control_characters_and_final_assignments(self) -> None:
        comment = '汉字 "quoted" \\path\n\t\0' + '长' * 5000
        output = list(records(script_with(comment), HEADER))
        member = next(row for row in output if row.startswith('M\tDartObjectPool\t16\t'))
        self.assertEqual(base64.b64decode(member.rstrip('\n').split('\t')[4]).decode('utf-8'), comment)
        names = [row for row in output if row.startswith('N\t')]
        self.assertEqual(len(names), 1)
        self.assertEqual(base64.b64decode(names[0].strip().split('\t')[2]).decode(), 'lib::#fn')
        self.assertEqual([row for row in output if row.startswith('O\t')],
                         ['O\t260\t1\tDartObjectPool\n'])
        self.assertLess(output.index('F\t256\t272\n'), output.index(names[0]))

    def test_pool_names_and_comments_follow_actual_offsets(self) -> None:
        header = HEADER.replace('__int64 Obj_0x10;', '''__int64 RAW_0xff_0x38;
    __int64 NativeFn_0x1234_0x30;
    __int64 IMM_0x1_0x28;
    __int64 UnlinkedCall_0x20_tagged_0x999;
    __int64 UnlinkedCall_0x18_unknown;
    __int64 Obj_0x10;''')
        rows = [row.rstrip('\n').split('\t') for row in records(script_with('object at sixteen'), header)
                if row.startswith('M\tDartObjectPool\t')]
        names = [base64.b64decode(row[3]).decode() for row in rows]
        self.assertEqual(names, ['pad0', 'pad1', 'Obj_0x10', 'UnlinkedCall_0x18_unknown',
                                 'UnlinkedCall_0x20_tagged_0x999', 'IMM_0x1_0x28',
                                 'NativeFn_0x1234_0x30', 'RAW_0xff_0x38'])
        self.assertEqual([int(row[2]) for row in rows], list(range(0, 64, 8)))
        self.assertEqual(base64.b64decode(rows[2][4]).decode(), 'object at sixteen')
        self.assertEqual(rows[-1][4], '')

    def test_rejects_invalid_pool_offsets(self) -> None:
        for fields in ('Obj_0x18;', 'Obj_0x10; __int64 IMM_0xff_0x10;', 'unknown;'):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                list(records(script_with('ok'), HEADER.replace('Obj_0x10;', fields)))

    def test_rejects_executable_expressions_in_data(self) -> None:
        source = script_with('ok').replace("'lib::#fn'", "__import__('os').getcwd()")
        with self.assertRaises(ValueError):
            list(records(source, HEADER))

    def test_rejects_out_of_range_comment_and_invalid_function(self) -> None:
        with self.assertRaisesRegex(ValueError, 'outside'):
            list(records(script_with('ok').replace('{16:', '{24:'), HEADER))
        with self.assertRaisesRegex(ValueError, 'end'):
            list(records(script_with('ok').replace('256, 272', '256, 256'), HEADER))

    def test_rejects_missing_or_unsupported_structures(self) -> None:
        with self.assertRaises(ValueError):
            list(records(script_with('ok'), HEADER.replace('__int64 pad0;', 'char pad0;')))
        with self.assertRaises(ValueError):
            list(records(script_with('ok'), HEADER.split('typedef struct DartObjectPool')[0]))

    def test_converts_without_executing_script_and_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'input' / 'ida_script'
            source.mkdir(parents=True)
            (source / 'addNames.py').write_text(script_with('ok'), encoding='utf-8')
            (source / 'ida_dart_struct.h').write_text(HEADER, encoding='utf-8')
            output = root / 'output'
            convert(source.parent, output)
            self.assertTrue((output / 'BlutterImport.java').is_file())
            self.assertTrue((output / 'blutter.tsv').read_text().startswith('BLUTTER_GHIDRA\t1\n'))
            with self.assertRaisesRegex(ValueError, 'empty'):
                convert(source, output)


if __name__ == '__main__':
    unittest.main()
