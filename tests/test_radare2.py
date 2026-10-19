from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from blutter_radare2 import commands, convert, symbol
from test_ghidra import HEADER, script_with


class Radare2Tests(unittest.TestCase):
    def test_names_cannot_inject_commands_and_keep_address_suffix(self) -> None:
        name = symbol('a;!touch /tmp/should_not_exist`$()@#\n汉' * 30, 0x123)
        self.assertRegex(name, r'^blutter\.[A-Za-z0-9_]+_123$')
        self.assertLess(len(name), 210)
        self.assertNotEqual(symbol('a-b', 1), symbol('a+b', 2))

    def test_preserves_full_comments_and_relocates_all_addresses(self) -> None:
        original = '汉字 " \\ \n\t\0 ;!echo injected' * 1000
        output = list(commands(script_with(original), HEADER, 0x1000))
        metadata = next(line for line in output if line.startswith('k blutter.pool.16='))
        self.assertEqual(base64.b64decode(metadata.split('=', 1)[1]).decode(), original)
        self.assertIn('tk struct.DartObjectPool.Obj_0x10=uint64_t,16,0\n', output)
        self.assertIn('f blutter.range.1100 16 0x1100\n', output)
        self.assertTrue(any(line.startswith('af blutter.lib___fn_1100 0x1100') for line in output))
        self.assertEqual(sum(line.startswith('js blutterComment(') for line in output), 1)
        self.assertTrue(next(line for line in output if line.startswith('js blutterComment(')).startswith('js blutterComment("0x1104", '))

    def test_rejects_invalid_base_or_address_overflow(self) -> None:
        for base in (-1, 1 << 64, (1 << 64) - 260):
            with self.subTest(base=base), self.assertRaises(ValueError):
                list(commands(script_with('ok'), HEADER, base))

    def test_reorders_pool_members_using_offsets_in_their_names(self) -> None:
        header = HEADER.replace('__int64 Obj_0x10;', '__int64 Obj_0x18;\n    __int64 Obj_0x10;')
        output = list(commands(script_with('at sixteen'), header))
        self.assertIn('tk struct.DartObjectPool=pad0,pad1,Obj_0x10,Obj_0x18\n', output)
        self.assertIn('tk struct.DartObjectPool.Obj_0x10=uint64_t,16,0\n', output)

    def test_metadata_mode_preserves_ranges_without_function_analysis(self) -> None:
        output = list(commands(script_with('ok'), HEADER, analyze=False))
        self.assertFalse(any(line.startswith('af ') for line in output))
        self.assertIn('f blutter.range.100 16 0x100\n', output)
        self.assertTrue(any(line.startswith('js blutterComment(') for line in output))

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'existing.r2'
            output.write_text('keep')
            with self.assertRaises(ValueError):
                convert(Path(temporary), output)
            self.assertEqual(output.read_text(), 'keep')

    @unittest.skipUnless(shutil.which('r2'), 'radare2 is unavailable')
    def test_preserves_user_comments_while_updating_owned_annotation(self) -> None:
        user = '用户 note; !echo should-not-run `cmd` $() "quotes"\\path\nsecond line'
        encoded = base64.b64encode(user.encode()).decode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'arm64.bin'
            binary.write_bytes(bytes.fromhex('600b40f9c0035fd6'))
            source = script_with('pool').replace('256', '0').replace('272', '8').replace('260', '0')
            first = root / 'first.r2'
            first.write_text(''.join(commands(source, HEADER, analyze=False)), encoding='utf-8')
            updated = root / 'updated.r2'
            updated.write_text(''.join(commands(source.replace('apply_offset(0, 1, pps)',
                                                              'apply_offset(0, 1, thrs)'),
                                               HEADER, analyze=False)), encoding='utf-8')
            result = subprocess.run(['r2', '-N', '-q', '-a', 'arm', '-b', '64',
                                     '-c', f'CCu base64:{encoded} @ 0',
                                     '-c', f'. {first}', '-c', f'. {first}',
                                     '-c', 'CC base64:dXNlciBhZGRpdGlvbg== @ 0',
                                     '-c', f'. {updated}', '-c', f'. {updated}',
                                     '-c', 'CC. @ 0', '-c', 'q', str(binary)],
                                    text=True, capture_output=True, check=True, timeout=30)
            self.assertNotIn('ERROR', result.stderr)
            self.assertIn(user, result.stdout)
            self.assertIn('user addition', result.stdout)
            self.assertEqual(result.stdout.count('[Blutter]'), 1)
            self.assertNotIn('DartObjectPool (x27)', result.stdout)
            self.assertIn('DartThread (x26), operand 1', result.stdout)

    @unittest.skipUnless(shutil.which('r2'), 'radare2 is unavailable')
    def test_imports_into_real_radare2_and_can_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # ARM64: ldr x0, [x27, #16]; ret; nop; nop.
            binary = root / 'arm64.bin'
            binary.write_bytes(bytes.fromhex('600b40f9c0035fd61f2003d51f2003d5'))
            source = script_with('汉字; "quoted"\\path\nsecond line').replace('256', '0').replace('272', '16').replace('260', '0')
            output = root / 'import.r2'
            output.write_text(''.join(commands(source, HEADER)), encoding='utf-8')
            probe = root / 'probe.r2'
            probe.write_text('aflj\nfj\ntsj DartObjectPool\nk blutter.pool.16\nCC. @ 0\n', encoding='utf-8')
            result = subprocess.run(['r2', '-N', '-q', '-a', 'arm', '-b', '64', '-i', str(output),
                                     '-i', str(output), '-i', str(probe), '-c', 'q', str(binary)],
                                    text=True, capture_output=True, check=True, timeout=30)
            self.assertNotIn('ERROR', result.stderr)
            lines = [line for line in result.stdout.splitlines() if not line.startswith('Blutter')]
            functions = json.loads(lines[0])
            self.assertEqual(len(functions), 1)
            self.assertEqual(functions[0]['name'], symbol('lib::#fn', 0))
            flags = json.loads(lines[1])
            self.assertTrue(any(flag['name'] == 'blutter.range.0' and flag['size'] == 16 for flag in flags))
            structure = json.loads(lines[2])
            self.assertEqual(structure['fields'][2]['offset'], 16)
            self.assertEqual(base64.b64decode(lines[3]).decode(), '汉字; "quoted"\\path\nsecond line')
            self.assertIn('DartObjectPool (x27), operand 1', result.stdout)
            output.write_text(''.join(commands(source, HEADER, 0x1000)), encoding='utf-8')
            relocated = subprocess.run(['r2', '-N', '-q', '-a', 'arm', '-b', '64', '-m', '0x1000',
                                        '-i', str(output), '-c', 'aflj', '-c', 'q', str(binary)],
                                       text=True, capture_output=True, check=True, timeout=30)
            self.assertNotIn('ERROR', relocated.stderr)
            relocated_json = next(line for line in relocated.stdout.splitlines() if line.startswith('['))
            self.assertEqual(json.loads(relocated_json)[0]['addr'], 0x1000)


if __name__ == '__main__':
    unittest.main()
