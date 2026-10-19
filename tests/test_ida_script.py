from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Callable, cast
import unittest
from unittest.mock import MagicMock, patch


TEMPLATE: Path = Path(__file__).resolve().parents[1] / 'scripts/ida.template.py'


class IdaScriptTests(unittest.TestCase):
    def load_template(self, modules: dict[str, object]) -> dict[str, object]:
        names = ('ida_auto', 'ida_bytes', 'ida_funcs', 'ida_kernwin', 'ida_name',
                 'ida_typeinf', 'ida_ua', 'idaapi', 'idc')
        imports = {name: modules.get(name, MagicMock()) for name in names}
        namespace: dict[str, object] = {}
        with patch.dict('sys.modules', imports):
            exec(compile(TEMPLATE.read_text(), str(TEMPLATE), 'exec'), namespace)
        return namespace

    def test_saves_all_comments_once_and_preserves_unicode_boundary(self) -> None:
        members = [SimpleNamespace(offset=128, cmt='', is_regcmt=lambda: False,
                                   set_regcmt=MagicMock())]
        original, updated = MagicMock(), MagicMock()
        original.get_udt_details.return_value = True
        original.get_ordinal.return_value = 7
        original.get_type_by_tid.return_value = True
        updated.create_udt.return_value = True
        updated.set_numbered_type.return_value = 0
        types = MagicMock()
        types.tinfo_t.side_effect = [original, updated]
        types.udt_type_data_t.return_value = members
        types.TERR_OK = 0
        idc = MagicMock()
        idc.get_struc_id.return_value = 42
        namespace = self.load_template({'ida_typeinf': types, 'idc': idc})
        save = cast(Callable[[int, dict[int, str]], None], namespace['save_comments'])
        text = '汉' * 2000
        with patch('builtins.print'):
            save(42, {16: text})
        self.assertTrue(members[0].cmt.startswith('汉' * 1365))
        self.assertIn('[truncated;', members[0].cmt)
        self.assertIn('offset 0x10', members[0].cmt)
        updated.set_numbered_type.assert_called_once()
        members[0].set_regcmt.assert_called_once_with(False)
        idc.set_member_cmt.assert_not_called()

    def test_repeat_skips_unchanged_type_save(self) -> None:
        member = SimpleNamespace(offset=128, cmt='saved', is_regcmt=lambda: False)
        original = MagicMock()
        types = MagicMock()
        types.tinfo_t.return_value = original
        types.udt_type_data_t.return_value = [member]
        namespace = self.load_template({'ida_typeinf': types})
        save = cast(Callable[[int, dict[int, str]], None], namespace['save_comments'])
        with patch('builtins.print'):
            save(42, {16: 'saved'})
        self.assertEqual(types.tinfo_t.call_count, 1)
        original.set_numbered_type.assert_not_called()

    def test_missing_member_raises_before_saving(self) -> None:
        types = MagicMock()
        types.udt_type_data_t.return_value = []
        namespace = self.load_template({'ida_typeinf': types})
        save = cast(Callable[[int, dict[int, str]], None], namespace['save_comments'])
        with self.assertRaisesRegex(RuntimeError, 'member missing'):
            save(42, {16: 'comment'})

    def test_existing_offset_does_not_reapply_annotation(self) -> None:
        data = MagicMock()
        data.is_stroff.return_value = True
        data.get_stroff_path.return_value = ([42], 0)
        idc = MagicMock()
        namespace = self.load_template({'ida_bytes': data, 'idc': idc})
        apply = cast(Callable[[int, int, int], None], namespace['apply_offset'])
        apply(0x1000, 1, 42)
        idc.op_stroff.assert_not_called()

    def test_failure_restores_auto_analysis(self) -> None:
        auto = MagicMock()
        auto.is_auto_enabled.return_value = True
        namespace = self.load_template({'ida_auto': auto})
        run = cast(Callable[[Callable[[], None], Callable[[], tuple[int, int]],
                             Callable[[int, int], None]], None], namespace['run_import'])
        with patch('builtins.print'), self.assertRaisesRegex(RuntimeError, 'test failure'):
            run(MagicMock(side_effect=RuntimeError('test failure')), MagicMock(), MagicMock())
        self.assertEqual(auto.enable_auto.call_args_list, [((False,),), ((True,),)])


if __name__ == '__main__':
    unittest.main()
