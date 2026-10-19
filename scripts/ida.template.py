from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_typeinf
import ida_ua
import idaapi
import idc


counts: dict[str, int] = {}


def progress(kind: str, success: bool) -> None:
    counts[kind] = counts.get(kind, 0) + 1
    if not success:
        counts[kind + '_failed'] = counts.get(kind + '_failed', 0) + 1
    if counts[kind] % 5000 == 0:
        print(f'{kind}: {counts[kind]}', flush=True)
        if ida_kernwin.user_cancelled():
            raise RuntimeError('Import cancelled')


def add_function(ea: int, end: int) -> None:
    if idc.get_func_attr(ea, idc.FUNCATTR_START) == ea:
        progress('functions', True)
        return
    progress('functions', bool(ida_ua.create_insn(ea) and ida_funcs.add_func(ea, end)))


def set_name(ea: int, name: str) -> None:
    normalized = ida_name.validate_name(name, ida_name.VNT_IDENT)
    progress('names', idc.get_name(ea) == normalized or
             idaapi.set_name(ea, name, idaapi.SN_NOCHECK | idaapi.SN_NOWARN))


def apply_offset(ea: int, operand: int, sid: int) -> None:
    if ida_bytes.is_stroff(ida_bytes.get_flags(ea), operand):
        path, delta = ida_bytes.get_stroff_path(ea, operand)
        if list(path) == [sid] and delta == 0:
            progress('offsets', True)
            return
    code = ida_bytes.is_code(ida_bytes.get_flags(ea)) or ida_ua.create_insn(ea)
    progress('offsets', bool(code and idc.op_stroff(ea, operand, sid, 0)))


def save_comments(sid: int, comments: dict[int, str]) -> None:
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(sid):
        raise RuntimeError('Cannot load DartObjectPool type')
    members = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(members):
        raise RuntimeError('Cannot read DartObjectPool members')
    indices: dict[int, int] = {member.offset // 8: i for i, member in enumerate(members)}
    changed = 0
    shortened = 0
    for offset, text in comments.items():
        if offset not in indices:
            raise RuntimeError(f'DartObjectPool member missing at {offset:#x}')
        # IDA cannot serialize some very long comments; retain full text in this script.
        encoded = text.encode('utf-8')
        if len(encoded) > 4096:
            text = encoded[:4096].decode('utf-8', errors='ignore')
            text += f'\n[truncated; full text in addNames.py, offset {offset:#x}]'
            shortened += 1
        member = members[indices[offset]]
        if member.cmt != text or member.is_regcmt():
            member.cmt = text
            member.set_regcmt(False)
            changed += 1
        progress('comments', True)
    if changed:
        updated = ida_typeinf.tinfo_t()
        if not updated.create_udt(members, ida_typeinf.BTF_STRUCT):
            raise RuntimeError('Cannot build DartObjectPool type')
        status = updated.set_numbered_type(ida_typeinf.get_idati(), tif.get_ordinal(),
            ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_COPY, 'DartObjectPool')
        if status != ida_typeinf.TERR_OK:
            raise RuntimeError(f'Cannot save DartObjectPool comments: {status}')
        if idc.get_struc_id('DartObjectPool') != sid:
            raise RuntimeError('DartObjectPool type ID changed')
    print(f'Comments saved: {changed}; shortened: {shortened}', flush=True)


def run_import(names: Callable[[], None], structures: Callable[[], tuple[int, int]],
               offsets: Callable[[int, int], None]) -> None:
    counts.clear()
    started = time.monotonic()
    auto_enabled = ida_auto.is_auto_enabled()
    ida_auto.enable_auto(False)
    try:
        print('Creating functions and names', flush=True)
        names()
        print('Importing types and object pool comments', flush=True)
        thrs, pps = structures()
        print('Applying Thread and Object Pool offsets', flush=True)
        offsets(thrs, pps)
        print(f'Script finished in {time.monotonic() - started:.1f}s: {counts}', flush=True)
    finally:
        ida_auto.enable_auto(auto_enabled)
