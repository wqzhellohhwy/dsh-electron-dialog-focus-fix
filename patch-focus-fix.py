#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch-focus-fix.py —— 给 Electron 应用（实测：DeepSeek Harness 桌面版）打「原生对话框
关闭后键盘输入失效」的修复补丁。

原理（详见 README.md）
--------------------
在这个应用里，`window.confirm/alert/prompt` 最终落到 Win32 的 TaskDialogIndirect。
对话框关闭后，Windows 把前台窗口还给了宿主窗口，但 Chromium 的渲染进程仍然认为
自己没被激活（document.hasFocus() === false），于是页面收不到键盘输入。
窗口**无法自己**把前台抢回来（Windows 前台锁定），所以补丁在「对话框刚关闭、宿主
进程仍然是前台」的那一瞬间授权、并拉起一个小工具进程去做真正的「切走再切回」。

本脚本做四件事
------------
1. **自动定位补丁点**（不写死任何地址）：
   - 解析 PE 的导入表 / 延迟导入表，找 COMCTL32.DLL 的**序号 #345**（= TaskDialogIndirect）
     的 IAT 槽地址；
   - 扫描可执行段，找形如 `FF 15 <disp32>`（call qword ptr [rip+disp32]）且目标是该槽的
     指令 —— 那就是调用点。
   > 注意：comctl32 是**按序号**导入的，所以二进制里**搜不到 "TaskDialogIndirect" 这个字符串**，
   > 只能按序号找。
2. **自动探测 hook 点**：hook 打在**调用之后**那条指令上（**绝不能动 call 本身** ——
   延迟导入的 thunk 只能从它原本的调用位置被调用，换地方会 0xC0000005）。
   用 capstone 反汇编出紧随其后那条指令的长度，需要 ≥5 字节才放得下 `jmp rel32`。
   若单条不足 5 字节，会自动尝试「连吞后续若干条」凑够（前提是这些指令都不含
   RIP 相对寻址，否则无法安全搬运）。
3. 新增一个 `.fix` 段保管补丁代码：段属性**必须含 WRITE**、代码全部 **RIP 相对**（ASLR）、
   并清掉 **GUARD_CF**（新段里的回调不是 CFG 合法目标，会被 __fastfail 杀掉）。
4. 写回 PE 头（NumberOfSections / SizeOfImage / 校验和）并可选安装到目标位置。

用法
----
    # 只探测、不写盘（强烈建议先跑这个）
    python patch-focus-fix.py --probe

    # 生成打过补丁的副本
    python patch-focus-fix.py --out patched.exe

    # 生成并直接安装（先自动备份）
    python patch-focus-fix.py --install

    # 指定目标 / helper
    python patch-focus-fix.py --exe "D:\\Apps\\DeepSeek Harness\\DeepSeek Harness.exe" \\
                              --helper "D:\\tools\\focus-helper.exe" --install

依赖：pefile、capstone、keystone-engine
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import struct
import sys
import time

try:
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
    from capstone.x86 import X86_REG_RIP
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
except ImportError as exc:  # 依赖缺失时给出可执行的提示
    sys.exit(
        '缺少依赖：%s\n请先安装：  pip install pefile capstone keystone-engine' % exc
    )


# ─────────────────────────────── 常量 ───────────────────────────────

TASK_DLL = 'COMCTL32.DLL'
TASK_ORDINAL = 345                 # comctl32 里 TaskDialogIndirect 的导出序号
FIX_SECTION = '.fix'
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

# PE 段属性：CODE | EXECUTE | READ | WRITE
# WRITE 是必须的：补丁代码会写自己的计数器，只读段会直接 0xC0000005。
FIX_SECTION_CHARS = 0xE0000020

# DllCharacteristics 里的 GUARD_CF 位。
GUARD_CF = 0x4000

# 需要用到的一组 API（按「DLL!函数名」匹配导入表，大小写不敏感）。
WANTED_APIS = {
    'KERNEL32.DLL!CREATEPROCESSW': 'CREATEP',
    'USER32.DLL!ALLOWSETFOREGROUNDWINDOW': 'ALLOWFG',
    'USER32.DLL!GETFOREGROUNDWINDOW': 'GETFG',
}

# 常见安装位置（仅作为默认探测；可用 --exe / 环境变量覆盖）。
DEFAULT_EXE_GLOBS = [
    r'%LOCALAPPDATA%\Programs\DeepSeek Harness\DeepSeek Harness.exe',
    r'%LOCALAPPDATA%\Programs\deepseek-harness\DeepSeek Harness.exe',
    r'%PROGRAMFILES%\DeepSeek Harness\DeepSeek Harness.exe',
    r'%PROGRAMFILES(X86)%\DeepSeek Harness\DeepSeek Harness.exe',
    r'%PROGRAMFILES%\deepseek-harness\DeepSeek Harness.exe',
]

ENV_EXE = 'DSH_EXE'
ENV_HELPER = 'DSH_FOCUS_HELPER'


def align(value: int, alignment: int) -> int:
    """向上对齐。"""
    return (value + alignment - 1) & ~(alignment - 1)


def expand(path: str) -> str:
    """展开环境变量与 ~。"""
    return os.path.expanduser(os.path.expandvars(path))


# ─────────────────────────── 目标探测 ───────────────────────────

def find_target_exe(explicit: str | None) -> str:
    """
    确定要打补丁的 exe：命令行 > 环境变量 > 常见安装位置。
    找不到就报错，并把都试过哪些位置列出来。
    """
    tried: list[str] = []

    for candidate, source in (
        (explicit, '--exe'),
        (os.environ.get(ENV_EXE), '$%s' % ENV_EXE),
    ):
        if not candidate:
            continue
        full = expand(candidate)
        tried.append('%s → %s' % (source, full))
        if os.path.isfile(full):
            return full

    for pattern in DEFAULT_EXE_GLOBS:
        full = expand(pattern)
        tried.append('默认探测 → %s' % full)
        if os.path.isfile(full):
            return full
        # 安装目录名可能带版本号，做一次宽松匹配
        parent = os.path.dirname(full)
        if os.path.isdir(parent):
            hits = glob.glob(os.path.join(glob.escape(parent), '*.exe'))
            for hit in hits:
                if os.path.basename(hit).lower() == os.path.basename(full).lower():
                    return hit

    raise SystemExit(
        '找不到目标 exe。请用 --exe <路径> 或设置环境变量 %s。\n已尝试：\n  %s'
        % (ENV_EXE, '\n  '.join(tried))
    )


def find_helper(explicit: str | None, exe_dir: str) -> str | None:
    """
    确定 helper 可执行文件：命令行 > 环境变量 > exe 同目录 > 脚本同目录。
    找不到不直接报错（打补丁本身可以继续），但会提醒用户。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        (explicit, '--helper'),
        (os.environ.get(ENV_HELPER), '$%s' % ENV_HELPER),
        (os.path.join(exe_dir, 'focus-helper.exe'), 'exe 同目录'),
        (os.path.join(here, 'focus-helper.exe'), '脚本同目录'),
        (os.path.join(here, 'helper', 'focus-helper.exe'), 'helper/ 子目录'),
    ]
    for candidate, source in candidates:
        if not candidate:
            continue
        full = expand(candidate)
        if os.path.isfile(full):
            return full
    return None


# ─────────────────────── PE 解析与自动定位 ───────────────────────

def load_pe(path: str) -> pefile.PE:
    """打开 PE 并解析导入表 / 延迟导入表。"""
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
        ]
    )
    return pe


def find_taskdialog_slot(pe: pefile.PE) -> tuple[int, str] | None:
    """
    找 comctl32 里序号 #345（TaskDialogIndirect）的 IAT 槽虚拟地址。
    返回 (槽 VA, 来源表名)；找不到返回 None。

    —— 这一步是「为什么不能按名字搜」的关键：comctl32 的导入项只带序号、
    不带名字，所以二进制里根本没有 "TaskDialogIndirect" 这个字符串可搜。
    """
    for attr, label in (
        ('DIRECTORY_ENTRY_IMPORT', '导入表'),
        ('DIRECTORY_ENTRY_DELAY_IMPORT', '延迟导入表'),
    ):
        for entry in getattr(pe, attr, None) or []:
            try:
                dll = entry.dll.decode('ascii', 'ignore').upper()
            except Exception:
                continue
            if dll != TASK_DLL:
                continue
            for imp in entry.imports:
                # 按序号导入时 name 为 None
                if imp.name is None and imp.ordinal == TASK_ORDINAL:
                    return imp.address, label
    return None


def scan_call_sites(pe: pefile.PE, slot_va: int) -> list[int]:
    """
    在所有可执行段里扫 `FF 15 <disp32>`（call qword ptr [rip+disp32]），
    返回目标等于 slot_va 的指令地址列表。disp32 是相对「指令结束地址」的偏移。
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase
    hits: list[int] = []
    for section in pe.sections:
        # IMAGE_SCN_MEM_EXECUTE
        if not (section.Characteristics & 0x20000000):
            continue
        data = section.get_data()
        base_va = image_base + section.VirtualAddress
        pos = 0
        while True:
            pos = data.find(b'\xff\x15', pos)
            if pos < 0:
                break
            disp = struct.unpack_from('<i', data, pos + 2)[0]
            target = base_va + pos + 6 + disp
            if target == slot_va:
                hits.append(base_va + pos)
            pos += 2
    return hits


def read_at_va(pe: pefile.PE, va: int, size: int) -> bytes:
    """按虚拟地址读一段字节。"""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    rva = va - image_base
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < end:
            offset = rva - start
            data = section.get_data()
            return data[offset:offset + size]
    return b''


def has_rip_relative(insn) -> bool:
    """判断一条指令的操作数里是否含 RIP 相对寻址（含则不能整体搬走）。"""
    for operand in insn.operands:
        if operand.type == CS_OP_MEM and operand.mem.base == X86_REG_RIP:
            return True
    return False


def plan_hook(pe: pefile.PE, call_va: int) -> dict:
    """
    在调用点之后规划 hook：反汇编紧随 call 的那条（或若干条）指令，
    直到凑够 5 字节能放下 `jmp rel32`。

    返回一个字典；不可行时 ok=False 并给出 reason / hint。
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    blob = read_at_va(pe, call_va, 64)
    if not blob:
        return {'ok': False, 'reason': '读不到调用点附近的字节'}

    insns = list(md.disasm(blob, call_va))
    if len(insns) < 2:
        return {'ok': False, 'reason': '调用点之后反汇编不出指令'}

    call_insn = insns[0]
    if not call_insn.mnemonic.startswith('call'):
        return {'ok': False, 'reason': '该位置不是 call 指令（可能是数据误命中）'}

    stolen: list = []
    total = 0
    for insn in insns[1:]:
        if has_rip_relative(insn):
            return {
                'ok': False,
                'reason': 'hook 点之后第一条待搬运指令含 RIP 相对寻址（%s %s）'
                          % (insn.mnemonic, insn.op_str),
                'hint': '这条指令搬走后相对偏移会失效。请人工选择其它 hook 点。',
            }
        stolen.append(insn)
        total += insn.size
        if total >= 5:
            break

    if total < 5:
        return {
            'ok': False,
            'reason': 'hook 点之后连吞 %d 条指令也只凑到 %d 字节，放不下 5 字节的 jmp rel32'
                      % (len(stolen), total),
            'hint': '尝试 --site 指定另一个调用点；或人工分析该处代码布局。',
        }

    hook_va = call_va + call_insn.size
    return {
        'ok': True,
        'call_va': call_va,
        'call_size': call_insn.size,
        'hook_va': hook_va,
        'stolen': stolen,
        'stolen_len': total,
        'stolen_bytes': b''.join(bytes(i.bytes) for i in stolen),
        'resume_va': hook_va + total,
    }


# ─────────────────────────── 补丁代码生成 ───────────────────────────

class CaveBuilder:
    """
    往 .fix 段里拼机器码的小工具。
    全部跳转/取址都走 RIP 相对，保证在 ASLR 下依然有效。
    """

    REG = {
        'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4,
        'rbp': 5, 'rsi': 6, 'rdi': 7, 'r8': 8, 'r9': 9,
        'r10': 10, 'r11': 11, 'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15,
    }

    def __init__(self, base_va: int):
        self.base = base_va
        self.pos = base_va
        self.buf = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups_jcc: list[tuple[int, str, int]] = []
        self.fixups_rip: list[tuple[int, str, int]] = []
        self.fixups_jmp: list[tuple[int, str, int]] = []
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    # 记录标签
    def label(self, name: str) -> None:
        self.labels[name] = self.pos

    # 汇编一条指令（地址正确，keystone 会自己算相对偏移）
    def asm(self, text: str) -> None:
        encoded, _ = self.ks.asm(text, addr=self.pos)
        if not encoded:
            raise SystemExit('无法汇编：%s' % text)
        self.buf.extend(encoded)
        self.pos += len(encoded)

    # 调用 IAT 槽：call qword ptr [rip+disp32]
    def call_iat(self, slot_va: int) -> None:
        self.buf.extend(b'\xff\x15' + struct.pack('<i', slot_va - (self.pos + 6)))
        self.pos += 6

    # lea reg, [rip+目标]（目标可以是标签名或绝对地址）
    def lea_rip(self, reg: str, target) -> None:
        code = self.REG[reg]
        rex = 0x48 | (0x04 if code >= 8 else 0)
        self.buf.extend(bytes([rex, 0x8d, ((code & 7) << 3) | 0x05]))
        if isinstance(target, str):
            self.buf.extend(b'\x00' * 4)
            self.fixups_rip.append((len(self.buf) - 4, target, self.pos + 7))
        else:
            self.buf.extend(struct.pack('<i', target - (self.pos + 7)))
        self.pos += 7

    # 条件跳转（0f 8x rel32），目标用标签
    def jcc(self, opcode: int, label: str) -> None:
        self.fixups_jcc.append((len(self.buf), label, self.pos))
        self.buf.extend(b'\x0f' + bytes([opcode]) + b'\x00' * 4)
        self.pos += 6

    # 无条件跳转（e9 rel32），目标用标签
    def jmp_label(self, label: str) -> None:
        self.fixups_jmp.append((len(self.buf), label, self.pos))
        self.buf.extend(b'\xe9\x00\x00\x00\x00')
        self.pos += 5

    # 无条件跳转（e9 rel32），目标用绝对地址
    def jmp_va(self, va: int) -> None:
        self.buf.extend(b'\xe9' + struct.pack('<i', va - (self.pos + 5)))
        self.pos += 5

    # 写一段原始字节（字符串等）
    def raw(self, data: bytes) -> None:
        self.buf.extend(data)
        self.pos += len(data)

    def finish(self) -> bytes:
        """回填所有 fixup 并返回最终机器码。"""
        for offset, label, end in self.fixups_jcc:
            target = self.labels[label]
            self.buf[offset + 2:offset + 6] = struct.pack('<i', target - (end + 6))
        for offset, label, end in self.fixups_jmp:
            target = self.labels[label]
            self.buf[offset + 1:offset + 5] = struct.pack('<i', target - (end + 5))
        for offset, label, end in self.fixups_rip:
            target = self.labels[label]
            self.buf[offset:offset + 4] = struct.pack('<i', target - end)
        return bytes(self.buf)


def build_cave(pe: pefile.PE, plan: dict, helper_path: str,
               stat_va: int, cave_va: int) -> bytes:
    """
    生成补丁代码。逻辑按顺序是：

      1. 计数器 +1（自证补丁真的被执行了）
      2. 保存被 hook 覆盖掉的原始指令所破坏的寄存器（本补丁只用易失寄存器，
         但为稳妥仍压栈全部）
      3. AllowSetForegroundWindow(-1) —— ⭐ 关键：**此刻本进程仍是前台进程**，
         这是唯一能让「授权」真正生效的时刻。错过这个瞬间，后面再怎么调都是空授权。
      4. CreateProcessW 拉起 helper（新进程才有前台权限去做「切走再切回」）
      5. 把探针写进 STAT 槽，便于事后判读
      6. 重放被覆盖的原始指令，跳回原流程的下一句
    """
    cb = CaveBuilder(cave_va)

    # ── 1. 计数器 ──
    cb.lea_rip('rcx', stat_va)
    cb.asm('inc qword ptr [rcx]')

    # ── 2. 保存寄存器 ──
    for reg in ('rbx', 'rbp', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'):
        cb.asm('push %s' % reg)
    cb.asm('sub rsp, 0x20')          # 影子空间，同时保持 16 字节对齐

    # ── 3. 授权（必须在前台身份还成立的时候做）──
    cb.asm('mov ecx, -1')            # ASFW_ANY
    cb.call_iat(API['ALLOWFG'])
    cb.lea_rip('rcx', stat_va)
    cb.asm('mov qword ptr [rcx + 0x10], rax')      # 记录授权是否成功

    cb.call_iat(API['GETFG'])
    cb.lea_rip('rcx', stat_va)
    cb.asm('mov qword ptr [rcx + 0x18], rax')      # 记录拉起 helper 时的前台窗口

    # ── 4. 拉起 helper ──
    cb.asm('sub rsp, 0xE0')                        # STARTUPINFOW(0x68) + PROCESS_INFORMATION(0x18) + 余量
    cb.asm('mov rdi, rsp')
    cb.asm('xor eax, eax')
    cb.asm('mov ecx, 0x1C')                        # 0x1C * 8 = 0xE0 字节清零
    cb.asm('rep stosq')
    cb.asm('mov dword ptr [rsp + 0x50], 0x68')     # STARTUPINFOW.cb
    cb.asm('lea rax, [rsp + 0x50]')
    cb.asm('mov qword ptr [rsp + 0x40], rax')      # 第 9 参：lpStartupInfo
    cb.asm('lea rax, [rsp + 0xB8]')
    cb.asm('mov qword ptr [rsp + 0x48], rax')      # 第 10 参：lpProcessInformation
    cb.asm('mov qword ptr [rsp + 0x20], 0')        # bInheritHandles = FALSE
    cb.asm('mov dword ptr [rsp + 0x28], 0x08000000')   # CREATE_NO_WINDOW
    cb.asm('mov qword ptr [rsp + 0x30], 0')        # lpEnvironment
    cb.asm('mov qword ptr [rsp + 0x38], 0')        # lpCurrentDirectory
    cb.asm('xor ecx, ecx')                         # lpApplicationName = NULL
    cb.lea_rip('rdx', 'sz_cmdline')                # lpCommandLine
    cb.asm('xor r8d, r8d')
    cb.asm('xor r9d, r9d')
    cb.call_iat(API['CREATEP'])
    cb.lea_rip('rcx', stat_va)
    cb.asm('mov qword ptr [rcx + 8], rax')         # 记录 CreateProcess 的返回值
    cb.asm('add rsp, 0xE0')

    # ── 5. 收尾：恢复寄存器 ──
    cb.asm('add rsp, 0x20')
    for reg in ('r15', 'r14', 'r13', 'r12', 'rdi', 'rsi', 'rbp', 'rbx'):
        cb.asm('pop %s' % reg)

    # ── 6. 重放被覆盖的原始指令，跳回 ──
    cb.raw(plan['stolen_bytes'])
    cb.jmp_va(plan['resume_va'])

    # ── 数据：命令行字符串 ──
    cb.label('sz_cmdline')
    cb.raw(('"%s"' % helper_path).encode('utf-16-le') + b'\x00\x00')

    code = cb.finish()
    if len(code) >= (stat_va - cave_va):
        raise SystemExit('补丁代码 %d 字节，超过了 STAT 槽偏移 %d，请调大间隔'
                         % (len(code), stat_va - cave_va))
    return code


# ─────────────────────────── PE 写回 ───────────────────────────

def patch_pe(src: str, out: str, helper_path: str, site_index: int | None,
             dry_run: bool) -> dict:
    """完整流程：定位 → 规划 → 生成 → 写回。返回一份报告字典。"""
    global API

    pe = load_pe(src)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # ── 幂等检测：已经有 .fix 段就认为打过 ──
    section_names = [s.Name.rstrip(b'\x00').decode('ascii', 'ignore') for s in pe.sections]
    if FIX_SECTION in section_names:
        return {'status': 'ALREADY_PATCHED', 'detail': '目标里已存在 %s 段' % FIX_SECTION}

    # ── 定位 TaskDialogIndirect 的 IAT 槽 ──
    slot = find_taskdialog_slot(pe)
    if slot is None:
        return {
            'status': 'NO_SLOT',
            'detail': '在 %s 里找不到序号 #%d（TaskDialogIndirect）的导入项。\n'
                      '可能这个应用没有用 comctl32 的 TaskDialog（那就不是这个 bug）。'
                      % (TASK_DLL, TASK_ORDINAL),
        }
    slot_va, slot_from = slot

    # ── 解析所需的其它 API ──
    API = resolve_apis(pe)
    missing = [name for name in WANTED_APIS.values() if name not in API]
    if missing:
        return {
            'status': 'MISSING_APIS',
            'detail': '目标缺少这些导入：%s' % ', '.join(missing),
        }

    # ── 找调用点 ──
    sites = scan_call_sites(pe, slot_va)
    if not sites:
        return {
            'status': 'NO_CALL_SITE',
            'detail': '找到了 IAT 槽 0x%X，但没扫到指向它的 call 指令。' % slot_va,
        }

    # 逐个规划，挑可行的
    plans = []
    for va in sites:
        plan = plan_hook(pe, va)
        plan['va'] = va
        plans.append(plan)
    usable = [p for p in plans if p['ok']]

    if not usable:
        lines = ['找到 %d 个调用点，但没有一个能安全打 hook：' % len(sites)]
        for p in plans:
            lines.append('  0x%X → %s' % (p['va'], p.get('reason', '?')))
        return {'status': 'NO_USABLE_SITE', 'detail': '\n'.join(lines)}

    if site_index is None:
        if len(usable) > 1:
            lines = ['发现 %d 个可用的调用点，请用 --site <序号> 指定要打哪一个：' % len(usable)]
            for i, p in enumerate(usable):
                lines.append('  [%d] call@0x%X → hook@0x%X，吞 %d 字节'
                             % (i, p['call_va'], p['hook_va'], p['stolen_len']))
            return {'status': 'AMBIGUOUS', 'detail': '\n'.join(lines)}
        plan = usable[0]
    else:
        if not 0 <= site_index < len(usable):
            return {'status': 'BAD_SITE',
                    'detail': '--site %d 超范围（可用 0..%d）' % (site_index, len(usable) - 1)}
        plan = usable[site_index]

    # ── 规划新段 ──
    last = pe.sections[-1]
    new_va = align(last.VirtualAddress + max(last.Misc_VirtualSize, last.SizeOfRawData), SECT_ALIGN)
    new_raw = align(os.path.getsize(src), FILE_ALIGN)
    cave_va = image_base + new_va
    stat_va = cave_va + 0x600            # 探针槽：必须落在补丁代码之后

    code = build_cave(pe, plan, helper_path, stat_va, cave_va)

    report = {
        'status': 'OK',
        'slot_va': slot_va,
        'slot_from': slot_from,
        'call_va': plan['call_va'],
        'hook_va': plan['hook_va'],
        'stolen_len': plan['stolen_len'],
        'resume_va': plan['resume_va'],
        'cave_va': cave_va,
        'stat_va': stat_va,
        'code_len': len(code),
        'sites_found': len(sites),
        'sites_usable': len(usable),
        'helper': helper_path,
        'guard_cf_before': pe.OPTIONAL_HEADER.DllCharacteristics,
    }

    if dry_run:
        return report

    # ── 写盘 ──
    if os.path.abspath(src) == os.path.abspath(out):
        raise SystemExit('输入与输出不能是同一个文件；请先输出副本再安装。')
    shutil.copy2(src, out)

    section_size = align(max(len(code), 0x800), FILE_ALIGN)

    with open(out, 'r+b') as fh:
        e_lfanew = pe.DOS_HEADER.e_lfanew
        opt_size = pe.FILE_HEADER.SizeOfOptionalHeader
        n_sections = pe.FILE_HEADER.NumberOfSections

        # 1) 追加段头
        section_table = e_lfanew + 4 + 20 + opt_size + n_sections * 40
        fh.seek(section_table)
        fh.write(struct.pack(
            '<8sIIIIIIHHI',
            FIX_SECTION.encode().ljust(8, b'\x00'),
            section_size,          # VirtualSize
            new_va,                # VirtualAddress
            section_size,          # SizeOfRawData
            new_raw,               # PointerToRawData
            0, 0, 0, 0,            # 重定位/行号指针（此段不需要）
            FIX_SECTION_CHARS,
        ))

        # 2) 写入段内容
        fh.seek(new_raw)
        fh.write(code)
        fh.write(b'\x00' * (section_size - len(code)))

        # 3) 安装 hook（覆盖 hook 点起 stolen_len 字节）
        hook_off = va_to_file_offset(pe, plan['hook_va'])
        if hook_off is None:
            raise SystemExit('算不出 hook 点的文件偏移')
        fh.seek(hook_off)
        original = fh.read(plan['stolen_len'])
        expected = plan['stolen_bytes']
        if original != expected:
            raise SystemExit('hook 点字节与预期不符：实际 %s / 预期 %s'
                             % (original.hex(), expected.hex()))
        jump = b'\xe9' + struct.pack('<i', cave_va - (plan['hook_va'] + 5))
        if plan['stolen_len'] > 5:
            jump += b'\x90' * (plan['stolen_len'] - 5)     # NOP 补齐
        fh.seek(hook_off)
        fh.write(jump)

        # 4) 清 GUARD_CF
        #    新段里的代码不是 CFG 的合法间接调用目标；不清掉的话，
        #    一旦有回调式调用进入这一区，进程会直接 __fastfail（0xC0000409）。
        dc_off = e_lfanew + 4 + 20 + 70
        fh.seek(dc_off)
        dc = struct.unpack('<H', fh.read(2))[0]
        fh.seek(dc_off)
        fh.write(struct.pack('<H', dc & ~GUARD_CF))
        report['guard_cf_after'] = dc & ~GUARD_CF

        # 5) 段数 +1
        fh.seek(e_lfanew + 4 + 2)
        fh.write(struct.pack('<H', n_sections + 1))

        # 6) 修正 SizeOfImage（可选头偏移 56）
        fh.seek(e_lfanew + 4 + 20 + 56)
        fh.write(struct.pack('<I', align(new_va + section_size, SECT_ALIGN)))

    # 7) 重算 PE 校验和（可选头偏移 64）
    with open(out, 'r+b') as fh:
        fh.seek(e_lfanew + 4 + 20 + 64)
        fh.write(struct.pack('<I', 0))
    patched = pefile.PE(out)
    checksum = patched.generate_checksum()
    del patched
    with open(out, 'r+b') as fh:
        fh.seek(e_lfanew + 4 + 20 + 64)
        fh.write(struct.pack('<I', checksum))
    report['checksum'] = checksum

    return report


def va_to_file_offset(pe: pefile.PE, va: int) -> int | None:
    """虚拟地址 → 文件偏移。"""
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        span = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if section.VirtualAddress <= rva < section.VirtualAddress + span:
            return section.PointerToRawData + (rva - section.VirtualAddress)
    return None


def resolve_apis(pe: pefile.PE) -> dict[str, int]:
    """按「DLL!函数」收集需要的 API 的 IAT 槽地址（大小写不敏感）。"""
    found: dict[str, int] = {}
    for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in getattr(pe, attr, None) or []:
            try:
                dll = entry.dll.decode('ascii', 'ignore').upper()
            except Exception:
                continue
            for imp in entry.imports:
                if imp.name is None:
                    continue
                key = (dll + '!' + imp.name.decode('ascii', 'ignore')).upper()
                if key in WANTED_APIS:
                    found[WANTED_APIS[key]] = imp.address
    return found


API: dict[str, int] = {}


# ─────────────────────────── 安装 / 回滚 ───────────────────────────

def backup_path(target: str) -> str:
    """备份文件名：<原名>.bak-focusfix-<日期>。"""
    return '%s.bak-focusfix-%s' % (target, time.strftime('%Y%m%d'))


def install(patched: str, target: str) -> str:
    """把打过补丁的副本装到目标位置（先备份）。"""
    bak = backup_path(target)
    if not os.path.exists(bak):
        shutil.copy2(target, bak)
    shutil.copy2(patched, target)
    return bak


# ─────────────────────────── 命令行 ───────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description='给 Electron 应用打「原生对话框后键盘失效」修复补丁（自动定位补丁点）',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--exe', help='目标 exe（默认自动探测；也可用环境变量 %s）' % ENV_EXE)
    parser.add_argument('--out', help='输出副本路径（默认 <exe>.patched.exe）')
    parser.add_argument('--helper', help='helper 可执行文件（默认在 exe 同目录/脚本目录找；'
                                         '也可用环境变量 %s）' % ENV_HELPER)
    parser.add_argument('--site', type=int, default=None,
                        help='有多个可用调用点时，指定要打哪一个（从 0 开始）')
    parser.add_argument('--probe', action='store_true', help='只探测，不写盘')
    parser.add_argument('--install', action='store_true', help='生成后直接安装到目标位置（先备份）')
    args = parser.parse_args()

    target = find_target_exe(args.exe)
    print('目标 exe : %s' % target)
    print('文件大小 : %d 字节' % os.path.getsize(target))

    helper = find_helper(args.helper, os.path.dirname(target))
    if helper:
        print('helper   : %s' % helper)
    else:
        print('helper   : 未找到！补丁仍可生成，但运行时必须能在这个路径找到它：')
        print('           请在 exe 同目录放 focus-helper.exe，或用 --helper 指定')

    out = args.out or (target + '.patched.exe')

    report = patch_pe(target, out, helper or 'focus-helper.exe', args.site, args.probe)

    print('')
    print('=== 结果 ===')
    status = report['status']
    if status != 'OK':
        print('  %s' % status)
        print('  %s' % report.get('detail', ''))
        return 1

    print('  IAT 槽（TaskDialogIndirect） : 0x%X（来自%s）'
          % (report['slot_va'], report['slot_from']))
    print('  调用点                       : 0x%X' % report['call_va'])
    print('  hook 点                      : 0x%X（吞 %d 字节）'
          % (report['hook_va'], report['stolen_len']))
    print('  恢复执行地址                 : 0x%X' % report['resume_va'])
    print('  .fix 段                      : 0x%X，代码 %d 字节'
          % (report['cave_va'], report['code_len']))
    print('  探针槽                       : 0x%X' % report['stat_va'])
    print('  可用调用点                   : %d / 共 %d'
          % (report['sites_usable'], report['sites_found']))

    if args.probe:
        print('  （--probe：没有写盘）')
        return 0

    print('  输出                         : %s' % out)
    print('  PE 校验和                    : 0x%X' % report.get('checksum', 0))
    print('  GUARD_CF                     : 0x%X → 0x%X'
          % (report['guard_cf_before'], report.get('guard_cf_after', 0)))

    if args.install:
        bak = install(out, target)
        print('  已安装到目标位置；备份：%s' % bak)
        print('  请重启应用使其生效。')

    return 0


if __name__ == '__main__':
    sys.exit(main())
