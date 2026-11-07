---
id: code-analysis-reverse-firmware-vxworks-symbol-table-base
title: VxWorks 符号表/字符串表恢复加载基址：符号名地址减字符串偏移 + IDA 脚本恢复函数名
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: vxworks-base-symbol-table
aliases:
- VxWorks 符号表
- 字符串表基址
- vxhunter
- VxWorksSymTab_Finder
- VxWorksSymtab_Tab
- 符号恢复
- symtab
tags:
- reverse
- firmware
- vxworks
- symbol-table
- base-address
- ida
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:15:21+08:00'
  notes: 已对照原文与截图核对：M241 0x8EAC88-0xE8CC8=0x801FC0、NOE-771 0x27656C-0x26656C=0x10000、20 字节符号表条目与 IDA 恢复脚本均一致；原文无受影响版本；未实际运行脚本。
---

## 一句话结论

VxWorks 固件常保留符号表：每条记录含“符号名字符串地址 + 函数/变量地址 + 类型”等字段；找到符号表首条记录的名字地址，再找到字符串表首/尾字符串的文件偏移，二者相减即加载基址；rebase 后用 IDA 脚本按符号表批量创建字符串/函数名，即可把 `sub_XXX` 恢复成 `usrInit`、`cacheFlush` 等真实符号。

## 原理

- VxWorks 5.x 的符号表条目通常为 20 字节：`char *name`、`void *value`、`int type`、`struct symEntry *next`；6.x/7.x 结构不同（含 flags/module/section/size 等），需按版本解析。
- 符号表中的 `name` 是字符串表内的绝对地址，`value` 是函数/变量的运行时绝对地址；固件按 0 基址加载时，这些绝对地址都带同一个基址偏移。
- 基址推导：`base = 符号表首条 name 地址 - 字符串表首字符串文件偏移`（或 `符号表末条 name 地址 - 字符串表末字符串偏移`，取决于绑定顺序）。示例 M241：`0x8EAC88 - 0xE8CC8 = 0x801FC0`，页对齐 0x801000；示例 NOE-771：`0x27656C - 0x26656C = 0x10000`。
- 不同固件的符号表绑定顺序不同：有的第一条记录绑定字符串表第一个字符串，有的绑定最后一个；需要对照字符串表内容与 name 地址递增/递减关系确认。
- binwalk 可能报告符号表地址，但可能不准；用 vxhunter、VxWorksSymTab_Finder、Ghidra VxWorksSymtab_Tab 或 010 Editor 人工确认符号表起始与条目大小。
- rebase 后运行 IDA 脚本：遍历符号表，读取 name 地址与 value 地址，创建字符串、设置函数名、创建函数；遇到无效条目（0/0xFFFFFFFF/不在段内）跳过。

## 触发条件

- 固件为 VxWorks（binwalk 可见 `VxWorks WIND kernel version`、`VxWorks symbol table` 等）。
- 符号表/字符串表未被剥离或仍可在固件中定位。
- IDA 以 0 基址加载，函数显示为 `sub_XXX`。
- 能确定符号表条目大小与字段偏移（按 VxWorks 5.x/6.x/7.x 版本）。

## 利用步骤

1. `binwalk firmware.bin` 查看 VxWorks 版本、符号表/字符串表线索；`binwalk -A` 确认架构/大小端。
2. 用 vxhunter/VxWorksSymTab_Finder 扫描，记录符号表起始偏移、条目大小、字符串表范围；binwalk 结果需人工复核。
3. 在十六进制视图查看符号表首条记录：第一个字段是 name 指针，第二个字段是 value 指针，随后是 type/next（5.x）。
4. 在字符串表中找到第一个（或最后一个）字符串的文件偏移；用 `name_addr - string_offset` 计算候选基址，页对齐。
5. 在 IDA 中 rebase 到该基址，重新运行符号恢复脚本；检查函数名是否合理（usr*、cache*、任务/驱动函数）。
6. 若恢复失败，换字符串表首/尾、检查大小端/条目大小、确认符号表起始是否偏移。
7. 保存 IDA 数据库/导出符号，继续漏洞挖掘。

## PoC

```python
# IDA Python 符号恢复核心（按实际 loadaddress/eaStart/eaEnd/ENTRY_SIZE 调整）
from idaapi import *
import ida_bytes, ida_ua, ida_funcs, ida_segment, idc

loadaddress = 0x801000
eaStart = 0x1204E0 + loadaddress
eaEnd   = 0x137890 + loadaddress
ENTRY_SIZE = 20

ea = eaStart
while ea < eaEnd:
    str_addr = ida_bytes.get_32bit(ea + 4)
    eaFunc   = ida_bytes.get_32bit(ea + 8)
    if str_addr in (0, 0xFFFFFFFF) or eaFunc in (0, 0xFFFFFFFF):
        ea += ENTRY_SIZE
        continue
    if ida_segment.getseg(str_addr) is None or ida_segment.getseg(eaFunc) is None:
        ea += ENTRY_SIZE
        continue
    ida_bytes.create_strlit(str_addr, 256, idc.STRTYPE_C)
    s = idc.get_strlit_contents(str_addr)
    name = s.decode("utf-8", "ignore") if s else "sub_{:X}".format(eaFunc)
    idc.set_name(eaFunc, name, idc.SN_NOWARN)
    if not ida_bytes.is_code(ida_bytes.get_full_flags(eaFunc)):
        ida_ua.create_insn(eaFunc)
    if not ida_funcs.get_func(eaFunc):
        ida_funcs.add_func(eaFunc)
    ea += ENTRY_SIZE
```

## 变体与关联

- 变体：VxWorks 6.x/7.x 符号表结构不同（name/value/type/flags/module/section/size），需按版本调整字段偏移与条目大小。
- 变体：大端/小端固件读取字段时要用对应字节序；示例 NOE-771 为大端。
- 变体：符号表被剥离时改用跳转表/SP/BSS 法恢复基址，再靠字符串/函数特征人工命名。
- 关联：[[code-analysis-reverse-firmware-vxworks-base-jump-table]]（跳转表法）、[[code-analysis-reverse-firmware-vxworks-base-sp-bss]]（SP/BSS 法）、[[code-analysis-reverse-firmware-stm32-hal-function-identification]]（固件函数识别）。

## 检测与防御

- 检测：固件中残留 VxWorks 符号表/字符串表、`usrInit`/`cacheFlush` 等符号名。
- 防御：发布固件时剥离符号表、去除调试信息；但字符串/函数特征仍可能泄露语义。
- 响应：确认符号泄露后，评估敏感函数/密钥暴露，升级固件保护与代码混淆。
