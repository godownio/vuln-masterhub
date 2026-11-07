---
id: tools-ida-kernel-source-struct-import-decompiler-cleanup
title: 内核驱动逆向：用源码结构体在 IDA Local Types 导入并校正 Hex-Rays 反编译
type: scenario
domain: tools
path: tools/ida
technique: ida-kernel-source-struct-import-decompiler-cleanup
aliases:
- IDA 内核结构体恢复
- Local Types 导入结构体
- Hex-Rays 参数混乱修复
- 源码辅助反编译
- set_local_type
tags:
- ida
- idapython
- hexrays
- kernel
- reverse
- struct-recovery
- decompiler
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T11:38:45+08:00'
  notes: 已对照原文核对：idc.set_local_type(-1, decl, idc.PT_TYP) 导入 typedef/结构体、builtin 回退、SetType 应用原型、F5 刷新、按偏移核对 Hex-Rays、err() 非终止导致误判等均与原文方法一致；属工具工作流卡而非攻击链。未验证点：未在 IDA 中实际执行脚本；frontmatter 无 sources/source_url。
---

## 一句话结论

分析带源码的内核驱动时，先在 IDA 的 Local Types 中用 IDAPython 导入 `request_t`、`queue`、`queue_entry` 等结构体，再用 `SetType` 给 `create/edit/save/delete/ioctl` 应用正确函数原型；Hex-Rays 会立刻把 `a1+偏移` 还原成字段访问，尺寸计算、整数回绕和越界拷贝位置变得可读。IDA 常把源码多行合并或单行拆分并复用局部变量，读反编译结果要按结构体偏移和内存布局，而不是按变量名。

## 原理

- **反编译为什么乱**：内核模块通常没有 DWARF/BTF 类型信息，Hex-Rays 只能从指针算术推断类型；同一块内存被不同函数当作不同结构体时，反编译器会把字段访问显示成 `*(_QWORD *)(a1 + 8)`、`WORD2(x)`、`HIWORD(x)` 等，参数也会被错误地拆成多个。
- **Local Types 的作用**：`idc.set_local_type(-1, decl, idc.PT_TYP)` 把 C 声明解析进 IDA 的类型库；之后对函数地址 `idc.SetType(ea, "queue *create_kqueue(request_t *req)")` 应用原型，Hex-Rays 重新分析时使用这些类型，字段名和结构体边界就能显示出来。
- **结构体布局决定漏洞**：本题 `queue_size = 24 * (max_entries + 1) + 0x20` 说明 `queue` 头（0x20）后紧跟 `queue_entry` 数组（每个 0x18）；`queue->data` 与 `entry->data` 是另分配的缓冲区。只有恢复出这个布局，才能看出 `max_entries=0xffffffff` 回绕后“只分配 0x20、却仍保存 0xffffffff”的矛盾。
- **反编译器的合并/拆分**：源码一行 `prev_entry->next = current_entry; prev_entry = prev_entry->next;` 可能被合并成自引用；源码两行可能被拆成多个临时变量。`v10` 在不同基本块可能被复用为 `queue*` 或 `queue_entry*`，不能据变量名判断类型，应按 `queue`/`queue_entry` 的字段偏移核对。
- **错误处理的影响**：驱动里的 `err()` 只 `printk` 不返回，反编译中看起来像“检查失败就报错”，实际会继续执行；审计时要把这类函数标记为“非终止”，否则会误判漏洞不可达。

## 触发条件

- 目标内核模块有源码、头文件或可通过分配大小/偏移推断出的结构体。
- Hex-Rays 输出中存在大量 `a1 + 常数`、`WORD2/HIWORD`、`*(_QWORD *)`，函数参数数量与源码明显不符。
- 需要审计尺寸计算、结构体字段边界、函数指针偏移或链表遍历。

## 利用步骤

1. 从源码提取所有相关 typedef（如 `request_t`、`queue`、`queue_entry`），注意 `stdint.h` 类型在 IDA 中可能缺失，准备 `unsigned __int16/32/64` 的备用声明。
2. 用 IDAPython 逐个 `set_local_type(-1, decl, idc.PT_TYP)` 导入；先导入 typedef 别名，再导入结构体，失败时回退到 builtin 版本。
3. 对每个函数 `idc.SetType(ea, "返回类型 函数名(参数列表)")` 应用原型；至少覆盖 ioctl 分发入口和 create/edit/save/delete 四个操作。
4. 重新按 F5 刷新 Hex-Rays，检查字段是否按预期展开；若仍有字段错位，用 `idc.get_struc`/`ida_struct` 检查成员偏移与对齐（`u16` 后的 padding、`u64` 对齐）。
5. 对照源码逐行核对：分配大小表达式、`copy_from_user` 长度、边界检查是否终止、链表 `next` 更新顺序。
6. 用 GDB 在 `kmalloc`/`kzalloc` 返回处和关键字段写入处下断点，验证运行时偏移与 IDA 结构体一致；必要时用 `ptype`/`print` 查看结构体。

## PoC

```python
import idc, ida_kernwin

def add_type(decl):
    try:
        return idc.set_local_type(-1, decl, idc.PT_TYP) != 0
    except Exception:
        return False

# 1) stdint 别名（已存在会失败，忽略）
add_type("typedef unsigned __int16 uint16_t;")
add_type("typedef unsigned __int32 uint32_t;")
add_type("typedef unsigned __int64 uint64_t;")

# 2) 结构体
add_type("""
typedef struct request_t {
    uint32_t max_entries;
    uint16_t data_size;
    uint16_t entry_idx;
    uint16_t queue_idx;
    char *data;
} request_t;
""")
add_type("""
typedef struct queue {
    uint16_t data_size;
    uint64_t queue_size;
    uint32_t max_entries;
    uint16_t idx;
    char *data;
} queue;
""")
add_type("""
typedef struct queue_entry {
    uint16_t idx;
    char *data;
    struct queue_entry *next;
} queue_entry;
""")

# 3) 函数原型（地址用 idc.get_name_ea_simple 获取）
for name, proto in {
    "kqueue_ioctl": "__int64 kqueue_ioctl(__int64 file, unsigned int cmd, __int64 arg)",
    "create_kqueue": "__int64 create_kqueue(request_t *req, __int64 arg)",
    "save_kqueue_entries": "__int64 save_kqueue_entries(request_t *req, __int64 arg)",
    "edit_kqueue": "__int64 edit_kqueue(request_t *req, __int64 arg)",
    "delete_kqueue": "__int64 delete_kqueue(request_t *req, __int64 arg)",
}.items():
    ea = idc.get_name_ea_simple(name)
    if ea not in (idc.BADADDR, -1):
        idc.SetType(ea, proto)

ida_kernwin.info("types imported; reopen Hex-Rays view (F5)")
```

实际函数的参数个数/类型以源码为准；上面的原型是示例，应用前要按目标签名调整，否则 `SetType` 可能解析失败或产生新的错位。

## 变体与关联

- **无源码**：按 `kmalloc` 大小、字段访问偏移、`copy_from_user` 长度反推结构体；对“头 + 变长数组”布局，重点确认数组元素大小与头大小。
- **C++ 驱动**：先恢复 vtable/虚函数表，再用 `ida_typeinf` 导入 class；虚表偏移与 RTTI 可辅助确认字段。
- **BTF/DWARF 可用**：优先导入 BTF/DWARF 类型（`vmlinux` 的 BTF、模块的 debug info），比手工 typedef 更准确。
- **与 exploit 卡片的配合**：结构体恢复后，把字段代入尺寸表达式即可发现整数回绕/长度不一致；本库 `binary-pwn-kernel-kqueue-maxentries-intwrap-seqops-ret2usr` 是完整案例。

## 检测与防御

- 对分析者：建立“先类型、后逻辑”的习惯，任何 `a1 + 常数` 都先问“这是哪个结构体的哪个字段”；不要直接相信 Hex-Rays 的变量名和参数个数。
- 对防御方（驱动开发者）：发布时剥离调试符号和源码路径只能增加逆向成本，不能替代安全设计；真正的防御是尺寸检查、边界校验和失败即终止。
- 对 CTF/样本分析：若 `err()`/`printk` 类函数不终止流程，应在反编译中标注为“非致命”，否则会漏掉可触发的漏洞路径。
