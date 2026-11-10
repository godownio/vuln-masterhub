---
id: code-analysis-reverse-obfuscation-salted-fnv1a-api-hash-resolve
title: 加盐 FNV-1a API 哈希解析：字符串哈希后再哈希 4 字节盐，遍历导出表缓存函数指针
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: salted-fnv1a-api-hash-resolve
aliases:
- 加盐 FNV1a
- FNV-1a API hash
- salt CB24B4BA
- 动态解析 API
- ResolveImport
tags:
- reverse
- api-hash
- fnv1a
- salt
- import-resolution
- obfuscation
- windows
- malware
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T07:52:13+08:00'
  notes: 已对照原文与21张图核对：FNV-1a seed 0x811C9DC5/prime 0x01000193、先哈希名称再哈希盐、ResolveImport 哈希常量(0xFE0B07B0/0xCA7BB6AC)与盐字节序差异均与原文一致；PEB/导出表遍历为基于样本行为的合理补充描述；PoC未执行
---

## 一句话结论

样本不在导入表或明文字符串里暴露 API 名，而是对 DLL 名和函数名分别做 32 位 FNV-1a（seed `0x811C9DC5`、prime `0x01000193`），再把 4 字节盐继续哈希，遍历 PEB 已加载模块的导出表按哈希比对，把解析出的函数指针写入结构体供后续间接调用；盐让不同样本/版本的哈希值不同，标准哈希库无法直接反查。

## 原理

- **FNV-1a 基础**：32 位 FNV-1a 以 `hash = 0x811C9DC5` 开始，对每个字节执行 `hash ^= byte; hash *= 0x01000193`（32 位截断）。它对输入顺序敏感、实现简单，是恶意样本隐藏 API 名的常见选择。
- **加盐步骤**：样本先对输入字符串（DLL 名或函数名）做一遍 FNV-1a，再对紧跟的 4 字节盐值继续做同样的 `xor/mul`，等价于对 `name || salt` 做 FNV-1a。盐是样本级常量（原文为 `CB 24 B4 BA`；其 Python 实现按内存小端写作 `BA B4 24 CB`），换样本/换版本就换盐，因此攻击者预先算好的“API 名→哈希”表无法直接命中。
- **解析流程**：`ResolveImport(L"ntdll", dll_hash, func_hash)` 先按 DLL 名哈希在 PEB `InMemoryOrderModuleList` 中找到模块基址，再解析 PE 导出目录的 `AddressOfNames` / `AddressOfFunctions` / `AddressOfNameOrdinals`，对每个导出名计算加盐哈希并与目标值比对，命中后返回函数地址；例如 `sImportTable->ntdll_LdrLoadDll = ResolveImport(L"ntdll", 0xFE0B07B0, 0xCA7BB6AC)`。
- **为什么要缓存到结构体**：解析结果按固定偏移写入自定义导入表结构体（函数指针数组），后续代码通过结构体成员间接调用，既避免在代码里反复解析，也让静态分析难以从调用点直接看出 API 名。
- **为什么能规避静态检测**：导入表里没有敏感 API、`.rdata` 里没有 API 字符串，只剩若干 32 位整数常量；检测方必须识别出 FNV-1a 常量/循环与盐值，才能反查哈希。分析和检测的突破口正是 `0x811C9DC5`、`0x01000193`、盐常量以及 `ResolveImport` 的调用参数。

## 触发条件

- Windows PE 或 shellcode 具备自定义 PE 解析/PEB 访问能力；无需 `LoadLibrary`/`GetProcAddress` 导入。
- 样本中能找到 FNV-1a 常量（`0x811C9DC5`、`0x01000193`）和 4 字节盐常量；盐可能与代码/数据一起加密，需先解密。
- 目标 API 名在常见 DLL 导出表中（ntdll/kernel32/advapi32 等），可用字典/导出表枚举反查。
- 样本未阻止 PEB 遍历或导出表解析（常规用户态进程即可）。

## 利用步骤

> 本卡为逆向分析/实现视角；“利用步骤”即识别与还原流程。

1. 在样本中搜索 `0x811C9DC5` 与 `0x01000193`，定位哈希循环；观察循环结束后是否还有一段对固定 4 字节的同样 `xor/mul`，即盐值。
2. 记录盐的字节序：按内存实际读取顺序取盐（原文文字标 `CB 24 B4 BA`，其 Python 实现按小端写 `BA B4 24 CB`），顺序错一位哈希就全错。
3. 找到 `ResolveImport(dll_name, dll_hash, func_hash)` 的调用点，导出所有目标哈希常量。
4. 用 Python/Go 复现加盐 FNV-1a，对常见 DLL/API 名字典或目标 DLL 的导出表逐个计算哈希，建立“哈希→名称”映射。
5. 把映射写回 IDA 注释/结构体成员，恢复 `sImportTable->ntdll_LdrLoadDll` 等间接调用；对无法反查的哈希，扩大字典（含 `Nt*`/`Zw*`、序号导出、转发导出）。
6. 若盐被加密或运行时生成，在调试器中于哈希循环入口下断，直接读出盐与目标哈希，再离线反查。

## PoC

加盐 FNV-1a 的 Python 复现（与原文 Go 实现等价）：

```python
def fnv1a_salted(data: bytes, salt: bytes, seed: int = 0x811C9DC5) -> int:
    h = seed
    for b in data + salt:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

# 原文文字盐值 CB 24 B4 BA；按其 Python 实现取小端字节
salt = bytes([0xBA, 0xB4, 0x24, 0xCB])
print(hex(fnv1a_salted(b"ntdll", salt)))        # 对应 0xFE0B07B0 一类的 DLL 哈希
print(hex(fnv1a_salted(b"LdrLoadDll", salt)))   # 对应 0xCA7BB6AC 一类的函数哈希
```

IDA/分析侧：以 `0x811C9DC5`/`0x01000193` 定位循环，按 `ResolveImport` 的第二个/第三个参数收集目标哈希，再批量反查。

## 变体与关联

- **变体**：盐可以是 4/8 字节常量、运行时生成（时间/文件名/机器码）或分两段加入；哈希算法可换成 CRC32+XOR、ROR13、自定义多项式；解析目标可以是 PEB 模块链表、`LdrLoadDll`、或直接解析已映射模块的导出表。
- **关联卡片**：[[code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key]]（CRC32+XOR 的 API hash）；[[code-analysis-reverse-obfuscation-shellcode-api-hash-ror13-blobrunner]]（ROR13 类 shellcode API hash）；[[pentest-c2-iat-hidden-peb-walk-api-hash-crt-free]]（PEB/导出表遍历 + 自实现 GetProcAddress 的 IAT 隐身）；[[pentest-c2-module-unhooking-pdata-runtime-function-fnv1a]]（同样用 FNV-1a，但用于 .pdata 函数字节比对脱钩，不是 API 名解析）。
- 区分：CTF 里的 FNV-1a 卡多用于输入校验/跳表，不是 API 解析。

## 检测与防御

- **静态检测**：扫描二进制中的 `0x811C9DC5`/`0x01000193` 常量与“字符串→哈希→导出表遍历”模式；监控样本是否导入 `LoadLibrary`/`GetProcAddress` 却仍能调用大量 API（导入表异常干净）。
- **动态检测**：监控 PEB 遍历、导出表解析、短时间大量 `LdrLoadDll`/手工映射行为；对“函数指针来自结构体偏移而非导入表”的间接调用链做告警。
- **分析侧**：用 IDA 脚本/哈希库（支持自定义盐与算法）批量反查；对加密盐先在调试器断点读出。
- **防御**：EDR 对敏感 API 的用户态 hook 与内核回调不依赖导入表，仍能覆盖间接调用；限制未知 PE 的内存加载与 PEB 异常访问。
