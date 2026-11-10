---
id: code-analysis-reverse-windows-driver-cdata-xor-api-resolution
title: 内核驱动 .cdata 段 4 字节 XOR（key 0x9D802CB0）加密 API 名还原：IDA Python 解段 + 动态解析 Zw*/内核例程地址
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: driver-cdata-xor-encrypted-api-name-resolution
aliases:
- .cdata XOR 解密
- 4 字节异或密钥 0x9D802CB0
- IDA Python 段解密
- 动态解析内核 API
- 加密 API 名
- Festi .cdata
tags:
- reverse
- windows
- kernel
- rootkit
- string-decryption
- xor
- idapython
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:37:41+08:00'
  notes: 已对照原文 content.md 与 33 张图片逐项核对（Festi 样本分析）；六卡分别对应文件系统过滤隐藏/SSDT 注册表隐藏/直发 IRP 通信/.cdata XOR API 名/DR 寄存器反调试/日期种子 DGA，各自技术原子独立、判为原子粒度合格；与 dup-scan 中同文 related pair 并列保留（机制与触发不同）；未动态运行驱动/样本。
---

## 一句话结论

Festi 把 `ZwDeleteFile`、`ZwClose`、`ZwCreateKey` 等 API 名字符串以 4 字节为块、用固定 32 位密钥 `0x9D802CB0` 做 XOR 存放在 `.cdata` 段，加载时在 `ResolveKernelApiAddresses` 中解密并通过内核导出解析函数取地址存入全局指针；分析时用 IDA Python 遍历 `.cdata`、按小端密钥逐 4 字节 XOR 并 `patch_bytes` 写回，即可批量还原所有加密 API 名并定位调用点。

## 原理

- **加密形式**：字符串不是明文，而是与 4 字节密钥 `0x9D802CB0`（小端字节 `B0 2C 80 9D`）按块异或；由于密钥长度 4，每 4 个字节重复一次，密文呈现周期性/高熵，静态字符串搜索找不到 `ZwCreateKey` 等敏感名。
- **解密位置**：`ResolveKernelApiAddresses` 调用 `sub_1D620(byte_XXXX)` 之类的解析函数，把解密后的名字传给 `MmGetSystemRoutineAddress` 或导出表解析，得到函数指针存入 `dword_16E68` 等全局变量；驱动随后通过这些指针调用 `ZwDeleteFile`/`ZwClose`/`ZwCreateKey`，避免在导入表留下敏感 API。
- **IDA Python 解密**：文章脚本遍历 `idautils.Segments()` 找 `.cdata`，读取段字节，`key.to_bytes(4,'little')`，按 `i%4` 异或每个字节，`ida_bytes.patch_bytes(start, bytes(result))` 写回；写回后 IDA 反汇编/字符串视图就能看到真实 API 名与引用。
- **为什么用固定 XOR**：实现简单、无需密钥分发/复杂算法，足以躲过基于明文字符串的查杀与人工 grep；但密钥硬编码在驱动中，分析者只要找到解密循环或试常见密钥即可还原。
- **分析价值**：还原后能看到驱动实际使用的内核 API 集合（文件删除、注册表、对象管理、网络），快速画出能力面并定位关键函数。

## 触发条件

- 驱动样本的 `.cdata`/`.rdata` 段存在高熵、周期性 4 字节模式，或 `ResolveKernelApiAddresses` 中出现对同一段地址的批量解析。
- 可定位解密循环/密钥常量（如 `0x9D802CB0`），或通过试错/已知明文（`Zw` 开头）推断密钥。
- 使用 IDA/Ghidra 与 Python 脚本环境；样本未加壳/未做二次加密。
- 仅用于授权恶意样本分析；不运行驱动。

## 利用步骤

1. 在 IDA 中查看段表，找 `.cdata` 段；用 Entropy/十六进制视图确认高熵/4 字节周期。
2. 搜索 `ResolveKernelApiAddresses`/批量 `sub_1D620` 调用；定位解密函数与密钥常量（文章为 `0x9D802CB0`）。
3. 运行 IDA Python 脚本：遍历段、按 4 字节小端密钥 XOR、`patch_bytes` 写回。
4. 重新分析：字符串窗口应出现 `ZwDeleteFile`/`ZwClose`/`ZwCreateKey` 等；对每个字符串取 xref，定位解析后的全局函数指针与调用点。
5. 建立 API 能力表（文件/注册表/对象/网络），标记可疑组合（如 `ZwDeleteFile` + 文件隐藏、`ZwCreateKey` + 服务持久化）。
6. 交叉验证：动态调试时在解析函数/`MmGetSystemRoutineAddress` 下断，确认解密后的名字与指针。

## PoC

```python
import idaapi, idautils, idc

XOR_KEY = 0x9D802CB0

def xor_data(data, key):
    kb = key.to_bytes(4, byteorder='little')
    out = bytearray(len(data))
    for i in range(0, len(data), 4):
        for j in range(4):
            if i + j < len(data):
                out[i + j] = data[i + j] ^ kb[j]
    return out

for seg in idautils.Segments():
    if idc.get_segm_name(seg) == ".cdata":
        start, end = idc.get_segm_start(seg), idc.get_segm_end(seg)
        blob = idaapi.get_bytes(start, end - start)
        if blob:
            ida_bytes.patch_bytes(start, bytes(xor_data(bytearray(blob), XOR_KEY)))
            print(f"patched .cdata {hex(start)}-{hex(end)}")
        break
```

## 变体与关联

- 变体：密钥可能不是固定 4 字节，而是 8/16 字节、按索引变化、与段地址/时间异或；先找解密循环，再用已知明文（`Zw`/`\Device`）反推。
- 变体：字符串可能分片存放、运行时拼接、或使用哈希（如 API hash）而非明文；此时需按哈希算法枚举/查表。
- 变体：除 `.cdata` 外，`.rdata`/`.data`/资源段也可能存加密字符串；脚本可遍历所有非代码段。
- 关联：[[code-analysis-reverse-windows-rootkit-fs-filter-attach-hide-file]]（同一样本的文件隐藏能力）、[[code-analysis-reverse-windows-rootkit-ssdt-zwenumeratekey-hide-service]]（注册表隐藏能力）、[[code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt]]（.NET 字符串解密对照）。

## 检测与防御

- 检测：对驱动做熵分析/周期性 XOR 检测、查找批量字符串解析循环；YARA 规则匹配固定密钥/`.cdata` 解密特征；监控 `MmGetSystemRoutineAddress` 批量调用。
- 防御：驱动签名/加载白名单、内核完整性；分析侧建立加密字符串自动解密流水线（识别 XOR/RC4/AES 循环），不要只依赖 `strings`。
- 说明：本文是恶意驱动加密 API 名还原技术，severity 记为 low；仅用于授权的样本分析。
