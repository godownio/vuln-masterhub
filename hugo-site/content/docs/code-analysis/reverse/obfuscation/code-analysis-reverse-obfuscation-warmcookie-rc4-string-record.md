---
id: code-analysis-reverse-obfuscation-warmcookie-rc4-string-record
title: WARMCOOKIE 原生 PE 字符串加密：.rdata 中 [4 字节长度][4 字节 RC4 key][密文] 记录 + 用后清零
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: warmcookie-rc4-string-record-decrypt
tags:
- malware-analysis
- obfuscation
- string-encryption
- rc4
- idapython
- windows
- reverse
- warmcookie
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V322
  verified_at: '2026-11-08T15:56:28+08:00'
  notes: 已对照 img12-15 核对 [size][key][cipher] 记录 06/3BF2E8F3→C:\、key 复用 0F3E8F23Bh 与用后 memset/FreeHeap；已修正清零偏移表述为 -4/-8；未复跑样本。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-warmcookie-rc4-string-record/
draft: false
kb_aliases:
- WARMCOOKIE 字符串解密
- '[size][key][data] RC4 字符串'
- .rdata RC4 字符串记录
- 每字符串 RC4 key
- 用后 memset 清零
- 原生 PE 字符串加密
---

## 一句话结论

WARMCOOKIE 的字符串在 `.rdata` 中按 `[4 字节长度/大小][4 字节 RC4 key][密文]` 的记录排列，运行时由统一的 `DecryptString` 函数用记录内的 4 字节 key 做 RC4 解密；key 不总是逐字符串轮换（多个字符串复用同一 key，如 `0F3E8F23Bh`），且解密后的字符串在使用后立即 `memset` 清零并 `FreeHeap`，因此内存扫描/延迟 dump 也难拿到明文。

## 原理

- **记录格式**：每条记录前 4 字节是长度/大小字段，紧接着 4 字节是 RC4 key，再往后是密文；`DecryptString(ptr)` 读取 `ptr+4` 的 key 与 `ptr` 的大小，对 `ptr+8` 开始的密文做 RC4，返回解密后的宽/窄字符串指针。原文 HxD 截图中可见 `06 00 00 00 | 3B F2 E8 F3 | 3B B8 BE E6 B0 04`，即 size=6、key=`3BF2E8F3`、data 6 字节；用该 key 做 RC4 并去掉 null 后得到 `C:\`。
- **key 复用**：反编译的 `.rdata` 交叉引用显示多个 `DecryptString(dword_...)` 记录共用同一个 key（`0F3E8F23Bh`），覆盖 `TakeScreenCapture`、`GenerateJPG` 等字符串；开发者并非为每条字符串生成独立 key，这给批量解密提供了便利——找到一个 key 后可尝试解一整组记录。
- **为什么选 RC4**：RC4 实现短小、无 IV、密钥 4 字节即可，适合嵌入恶意样本；缺点是同一 key 重复使用会暴露统计特征，且 4 字节 key 可暴力枚举，但在静态分析中先拿到 key 即可直接解密。
- **用后清零**：每解密完一个字符串，代码用 `memset(ptr - 4 或 ptr - 8, 0, *(ptr - 2) + 8)`（原文 `C:\`/`KERNEL32.DLL` 记录用 `-4`，`GetNativeSystemInfo` 记录用 `-8`）把记录头与明文一起清零，再 `FreeHeap`。这样字符串只在调用瞬间存在于堆中，常规内存扫描、`strings` 延迟 dump 或 EDR 周期性扫描可能错过明文。
- **动态 API 加载配合**：`DecryptString` 不仅解普通字符串，也用于解 `KERNEL32.DLL`、`GetNativeSystemInfo`、`GetProcAddress` 等 API 名；解密后立即 `GetModuleHandle`/`GetProcAddress`，再把字符串清零，形成“字符串不长期驻留内存”的 OpSec。
- **静态分析切入点**：在 IDA 中找 `DecryptString` 的调用点与 `rc4` 初始化循环；按记录边界批量读取 `.rdata`，用每条记录自带的 key 解密；或用 CyberChef 的 RC4 操作（key 选 Hex 输入、密文选 Hex、输出 UTF8/Latin1）手工验证。
- **边界**：记录长度字段的含义（字节数/宽字符数）与是否包含 null 可能因样本/编译版本略有差异，需要按解密结果调整；key 复用不是所有样本都成立。

## 触发条件

- 分析对象为原生 Windows PE（WARMCOOKIE 为 DLL），字符串位于 `.rdata` 且由统一解密函数引用。
- 能定位 `DecryptString`（通常被大量 `xmm`/循环 RC4 代码引用）或识别 `[4 字节 size][4 字节 key][密文]` 的记录模式。
- 样本未使用额外的反调试/反 dump 让静态读取无法进行；解密函数本身可在调试器中下断并观察返回值。
- 需要批量还原字符串以理解 C2 协议、命令处理与 API 调用；手工逐条 CyberChef 只适合少量验证。

## 利用步骤

1. 在 IDA 中搜索 RC4 初始化（256 字节 S 盒、`i/j` 交换）或 `DecryptString` 调用点，确认记录格式。
2. 选取一条记录，读取 `size`、`key`、`ciphertext`；用 RC4(key, ciphertext) 解密，确认得到可读字符串（原文示例得到 `C:\`）。
3. 在 `.rdata` 中从记录起始地址按 `8 + size`（或对齐后的长度）步进，批量解析所有记录；注意记录之间可能有 0 填充/对齐。
4. 对每条记录用其自带 key 解密；若 key 复用，可先统计高频 key，优先解一整组。
5. 把解密结果写回 IDA 注释/重命名，或用 IDAPython 脚本批量注释；原文作者发布了对应的 IDAPython 解密/注释工具。
6. 对解密后的 API 名、C2 路径、User-Agent、命令字符串做交叉引用，定位网络与命令处理逻辑。
7. 动态验证：在 `DecryptString` 返回处下断，读取返回值指向的字符串；注意样本可能在返回后立刻清零，需在 `memset` 前 dump。

## PoC

```python
# 解析 [4-byte size][4-byte key][ciphertext] 记录并用 RC4 解密（结构示意）
import struct

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

def decrypt_record(blob: bytes, off: int):
    size = struct.unpack_from("<I", blob, off)[0]
    key = blob[off + 4:off + 8]
    cipher = blob[off + 8:off + 8 + size]
    plain = rc4(key, cipher)
    return plain.split(b"\x00", 1)[0], size, key

# 示例：size=6, key=3BF2E8F3, data=3BB8BEE6B004 -> C:\
rec = bytes.fromhex("06000000" + "3BF2E8F3" + "3BB8BEE6B004")
print(decrypt_record(rec, 0))
```

```text
CyberChef 手工验证：
From Hex -> RC4 (Passphrase: 3B F2 E8 F3, Input format: Hex, Output: UTF8) -> Remove null bytes
输入 3B B8 BE E6 B0 04 -> 输出 C:\
```

## 变体与关联

- **同布局的 .NET XORStringsNet**：也是 `[4 字节长度][4 字节 key][密文]` 记录表，但使用 XOR 而非 RC4，且通过 `ClassLayout`/`FieldRVA` 自动定位，见 [[code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt]]。
- **ChaCha20-Poly1305 字符串解密**：Rust 样本用硬编码 32 字节 key + nonce，IDAPython 批量还原，见 [[code-analysis-reverse-obfuscation-rust-chacha20poly1305-string-decrypt-idapython]]。
- **银狐轻量字符串混淆**：@ 隔字符、栈上字符串、API 包装，见 [[code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation]]。
- **动态 API 解析**：解密后的 API 名直接用于 `GetModuleHandle`/`GetProcAddress`，见 [[pentest-c2-peb-ldr-export-dynamic-api-resolution]] 与 [[pentest-c2-iat-hidden-peb-walk-api-hash-crt-free]]。
- **反内存扫描**：用后清零/释放的做法与“解密后立即擦除”的 OpSec 思路一致，可参考内存马/loader 相关卡。

## 检测与防御

- **静态识别**：在 `.rdata` 中搜索“4 字节小整数 + 4 字节高熵 key + 密文”的记录簇；RC4 初始化循环与大量字符串引用是强特征；YARA 可匹配 `DecryptString` 的 RC4 常量/循环与记录结构。
- **动态检测**：在 `DecryptString` 返回处/`memset` 前抓取明文；监控进程对自身 `.rdata`/堆的读取与随后的 `memset`/`FreeHeap`；内存扫描应在解密函数返回瞬间进行，而非固定周期。
- **API 名监控**：解密后立即调用 `GetModuleHandle`/`GetProcAddress` 的行为可作为“字符串解密 + 动态解析”组合特征。
- **key 复用弱点**：同一 key 加密多条字符串会降低破解成本；防御方可用已知明文/统计方法恢复 key，再批量解密。
- **检测边界**：字符串加密只提高静态分析成本，不改变网络与命令行为；C2 流量、进程链、计划任务仍是主要检测面。
