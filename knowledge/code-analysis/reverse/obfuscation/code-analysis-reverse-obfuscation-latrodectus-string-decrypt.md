---
id: code-analysis-reverse-obfuscation-latrodectus-string-decrypt
title: LATRODECTUS 字符串解密：前 4 字节 u32 x 与 2 字节 u16 y 派生长度，明文 = ((x+i+1) XOR 密文字节) & 0xFF
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: latrodectus-string-decrypt-xor-index
aliases:
- LATRODECTUS 字符串解密
- latro_str_decrypt
- 6 字节头字符串加密
- u32 x u16 y 异或长度
- loader 字符串批量解密
tags:
- windows
- malware-analysis
- latrodectus
- string-encryption
- obfuscation
- xor
- ida
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V393
  verified_at: '2026-11-09T11:34:37+08:00'
  notes: 已对照原文算法与图15等解密调用核对：x=u32(前4字节)、y=u16(4:6)、len=(x^y)&0xFFFF、明文=((x+i+1)^密文)&0xFF，与原文 decrypt_string 一致；与 WARMCOOKIE RC4 记录、Grandoreiro 等既有字符串解密卡算法不同，非重复；原文无版本；未复跑
---

## 一句话结论

LATRODECTUS 把每个字符串存成“6 字节头 + 密文”：头 4 字节为 u32 `x`、后 2 字节为 u16 `y`，明文长度取 `(x ^ y) & 0xFFFF`，第 i 个明文字节为 `((x + i + 1) ^ 第 i 个密文字节) & 0xFF`；按此实现十几行 Python 即可批量还原样本中所有字符串（配置目录、C2 域、格式化串、注册表/API 名等），并回填 IDA 注释。

## 原理

- **头部即参数**：密文块前 4 字节读作小端 u32 `x`，紧接 2 字节小端 u16 `y`；`x ^ y` 的低 16 位就是明文字节数。长度不单独存储，而是藏在两个看似随机的字段的异或里，静态扫描不易直接看出边界。
- **逐字节变钥异或**：第 i 个明文字节 = `(x + i + 1) ^ 密文字节`，再取低 8 位。密钥流是“x 的低字节递增”，每个位置都不同；`x` 的高位在 `& 0xFF` 后被丢弃，因此等价于 `((x + i + 1) & 0xFF) ^ c[i]`。
- **为什么有效**：没有硬编码可识别的字符串，字符串的存放位置与长度都依赖头部字段；但算法是纯算术、可逆且无外部密钥，拿到任一处解密函数（或识别出 6 字节头 + `(x + i + 1) ^ b` 的模式）即可批量还原。
- **版本演进**：2023 年初始报告描述过 PRNG 参与的算法，本样本未使用，说明该加载器的字符串保护在持续变化；遇到新样本应先确认头部字段布局再套用。

## 触发条件

- 样本中出现大量“6 字节前缀 + 短密文”的赋值，解密函数特征为读取 u32/u16、异或、按索引加一后异或字节。
- 需要还原配置（C2、目录名、活动名）或格式化字符串（如 `%s%d.exe`、`init -zzzz="%s\\%s"`）以继续分析。

## 利用步骤

1. 在 IDA 中定位字符串解密函数：读取首 4+2 字节、`x ^ y` 取低 16 位作为循环上界、循环体为 `(x + i + 1) ^ byte`。
2. 提取所有调用点的密文块（或从数据段按引用批量读取）。
3. 用 Python 实现解密并批量输出；对格式化串保留 `%s/%d` 占位符不动。
4. 用 IDAPython 把解密结果写成注释或重命名数据，便于后续交叉引用分析（公开工具 `latro_str_decrypt.py` 即做此事）。
5. 用解密出的 C2、目录、活动名与行为串做威胁狩猎与 YARA 特征。

## PoC

```python
import struct

def latro_decrypt(blob: bytes) -> bytes:
    x = struct.unpack("<I", blob[:4])[0]
    y = struct.unpack("<H", blob[4:6])[0]
    n = (x ^ y) & 0xFFFF
    return bytes(((x + i + 1) ^ b) & 0xFF for i, b in enumerate(blob[6:6 + n]))

# 例：C2 域、配置目录、格式化串均为该结构，批量套用即可
```

## 变体与关联

- 关联：该家族完整行为见 [[code-analysis-reverse-windows-latrodectus-loader-behavior-c2]]。
- 变体：同一加载器的 API 名解析另用 CRC32，不含字符串；DLL 名则通过 System32 通配枚举 + CRC32 匹配，见 [[code-analysis-reverse-obfuscation-wildcard-dll-crc32-resolution]]。
- 关联：其他家族的逐字节变钥字符串解密（如三重 Base64+差分 XOR+AES）见 [[code-analysis-reverse-obfuscation-grandoreiro-string-decryption-triple-base64-diff-xor-aes]]，思路都是先定位解密循环再批量还原。

## 检测与防御

- 分析侧信号：大量短密文块以 6 字节头引用；解密循环出现 `u32 ^ u16` 取低 16 位与按索引递增异或。
- YARA 特征：可匹配字符串解密循环的字节模式（如 `89 44 24 ?? 48 8B 44 24 ?? 0F B7 40 ?? ...` 一类的栈变量运算序列）作为家族规则的多特征之一。
- 防御：字符串加密只提高静态分析成本，不构成安全边界；检测应基于行为（动态 API 解析、计划任务、rundll32 加载 AppData DLL 等）。
