---
id: code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract
title: Dridex 载荷还原：48 字节逆序 key 的 RC4 → Base64 → aPLib 静态提取 shellcode
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dridex-multilayer-payload-extraction
aliases:
- Dridex shellcode 提取
- RC4 Base64 aPLib
- 反转 key RC4
- 0x30 字节密钥
- aPLib 解压
- 银行木马载荷分析
- Dridex 多级解码
tags:
- windows
- malware-analysis
- dridex
- shellcode
- rc4
- base64
- aplib
- static-analysis
- payload-extraction
- ida
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V101
  verified_at: '2026-11-05T22:27:06+08:00'
  notes: 已对照原文与图36/50/57-59核对：前0x30字节倒序作RC4 key、RC4后Base64、decoded[4:]跳4字节头再aPLib解压得58be...开头shellcode、proc_bit==0x20选0x55A060否则0x55A6C0均一致；未在样本上执行PoC。
---

## 一句话结论

Dridex 把 32/64 位 stage-2 shellcode 以“前 `0x30` 字节倒序密钥 + RC4 密文”的形式嵌在 PE 数据区，运行时按进程位数选取对应块；静态分析时按同样布局做 RC4、Base64 解码、跳过 4 字节非 aPLib 头，再 aPLib 解压，即可离线还原出完整 shellcode。

## 原理

- **数据布局**：每个加密块的前 `0x30`（48）字节是密钥，但以逆序存放；解密函数先拷贝前 `0x30` 字节到密钥结构，再做一次字符串反转（示例 `mw_invert_string`），然后用反转后的 48 字节作为 RC4 Key 解密其后的全部密文。
- **为什么密钥要倒序**：这只是廉价的静态特征规避——直接按顺序取 48 字节做 key 解不出来，必须观察反转例程；反转本身不增加密码学强度，看到 `mw_get_key_addr`/`mw_invert_string` 即可还原。
- **32/64 位双份载荷**：样本用 `mw_wrap_get_proc_bit` 查询当前进程位数，`0x20` 表示 32 位，选数据块 `0x55A060`；否则选 64 位块 `0x55A6C0`。两份明文是同一阶段载荷的不同架构版本，分析 64 位块时不要误用 32 位 key。
- **后续解码链**：RC4 明文并不总是 shellcode；示例中有一段是 Base64 文本，Base64 解码后前 4 字节不是 aPLib 流（原文按长度/头部处理），从第 4 字节开始做 aPLib 解压，得到以 `58 BE ...` 开头的 shellcode，再写入文件即可用反汇编器分析。
- **为什么可静态复现**：RC4 算法（KSA/PRGA）、aPLib 解压器、Base64 解码器与 key 都必须嵌入样本；key 虽倒序但就在密文头部，因此不需要运行样本即可完整还原。示例第一轮直接 `aPLib(decoded)` 失败、改为 `aPLib(decoded[4:])` 成功，说明这 4 字节是固定头而非压缩流的一部分。
- **与配置块的区别**：同一套 RC4 布局也用于配置字符串、计划任务 XML 等块；解密后可能是可读字符串而非 Base64，需按内容分支处理，不能一律套 Base64+aPLib。

## 触发条件

- 目标为 Windows PE（EXE/DLL），数据区存在大段高熵块，代码中能定位 RC4 KSA/PRGA、Base64 解码与 aPLib 解压例程。
- 样本调用 `IsWow64Process`/`GetNativeSystemInfo` 或自定义 `get_proc_bit` 判断位数，并按结果选择两块数据之一。
- 解密函数签名中能看到 key 长度参数（示例为 `0x30`）或固定拷贝长度；Key 在密文头部且被反转。
- 分析者能导出数据区字节（IDA `Edit → Export data → hex string` 或直接从文件按 RVA 读取），不需要运行样本。
- aPLib 解压实现可用（标准 aPLib/AP32 或原文使用的 Python 实现）；若数据带 `AP32` 头则按头解析，否则按裸流处理。

## 利用步骤

1. 在 IDA 中定位 `mw_rc4_decrypt` 的交叉引用，找到调用点附近的“位数判断 + 两块数据地址”分支，确认 32 位块与 64 位块（示例 `0x55A060` / `0x55A6C0`）。
2. 选中目标块，`Edit → Export data`，导出格式选 `hex string (unspaced)`，得到连续十六进制。
3. 取前 `0x30` 字节并整体反转作为 RC4 Key，剩余字节作为密文，执行 RC4 解密。
4. 观察明文：若为 Base64 字符集，先 Base64 解码；若为可读字符串/XML，直接提取配置或 IOC（不要继续解压）。
5. 对 Base64 解码结果跳过前 4 字节（固定头），从第 5 字节起做 aPLib 解压；若解压仍失败，检查是否需要按 `AP32` 头读取 `header_size` 与 `packed_size`。
6. 将解压结果写为 `stage2.bin`，用 `file`/`strings`/IDA 检查是否为 shellcode（常见 `58 BE`、`FC E8` 等序言），提取其中 C2/配置。
7. 如需交叉验证，可在隔离环境的调试器中对注入前的缓冲区下断点 dump，但不要直接运行生产样本。

## PoC

```python
import base64
# 标准 aPLib 解压实现，例如 snemes/aplib 的 Python 版
from aplib import decompress

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

blob = bytes.fromhex(hex_data)          # IDA 导出的整块数据
key = blob[:0x30][::-1]                 # 前 48 字节倒序
plain = rc4(key, blob[0x30:])
decoded = base64.b64decode(plain)       # 若明文是 Base64
shellcode = decompress(decoded[4:])     # 跳过 4 字节头后 aPLib 解压
open("stage2.bin", "wb").write(shellcode)
```

示例流程中，直接 `decompress(decoded)` 会失败，改为 `decompress(decoded[4:])` 后成功，说明前 4 字节是自定义头；PoC 未在本机对样本执行。

## 变体与关联

- **架构变体**：32 位块与 64 位块布局相同但 key/密文不同；按 `proc_bit == 0x20` 选择，不要交叉使用。
- **Key 变体**：key 长度可能不是 `0x30`、可能正序存放或经其他轻量变换（加减、XOR）；以反编译中的拷贝长度和反转例程为准。
- **编码变体**：aPLib 可换成 LZMA/gzip/AP32 带包头格式；Base64 可换成自定义字母表或十六进制字符串；按解密后字节特征判断。
- **关联卡片**：[[code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump]]（hex→RC4→ASCII85 的动态/静态还原）、[[code-analysis-reverse-windows-dridex-c2-table-signature-extraction]]（同一样本的 C2 配置提取）、[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（另一家族的 RC4 配置提取）。
- **边界**：解压出的 shellcode 可能还有二次加密或反射加载器；本卡只还原到第一层可执行载荷。

## 检测与防御

- **静态检测**：YARA 组合“RC4 KSA/PRGA 常量 + aPLib 特征 + 高熵数据块 + `0x30` 密钥长度/反转循环”；对 Base64 长字符串与 `AP32` 头做二次匹配；关注同一 PE 内成对出现的 32/64 位加密块。
- **行为检测**：进程位数查询后紧接大块内存解密、`VirtualAlloc`/`VirtualProtect` 可执行内存、写入后创建线程/APC/映射注入；EDR 可对“解密→写入→执行”链告警。
- **防御**：启用 EDR/AV 内存扫描与 AMSI/ETW；阻断样本释放的 C2；对钓鱼邮件附件与宏文档做隔离；限制未知 PE 的注入行为。
- **取证**：保存原始样本、解密后的 shellcode 哈希、提取出的 C2 与配置；分析在隔离环境进行，不执行样本。
