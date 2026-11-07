---
id: code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump
title: 多层编码 shellcode 还原：hex→RC4→ASCII85 解码链与 VirtualAlloc 断点转储
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: multi-layer-encoded-shellcode-decrypt-and-dump
tags:
- windows
- malware-analysis
- shellcode
- rc4
- ascii85
- hex
- virtualalloc
- memory-dump
- debugging
- cobalt-strike
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V93
  verified_at: '2026-11-05T19:38:53+08:00'
  notes: 已对照原文20张图片核对：hex→RC4(key TETmqLyqLoyoin5)→ASCII85链、VirtualAlloc参数0x3000/0x40、解密后尾部IP 82.157.118.84均与截图一致；未实际运行样本或解码脚本
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump/
draft: false
kb_aliases:
- hex RC4 ASCII85 解码
- 加密 shellcode 提取
- VirtualAlloc 断点 dump
- 钓鱼样本 shellcode 分析
- Go DLL 加密载荷
- CobaltStrike shellcode 提取
---

## 一句话结论

恶意 DLL 常把 shellcode 做多层编码（示例：十六进制字符串 → RC4 → ASCII85），运行时才解码到 `VirtualAlloc` 分配的内存并执行；分析时既可静态复现整条解码链写出 `decrypted.bin`，也可在 `VirtualAlloc`/`RtlCopyMemory` 下断点直接 dump 目标内存，后者无需完全还原算法，能快速拿到可分析的 shellcode 与 C2。

## 原理

- **解码链**：示例 `GetInstallDetailsPayload` 中依次调用 `encoding_hex_Decoder`（把长十六进制字符串转字节）、`crypto_rc4_prt_Cipher_XORKeyStream`（RC4，key 为 16 字节字符串 `TETmqLyqLoyoin5`）、`encoding_ascii85_decoder`（ASCII85 解码），最终得到原始 shellcode。多层编码让静态字符串/YARA 难以直接命中，也提高人工分析成本。
- **执行链**：解码后调用 `syscall_ptr_Proc_Call(qword_2481F5030, ...)` 即 `VirtualAlloc` 分配内存（示例参数 `0x3000`/`0x40`），再用 `RtlCopyMemory` 把 shellcode 写入，最后 `syscall_Syscall` 直接执行（绕过用户态 hook 的一种方式）。
- **为什么能在 VirtualAlloc 断点 dump**：解密一定发生在写入 `VirtualAlloc` 返回内存之前；在 `VirtualAlloc` 返回后或 `RtlCopyMemory` 处下断点，此时目标缓冲区内容就是完整明文 shellcode，直接按大小 dump 即可，无需关心前面的编码层。
- **静态复现**：如果不想动态运行样本，可按反编译中的调用顺序提取十六进制字符串与 RC4 key，用 Python 依次 `bytes.fromhex` → RC4 → `base64.a85decode`（注意 ASCII85 与 Ascii85 变体差异）还原；示例还原出的 shellcode 尾部含明文 `82.157.118.84`，即 C2 地址。
- **样本判定**：沙箱/情报把该样本标记为 CobaltStrike 家族（IP 82.157.118.84、样本哈希）；提取出的 shellcode 可进一步用 CS 解析器/配置提取工具还原 Beacon 配置。
- **为什么多层编码不等于安全**：解码器与 key 必须在样本内，攻击者能静态定位；运行时明文必然出现在内存中，断点/dump 即可捕获。多层编码只增加分析时间，不改变可提取性。
- **边界**：若 loader 使用自定义加密/虚拟化、反调试、内存自修改或分片解码，静态复现难度上升；动态 dump 需要在正确进程/线程与时机下断点，且样本可能有反调试。

## 触发条件

- 恶意样本（DLL/EXE/Go 程序）内含大段十六进制/Base64/ASCII85 字符串与加密常量，导入或动态解析 `VirtualAlloc`、`RtlCopyMemory`、`memcpy` 等 API。
- 分析者可运行样本或使用调试器（x64dbg/WinDbg）；样本未启用强反调试，或可绕过。
- 已知/可推断解码顺序与 key（反编译可见）；或能在 `VirtualAlloc`/`RtlCopyMemory` 下断点。
- 样本分配的可执行内存大小合理（示例 shellcode 数十 KB），dump 后可用 `file`/`strings`/YARA/CS 工具分析。

## 利用步骤

1. 静态定位 loader（如 Go DLL 的 `main_GetInstallDetailsPayload`），记录解码函数调用顺序、十六进制字符串、RC4 key、`VirtualAlloc` 参数与 `RtlCopyMemory` 目标。
2. 静态复现：提取 hex 字符串 → `bytes.fromhex` → RC4(key) → ASCII85 解码，写出 `decrypted.bin`；校验 PE/shellcode 特征（如 `MZ` 或 Beacon 配置）。
3. 或动态提取：在调试器中给 `VirtualAlloc` 下断点，运行样本；返回后记录 `RAX` 指向的内存与大小，在 `RtlCopyMemory` 后 dump 该区域。
4. 用 `strings`/十六进制查看 shellcode 尾部/配置区，提取 C2 IP/域名、URI、端口、密钥等 IOC（示例尾部 `82.157.118.84`）。
5. 用 CobaltStrike 配置解析器、YARA、沙箱情报进一步确认家族与完整配置；必要时在隔离环境运行以捕获网络流量。
6. 将提取的 shellcode 哈希、C2、加载链写入 IOC，供检测与阻断使用。

## PoC

原文静态解码流程（示意，未在本机执行样本）：

```python
import base64, struct

data = bytes.fromhex(hex_string)          # encoding_hex_Decoder
# RC4，key = b"TETmqLyqLoyoin5"
S = list(range(256)); j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) & 0xff
    S[i], S[j] = S[j], S[i]
out = bytearray(); i = j = 0
for b in data:
    i = (i + 1) & 0xff
    j = (j + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
    out.append(b ^ S[(S[i] + S[j]) & 0xff])
shellcode = base64.a85decode(bytes(out), adobe=False)   # encoding_ascii85_decoder
open('decrypted.bin','wb').write(shellcode)
```

动态提取（x64dbg/WinDbg）：

```text
bp VirtualAlloc
运行到返回 -> 记录 RAX（分配地址）与 Size
bp RtlCopyMemory / 单步到复制完成
dump RAX 指向的内存 -> decrypted.bin
strings decrypted.bin | findstr 82.157
```

原文结果：`decrypted.bin` 尾部可见 ASCII `82.157.118.84`；沙箱情报将样本标记为 CobaltStrike，IOC 包括该 IP 与样本哈希。

## 变体与关联

- **其他编码层**：Base64、XOR、AES、gzip/压缩、分片拼接；顺序与 key 从反编译或动态调试获取。
- **其他执行方式**：`CreateThread`、APC、纤程、回调、`NtCreateThreadEx`；断点位置相应改为解密后/执行前。
- **无调试器**：可用 Frida/API monitor/沙箱内存 dump；或在隔离环境运行后抓进程内存。
- **关联**：Go DLL loader 定位见 [[code-analysis-reverse-windows-go-dll-init-export-loader-analysis]]；运行时 dump 相关见 [[code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump]]；CobaltStrike 检测可参考防御/检测卡片。
- **防御/检测**：监控 `VirtualAlloc` + `RtlCopyMemory` + syscall 执行链；对 Go DLL 中的大段十六进制字符串和 RC4 常量做静态规则；沙箱动态分析提取内存与网络 IOC。

## 检测与防御

- **静态检测**：YARA 规则匹配长十六进制字符串 + `encoding_hex_Decoder`/`crypto_rc4`/`encoding_ascii85` 符号或特征、`VirtualAlloc`/`RtlCopyMemory` 导入。
- **行为检测**：DLL 加载后短时间内 `VirtualAlloc` 可执行内存、`RtlCopyMemory` 写入、syscall 执行并外连；EDR 可对内存执行链告警。
- **防御**：启用 EDR/AV 内存扫描、AMSI/ETW、代码完整性；限制白程序从用户目录加载 DLL；对钓鱼附件做多层检查。
- **取证**：保存原始样本、解密后的 shellcode、C2 IOC 与内存 dump；用沙箱情报关联 CobaltStrike 等家族。
