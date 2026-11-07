---
id: ctf-forensics-webp-riff-custom-chunk-ech0-extraction
title: WebP RIFF 自定义 chunk 隐写提取：按 chunk 遍历与奇数字节对齐取出 ECH0 载荷
type: scenario
domain: ctf
path: ctf/forensics
technique: webp-riff-custom-chunk-extraction
tags:
- ctf
- forensics
- webp
- riff
- steganography
- chunk
- android
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:50+08:00'
  notes: 已对照原文核对：RIFF/WEBP 头、从 offset 12 遍历 chunk、VP8L 17 字节后 ECH0 236 字节、奇数长度 padding (size & 1)、ECH0 交给 EFVM 且需环境 key material，最终 flag ISCC{f0lded_echo_is_a_state_not_a_string} 均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-webp-riff-custom-chunk-ech0-extraction/
draft: false
kb_aliases:
- WebP 隐写
- RIFF chunk
- ECH0 chunk
- sleep_loop.webp
- 自定义 chunk
---

## 一句话结论

WebP 是 RIFF 容器，按 `tag(4) + size(4LE) + data` 遍历 chunk，未知 tag `ECH0` 就是题目藏的第二层数据；注意奇数长度 chunk 后有一个 padding 字节，漏掉会错位。取出 236 字节 ECH0 后交给自定义 VM 解释。

## 原理

- **RIFF/WebP 结构**：文件头为 `RIFF` + 4 字节小端总长 + `WEBP`；之后是 chunk 序列。标准 chunk 有 `VP8 `、`VP8L`、`VP8X`、`ALPH`、`ANIM` 等；解析器应按 tag 跳过未知块。
- **chunk 布局**：4 字节 tag、4 字节小端 size、size 字节 data；若 size 为奇数，末尾补 1 字节 padding，下一个 chunk 从 `pos + 8 + size + (size & 1)` 开始。
- **自定义 chunk**：本题在 `VP8L`（17 字节）后放 `ECH0`（236 字节）；`ECH0` 不是标准 WebP chunk，是出题人植入的 VM 字节码/数据块。
- **为什么容易漏**：只看图片解码器会忽略未知 chunk；用 `strings` 可能看到 `ECH0` 但不知道边界；不处理 padding 会把后续数据读错。
- **取出后**：ECH0 是自定义 VM（EFVM）的输入，VM 还接收 dex hash、签名 hash、TraceRecorder 状态、资源 ID 等作为 key material；本题最终 flag 由 VM keystream XOR 密文得到。
- **本题结果**：flag 为 `ISCC{f0lded_echo_is_a_state_not_a_string}`；ECH0 只是中间载荷，不能直接当明文。

## 触发条件

- 文件以 `RIFF`/`WEBP` 开头，或 APK assets 中有 `.webp`。
- 标准解码器能正常显示图片，但文件大小/尾部有额外数据。
- 十六进制中出现非标准 4 字节 tag（如 `ECH0`、`FLAG`、`DATA`）。
- 需要提取隐藏载荷做后续逆向。

## 利用步骤

1. 读文件，断言 `RIFF` 和 `WEBP`；从 offset 12 开始循环。
2. 读 tag/size，打印每个 chunk；遇到目标 tag 时 dump data。
3. 按 `pos += 8 + size + (size & 1)` 前进；不要漏 padding。
4. 对 dump 出的数据做熵/魔数/长度分析；若是字节码，找 VM 入口和 opcode 表。
5. 结合上层代码确认该 chunk 如何被读取（如 `readEchoChunk`），以及是否参与密钥派生。
6. 若载荷被加密/压缩，按上层算法解密；本题 ECH0 是 VM 数据块，需配合环境 key material 运行 VM。

## PoC

```python
import struct
from pathlib import Path

webp = Path("assets/sleep_loop.webp").read_bytes()
assert webp[:4] == b"RIFF"
assert webp[8:12] == b"WEBP"

pos = 12
while pos + 8 <= len(webp):
    tag = webp[pos:pos + 4]
    size = struct.unpack("<I", webp[pos + 4:pos + 8])[0]
    data = webp[pos + 8:pos + 8 + size]
    print(tag, size)
    if tag == b"ECH0":
        Path("ech0.bin").write_bytes(data)
        print("[+] dump ech0.bin", len(data), "bytes")
        break
    pos += 8 + size + (size & 1)
```

输出：`b'VP8L' 17`、`b'ECH0' 236`。

## 变体与关联

- **容器变体**：RIFF/WAV/AVI 的 `LIST`/`INFO` chunk、PNG 自定义 chunk（`tEXt`/`iTXt`/`zTXt`）、ZIP 尾部附加数据、MP4 box。
- **自定义 tag**：可能是 `FLAG`、`DATA`、`ECH0`；先枚举所有 tag 再猜，不要只看标准 chunk。
- **载荷变体**：可以是明文、压缩数据、加密数据、VM 字节码；提取后先看熵和魔数。
- **关联卡片**：[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 扫描顺序）、[[ctf-misc-png-trailing-data-lcg-xor-base62]]（PNG 尾部数据）、[[ctf-reverse-android-apk-environment-state-derived-keystream]]（同题后续 VM 派生）。
- **边界**：若文件被重新编码（转码/截图），自定义 chunk 会丢失；必须用原始文件。

## 检测与防御

- **防御视角**：不要把密钥/载荷藏在容器自定义 chunk；资源发布前做 chunk 白名单/重编码。
- **检测信号**：RIFF chunk 遍历发现未知 tag；图片解码后仍有额外数据；文件大小与像素数据不匹配。
- **CTF 取证**：先遍历 chunk 再谈隐写；奇数长度 padding 是常见错位点。
