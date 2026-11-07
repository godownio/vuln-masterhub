---
id: ctf-forensics-memory-image-flag-keyword-search
title: 内存镜像关键词搜索：按 UTF-8/UTF-16 编码定位明文 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: memory-image-flag-keyword-search
aliases:
- Personal Vault
- 内存镜像取证
- 关键词搜索 flag
- 多编码字符串搜索
tags:
- ctf
- forensics
- memory
- strings
- utf16
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:33+08:00'
  notes: 已对照 Personal Vault 文字与图 01 核对：多编码搜 flag{、3 条命中、0xAFA15CE7 UTF-8 命中一致；未复跑镜像。
---

## 一句话结论

拿到内存镜像（raw/dmp）时，直接用取证工具或 `strings` 以 `flag{` 为关键词，同时覆盖 ASCII/UTF-8/UTF-16LE/UTF-16BE 编码搜索，即可在进程堆或字符串对象中直接命中明文 flag；本题在镜像偏移约 `0xAFA15CE7` 处找到 UTF-8 编码的完整 flag。

## 原理

- 内存镜像保留进程堆、栈、文件缓存与字符串对象的原始字节。程序读取 flag 后，如果没有立即加密/清零，flag 会以明文留在内存中。
- Windows 程序常用 `std::wstring`/UTF-16，Linux/Go 程序常用 UTF-8；同一份镜像里多种编码并存，所以搜索必须覆盖 ASCII、UTF-8、UTF-16LE、UTF-16BE，否则会漏掉。
- 关键词搜索是成本最低的第一步：以 `flag{` 这类固定前缀定位，再按偏移查看上下文，拼接被截断的字符串。相比完整内存分析（Volatility 插件、进程枚举），它不依赖符号/配置，适合 CTF 快速拿分。
- 本题用取证工具的关键词搜索界面直接扫出 3 条命中，其中一条是完整 UTF-8 flag。

## 触发条件

- 有可读的内存镜像文件（raw/dmp/vmem 等）。
- 目标程序运行过并读取了 flag，且未做加密/擦除。
- 知道 flag 的固定前缀（如 `flag{`、`CTF{`）或题目给了提示。

## 利用步骤

1. 用取证工具（如火眼、Volatility、MemProcFS）加载镜像，选择“关键词搜索/字符串搜索”。
2. 关键词填 `flag{`（或题目前缀），编码勾选 ASCII、UTF-8、UTF-16LE、UTF-16BE，最小长度设为 8–10。
3. 逐条查看命中偏移与上下文，优先看 `UTF-8`/`UTF-16LE` 的完整可读串。
4. 离线也可用 `strings`：ASCII/UTF-8 用 `-a`，UTF-16LE 用 `-el`，UTF-16BE 用 `-eb`；按偏移排序后合并结果。
5. 若字符串被截断，读取命中偏移前后若干字节，按对应编码解码并去掉 NUL。

## PoC

```bash
strings -a -t x image.raw | grep -i 'flag{'
strings -a -el -t x image.raw | grep -i 'flag{'
strings -a -eb -t x image.raw | grep -i 'flag{'
```

```python
data = open("image.raw", "rb").read()
for enc in ("utf-8", "utf-16-le", "utf-16-be"):
    needle = "flag{".encode(enc)
    pos = data.find(needle)
    while pos != -1:
        chunk = data[pos:pos + 200]
        text = chunk.decode(enc, "ignore").split("\x00")[0]
        print(hex(pos), enc, text)
        pos = data.find(needle, pos + 1)
```

说明：镜像较大时逐编码扫描较慢，可先用 `grep -abo` 或工具索引；命中后务必核对完整字符串，避免把诱饵 flag 当答案。

## 变体与关联

- **浏览器堆快照**：网页里的 flag 可能留在 JS 堆中，导出 Heap snapshot 后搜前缀；见 [[ctf-forensics-chrome-heap-snapshot-flag-search]]。
- **磁盘镜像字符串**：ext4/NTFS 镜像直接 `strings` 也能从已删除/未分配块恢复明文；见 [[ctf-forensics-ext4-image-unallocated-strings-residual]]。
- **加密卷内存密钥**：若 flag 在加密卷中，内存搜索目标应改为卷主密钥；见 [[ctf-forensics-truecrypt-memory-key-mount]]。
- **编码陷阱**：UTF-16 字符串在 `strings` 默认模式下不可见，必须显式指定 `-el/-eb`。

## 检测与防御

- 敏感数据使用后及时清零（`memset_s`/`SecureZeroMemory`），避免明文长期驻留内存；密钥使用硬件保护/短生命周期。
- 进程内存加密、禁用不必要的 core dump/休眠文件，减少镜像可获取面。
- 检测：内存镜像中出现 `flag{`/密钥前缀、明文凭据；取证时同时注意诱饵与真实字符串的上下文。
