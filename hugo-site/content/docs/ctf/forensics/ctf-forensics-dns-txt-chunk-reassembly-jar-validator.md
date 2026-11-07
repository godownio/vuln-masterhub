---
id: ctf-forensics-dns-txt-chunk-reassembly-jar-validator
title: DNS TXT 两位编号分片重组 JAR：Java 校验器异或逆推
type: scenario
domain: ctf
path: ctf/forensics
technique: dns-txt-chunk-reassembly-jar-validator
tags:
- ctf
- forensics
- dns
- txt-record
- base64
- jar
- java
- xor
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:11+08:00'
  notes: 已对照原文 Data Needs Splitting 核对：TXT 两位编号分片、Base64 重组 JAR、assets/file.dat 为 Validator class、4 个 16 位 key 异或后十进制拼接、DFS 逆推均一致；未实际运行。
url: /docs/ctf/forensics/ctf-forensics-dns-txt-chunk-reassembly-jar-validator/
draft: false
kb_aliases:
- DNS TXT 分片重组
- 两位编号分片
- base64 JAR 还原
- Java Validator 逆推
- 十进制拼接异或校验
---

## 一句话结论

DNS TXT 记录以“两位编号 + Base64 分片”的形式存放附件：按编号排序拼接、Base64 解码得到 JAR；JAR 内 `assets/file.dat` 实际是 Java 校验器类，其 `validate()` 把输入逐字符与 4 个 16 位 key 异或后把十进制结果拼成字符串比较，逆推即可得到 flag。

## 原理

- 每个 TXT 记录形如 `00<base64>`、`01<base64>`…，前两位是分片编号，后续是 Base64 内容；编号保证乱序返回时也能按序重组。
- 拼接后的 Base64 解码得到一个 JAR/ZIP，内含 `Loader.class`、`Main.class`、`assets/file.dat`；`file.dat` 虽然是数据文件扩展名，但其实是 Java class（`Validator`），需按 class 文件反编译/分析。
- `validate()` 的逻辑：用两个 64 位常量 `a`、`b` 按 16 位切片异或得到 4 个 key；对输入每个字符 `ch`，计算 `val = ord(ch) ^ key[idx % 4]`，把 `val` 的十进制字符串追加到结果串；最后与目标十进制串比较。
- 逆推的难点是十进制拼接没有分隔符，一个字符的 `val` 可能是 1–5 位；用 DFS 从目标串开头匹配 `str(ord(ch) ^ key[idx%4])`，枚举可打印字符，即可恢复所有可能输入，再用 flag 格式筛选。
- 该场景结合了 DNS 外带、分片重组、JAR 分析、Java 反编译与 XOR 逆推，是典型的“多层编码 + 自定义校验”链。

## 触发条件

- DNS TXT 记录返回多个带两位编号的 Base64 分片，且编号连续。
- 分片拼接、Base64 解码后得到 ZIP/JAR 或其它容器。
- 容器内包含 Java class 或自定义校验逻辑。
- 校验器使用可逆运算（XOR/加减）并把结果转成十进制/十六进制字符串比较。

## 利用步骤

1. 收集 TXT 记录，按前两位编号排序；同一编号可能有多条，按题目规则去重/拼接。
2. 去掉编号后拼接 Base64，解码为 JAR/ZIP，列出条目。
3. 提取 `assets/file.dat` 等可疑文件，用 `file` 确认是否为 Java class；用 CFR/Procyon/JADX 反编译。
4. 还原 `validate()` 的 key 派生与逐字符变换；提取目标字符串。
5. 写 DFS/回溯：对每个位置枚举可打印字符，计算变换值并匹配目标串前缀，直到恢复完整输入。
6. 用 flag 格式（如 `DawgCTF{...}`）过滤候选，提交。

## PoC

```python
import re
import base64
import zipfile
import io
from pathlib import Path
from functools import lru_cache

text = Path("dns.txt").read_text(encoding="utf-8", errors="ignore")
parts = {}
for line in text.splitlines():
    m = re.match(r"^(\d{2})(.+)$", line.strip())
    if m:
        parts[int(m.group(1))] = m.group(2)

assembled = "".join(parts[i] for i in sorted(parts))
jar_bytes = base64.b64decode(assembled)
zf = zipfile.ZipFile(io.BytesIO(jar_bytes))
print(zf.namelist())
file_dat = zf.read("assets/file.dat")

# 反编译后得到的常量
target = "145511939249997195145441944550467175145531942549987228145401943650017203145451934650207244145651934650127169"
a = 2194307438957234483
b = 148527584754938272
keys = [((a >> (16 * i)) & 0xffff) ^ ((b >> (16 * i)) & 0xffff) for i in range(4)]

@lru_cache(None)
def dfs(pos, idx):
    if pos == len(target):
        return [""]
    out = []
    for ch in range(32, 127):
        s = str(ch ^ keys[idx % 4])
        if target.startswith(s, pos):
            for tail in dfs(pos + len(s), idx + 1):
                out.append(chr(ch) + tail)
    return out

for s in dfs(0, 0):
    if s.startswith("DawgCTF{") and s.endswith("}"):
        print(s)
```

## 变体与关联

- 变体：分片编号用 hex/字母；编码用 hex、Base32 而非 Base64；传输用 A/AAAA/CNAME 记录。
- 变体：容器换成 ZIP/APK/ELF；校验器用加减、RC4、AES 而非 XOR。
- 变体：十进制拼接改为十六进制/固定宽度，逆推更简单。
- 关联：[[ctf-forensics-soc-dns-tunnel-base32-pat-exfil]]（DNS 隧道分片外带）、[[ctf-misc-nested-zipcrypto-base32-crc32-overlap-chain]]（嵌套压缩包）、[[ctf-reverse-apk-rc6-base58-dex-db-derive]]（APK 多层解码）。

## 检测与防御

- 防御：限制 DNS TXT 出站到不可信域；对高熵 TXT 分片、连续编号子域做告警。
- 防御：终端/邮件网关检测 JAR/ZIP 内伪装成数据文件的 class；对下载附件做静态分析。
- 检测：DNS 查询中出现连续两位编号标签、固定长 Base64 TXT、同一域名短时间大量 TXT 查询。
- 响应：确认外带后阻断域名、吊销相关凭据，排查主机上的 JAR/Java 执行。
