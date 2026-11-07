---
id: ctf-forensics-registry-numbered-values-alternating-shift
title: 注册表编号值交替偏移：1-26 单字符值按奇偶 +7/-6 还原
type: scenario
domain: ctf
path: ctf/forensics
technique: registry-numbered-values-alternating-shift
tags:
- ctf
- forensics
- registry
- reg-file
- steganography
- shift-cipher
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:14+08:00'
  notes: 已对照原文 Gen-Z Found My Registry 核对：1-26 单字符值、+7/-6 与 evens/odds 提示、奇数位 -6/偶数位 +7 可打印取模均一致；未实际运行。
url: /docs/ctf/forensics/ctf-forensics-registry-numbered-values-alternating-shift/
draft: false
kb_aliases:
- 注册表隐写
- 编号值交替偏移
- evens/odds 提示
- +7/-6 服务名
- .reg 文件取证
---

## 一句话结论

Windows 注册表导出文件里有一组值名为 `"1"` 到 `"26"`、内容为单字符的键值；按编号排序拼出乱码后，利用伪装服务名 `+7`/`-6` 与 `evens`/`odds` 提示，对奇数位字符减 6、偶数位加 7（在可打印 ASCII 范围内取模），即可还原 flag。

## 原理

- `.reg` 文件是 UTF-16 文本，键值行形如 `"1"="J"`、`"2"="Z"`；值名是序号，值是单个字符。按数值排序拼接得到一串看似随机的字符。
- 同一注册表里存在异常服务名 `+7` 与 `-6`，其参数/提示字段为 `evens`、`odds`，暗示“偶数位 +7、奇数位 -6”的交替偏移。
- 对第 `i` 位字符（从 1 开始）：奇数位 `ord(c)-6`，偶数位 `ord(c)+7`；由于结果必须落在可打印 ASCII 区间 `32..126`，实际按 `((ord(c)-32+delta) % 95)+32` 取模。
- 该编码是 Caesar/ROT 的交替变体，密钥是“位置奇偶 + 两个偏移量”；注册表只是载体，换成任意文本/配置/日志同样适用。
- 若拼接结果仍不可读，检查序号是否从 0 开始、偏移方向是否反了、是否先反转字符串、是否只对字母/数字生效。

## 触发条件

- 拿到 `.reg` 导出文件或注册表 hive，存在按数字命名的单字符值。
- 文件中存在可疑服务名/参数（如 `+7`、`-6`、`evens`、`odds`）作为提示。
- 拼接后的字符集在可打印范围内，但语义乱码。
- 题目提示“注册表被改成了 String Cheese”等，暗示值被逐字符替换。

## 利用步骤

1. 以 UTF-16 读取 `.reg`，处理行尾 `\` 续行。
2. 用正则提取 `"<数字>"="<单字符>"` 形式的键值，按数字排序拼接。
3. 识别提示字段：`+7` 对应偶数位、`-6` 对应奇数位（或按题目实际提示）。
4. 对拼接串逐位应用偏移：奇数位 -6、偶数位 +7，按可打印 ASCII 取模。
5. 检查输出是否以 flag 前缀开头；若不是，尝试交换奇偶、反转字符串、调整起始索引。
6. 提取 flag。

## PoC

```python
from pathlib import Path
import re

text = Path("chal.reg").read_text("utf-16")
lines = text.splitlines()

# 处理 .reg 续行
merged, buf = [], ""
for line in lines:
    if buf:
        line = buf + line.lstrip()
        buf = ""
    if line.endswith("\\"):
        buf = line[:-1]
        continue
    merged.append(line)

pairs = {}
for line in merged:
    m = re.match(r'"(\d+)"="(.)"$', line.strip())
    if m:
        pairs[int(m.group(1))] = m.group(2)

encoded = "".join(pairs[i] for i in sorted(pairs))
print("encoded =", encoded)

def shift_printable(c, delta):
    return chr((ord(c) - 32 + delta) % 95 + 32)

out = []
for i, c in enumerate(encoded, start=1):
    out.append(shift_printable(c, -6 if i % 2 == 1 else +7))
print("flag =", "".join(out))
```

## 变体与关联

- 变体：偏移量不同、按 0/1 起始、只对字母生效、偏移后不取模（可能越界）。
- 变体：值名不是 1-26，而是 hex/日期/服务名；值可能是多字符或 hex 编码。
- 变体：提示藏在服务 `ImagePath`、注册表注释、文件名或题目描述中。
- 关联：[[ctf-forensics-windows-sam-system-offline-ntlm-mask-crack]]（Windows 注册表/hive 取证）、[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（可打印 ASCII Caesar）、[[ctf-misc-punctuation-2bit-encoding]]（字符级隐写）。

## 检测与防御

- 检测：注册表中出现按数字命名的单字符值、可疑服务名/参数、异常 `ImagePath`；对 `.reg` 文件做字符串与结构审计。
- 防御：限制普通用户写注册表敏感位置；对注册表导出文件做 DLP；监控服务创建与配置变更。
- 响应：确认恶意注册表修改后，恢复基线、删除异常服务/键值，排查持久化。
