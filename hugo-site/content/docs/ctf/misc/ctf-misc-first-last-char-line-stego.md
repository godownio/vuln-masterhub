---
id: ctf-misc-first-last-char-line-stego
title: 文本行首尾字符隐写：逐行取首尾非空白字符拼 flag
type: scenario
domain: ctf
path: ctf/misc
technique: first-last-char-line-stego
tags:
- ctf
- misc
- text
- steganography
- whitespace
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:23+08:00'
  notes: 已对照原文 I Hate Physics 核对：逐行取首尾非空白字符、拼到第一个 } 截断、跳过 Thisisn0tpartoftheflag 均一致；未实际运行。
url: /docs/ctf/misc/ctf-misc-first-last-char-line-stego/
draft: false
kb_aliases:
- 行首尾隐写
- 首尾字符
- I Hate Physics
- 文本边缘隐写
- line edge stego
---

## 一句话结论

一段被刻意排成很多行的文本，每行的首字符和尾字符按顺序拼接就是 flag；中间的正文只是掩护，空白/缩进是噪声，取每行首尾的非空白字符即可还原。

## 原理

- 文本排版本身可以承载信息：把消息字符放在每行开头/结尾，中间填充无关正文，视觉上像普通笔记。
- 解码规则：对每一非空行，取第一个非空白字符和最后一个非空白字符，按行顺序追加；前几行通常直接拼出 `DawgCTF{`。
- 首尾拼接可能产生重复/多余内容（例如 flag 结束后还有 `Thisisn0tpartoftheflag!`），需要在第一个 `}` 处截断。
- 变体：只取首字符、只取尾字符、首尾交替、按缩进/空格数编码；空白本身也可能是隐写层。
- 该场景不需要图像/加密工具，纯文本处理即可；关键是意识到“排版”也是信道。

## 触发条件

- 文本行数较多、每行长度差异大，正文语义不连贯或像填充。
- 每行首尾字符看起来异常（标点/大小写突变），拼接后出现 flag 前缀。
- 题目名/描述暗示“行”“首尾”“边缘”“笔记排版”等。
- 存在空行/缩进，需要决定是否跳过。

## 利用步骤

1. 按行读取文本，跳过空行（或按题目规则保留）。
2. 对每行取第一个非空白字符和最后一个非空白字符。
3. 按行顺序拼接所有首字符/尾字符。
4. 在拼接结果中查找 `DawgCTF{` 或题目 flag 前缀，截取到第一个 `}`。
5. 若首尾拼接顺序不对，尝试“先所有首字符、再所有尾字符”或首尾交替。

## PoC

```python
from pathlib import Path

def extract_flag(path: str) -> str:
    lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
    out = []
    for line in lines:
        s = line.rstrip("\r\n")
        if not s.strip():
            continue
        left = next((c for c in s if not c.isspace()), "")
        right = next((c for c in reversed(s) if not c.isspace()), "")
        if left:
            out.append(left)
        if right:
            out.append(right)

    joined = "".join(out)
    start = joined.find("DawgCTF{")
    if start == -1:
        raise ValueError("prefix not found")
    end = joined.find("}", start)
    return joined[start:end + 1]

print(extract_flag("STUDYME.txt"))
```

## 变体与关联

- 变体：只取首字符/只取尾字符、首尾交替、按行号奇偶取不同侧。
- 变体：用空格/制表符数量编码（whitespace stego），需统计缩进。
- 变体：多列文本，取每列边缘字符。
- 关联：[[ctf-forensics-snow-whitespace-binwalk-known-plaintext-zip]]（空白隐写）、[[ctf-misc-zero-width-unicode-binary-quinary-stego]]（零宽字符）、[[ctf-misc-repeated-text-fragment-reverse]]（文本碎片）。

## 检测与防御

- 检测：文本行首尾字符异常、正文语义不连贯、行长度分布异常、空白/缩进模式规律。
- 防御：该场景是 CTF 文本隐写；真实系统对文本做规范化/重排可破坏边缘隐写。
- 响应：若业务文本中出现类似模式，按隐写/泄露排查。
