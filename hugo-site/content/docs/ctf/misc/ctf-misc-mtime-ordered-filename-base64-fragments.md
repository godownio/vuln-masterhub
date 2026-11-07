---
id: ctf-misc-mtime-ordered-filename-base64-fragments
title: 按 mtime 排序文件名碎片重组 Base64：噪声过滤 + 增量解码恢复 flag
type: scenario
domain: ctf
path: ctf/misc
technique: mtime-ordered-filename-base64-fragment-reassembly
tags:
- ctf
- misc
- mtime
- timestamp
- base64
- fragment
- reassembly
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:19:23+08:00'
  notes: 已对照原文与图20核对：文件 mtime 21:01-21:49 升序、Base64 碎片与增量解码脚本、flag 一致；未在本机复跑
url: /docs/ctf/misc/ctf-misc-mtime-ordered-filename-base64-fragments/
draft: false
kb_aliases:
- ChronoFolder
- 修改时间排序
- 文件名 Base64 碎片
- 时间戳隐写
- 增量 Base64 解码
- 噪声片段过滤
---

## 一句话结论

题目给出一堆以 Base64 片段命名的 `.txt` 文件，文件名本身是数据、修改时间（mtime）是顺序；按 mtime 升序拼接文件名（去扩展名），再人工/程序过滤噪声片段，对候选做增量 Base64 解码并保留可打印结果，即可恢复 `Vianu_CTF{t1m3_m@st3r_4728290}`。

## 原理

- **文件名承载数据**：每个文件内容无关紧要，文件名前缀（如 `Vmlh`、`bnVf`、`Q1RG`、`e3Qx`…）是 Base64 字符串的片段；单独看是乱码，拼起来才是完整编码。
- **mtime 承载顺序**：文件系统保存修改时间，题目按正确顺序写入文件，因此 `getmtime()` 升序就是片段顺序；文件名/字母序、大小序都不对。
- **噪声片段**：文件列表中含有 `erero`、`gerw8`、`7lei`、`Pow21`、`6767...` 等不参与最终 Base64 的干扰项；直接全拼会解码失败或得到乱码。
- **增量解码**：Base64 每 4 个字符一组，拼接过程中长度可能不是 4 的倍数，需要补 `=`；每加入一个候选片段就尝试 `base64.b64decode`，若解码结果可打印字符比例 >90% 则接受，否则回退。这样可以在有噪声的情况下自动找出正确片段序列。
- **人工筛选 + 自动续接**：先根据可见的 `VmlhbnVfQ1RGe3QxbTNfbUBzdDNyXzQ3Mj` 前缀（解码为 `Vianu_CTF{t1m3_m@st3r_472...`）确定起点，再让脚本在候选中逐个尝试追加，直到补全 `}`。
- **为什么成立**：Base64 是确定性编码，正确片段序列必然解码为合法文本；错误片段会破坏分组/产生不可打印字节，因此可用“可打印比例”作为筛选启发式。

## 触发条件

- 题目提供大量小文件，文件名/内容看似随机片段，无显式顺序。
- 文件 mtime 被设置为有意义的顺序（或可通过 `ls -lt`/`stat` 观察）。
- 片段属于 Base64/Base32/Hex 等可拼接编码，且存在少量噪声片段。
- 允许读取文件元数据（mtime）并按时间排序。

## 利用步骤

1. 列出目录，确认文件数量、命名规律；用 `stat`/`ls -lt` 查看 mtime，判断是否存在明显时间顺序。
2. 用脚本按 `os.path.getmtime` 升序排序，取文件名去扩展名，用空格拼接。
3. 观察拼接结果，人工识别 Base64 起始片段（如 `VmlhbnVfQ1RG...`）并解码出可读前缀。
4. 将剩余片段作为候选，逐个尝试追加到当前 Base64 串，补 `=` 后解码；保留解码结果可打印比例高的片段。
5. 重复直到解码结果出现完整 flag（`}` 结尾）；若卡住，检查是否应使用文件名全名/内容、是否需 Base32/Hex、是否 mtime 精度不足。
6. 输出最终 Base64 与解码文本。

## PoC

```python
import os
import base64
import string

files = [f for f in os.listdir('.') if os.path.isfile(f)]
files.sort(key=lambda f: os.path.getmtime(f))
print(' '.join(os.path.splitext(f)[0] for f in files))

current = "VmlhbnVfQ1RGe3QxbTNfbUBzdDNyXzQ3Mj"
candidates = [
    "SHsa8w", "Ku76", "8sh", "Q1gR", "gyOTB9", "yTfhnj57",
    "Ofwa", "sdhF5", "Hsa", "21H", "ffaH", "Jk28b",
    "poujhg", "cC5pd"
]

def readable(s):
    return sum(c in string.printable for c in s) / len(s) > 0.9

used = set()
progress = True
while progress:
    progress = False
    for b in candidates:
        if b in used:
            continue
        test = current + b
        padded = test + "=" * (-len(test) % 4)
        try:
            decoded = base64.b64decode(padded).decode()
            if readable(decoded):
                print(f"[+] Appended: {b} -> {decoded}")
                current = test
                used.add(b)
                progress = True
                break
        except Exception:
            pass

print(base64.b64decode(current + "=" * (-len(current) % 4)).decode())
```

输出：

```text
Vianu_CTF{t1m3_m@st3r_4728290}
```

## 变体与关联

- 时间通道变体：mtime、atime、ctime、EXIF `DateTimeOriginal`、ZIP 条目时间、邮件 Date 头；顺序可能升序或降序。
- 编码变体：Base32/Base64/Hex/Base85 片段；片段可能在文件名、文件内容、扩展名或目录名中。
- 噪声处理变体：用 CRC/长度/字符集约束、字典匹配、增量解码可打印比例；也可先人工筛选明显合法片段。
- 关联：[[ctf-misc-mtime-last-three-digits-ascii]]（mtime 末三位 ASCII）、[[ctf-misc-broken-docx-zip-mtime-thumbnail-stego]]（ZIP 条目 mtime 异常）、[[ctf-misc-repeated-text-fragment-reverse]]（片段重组）。
- 边界：mtime 被统一重置/精度不足、片段有压缩或加密、噪声比例过高时，纯启发式可能失败。

## 检测与防御

- 检测：CTF 中目录内大量小文件、文件名呈编码字符集、mtime 连续递增；拼接后可解码出可读前缀。
- 防御：CTF 出题时可用精确时间戳/顺序字段；真实场景不要把秘密拆成文件名/时间元数据，元数据可被批量读取。
- 加固：对上传/同步文件清理或统一时间戳；敏感数据不要依赖文件系统元数据隐藏。
