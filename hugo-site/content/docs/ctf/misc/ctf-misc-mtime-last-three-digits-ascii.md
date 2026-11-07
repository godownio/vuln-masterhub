---
id: ctf-misc-mtime-last-three-digits-ascii
title: 文件 mtime 末三位隐写：修改时间戳后三位映射 ASCII 字符
type: scenario
domain: ctf
path: ctf/misc
technique: file-mtime-last-three-digits-ascii
tags:
- ctf
- misc
- timestamp
- mtime
- filesystem
- stego
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:58:11+08:00'
  notes: 已对照原文超级拼装2077与截图核对：43个0字节txt、mtime末三位110/111/...→no flag but something useful:4,3,5、范围4,3,5一致；未验证点：未对附件复跑。
url: /docs/ctf/misc/ctf-misc-mtime-last-three-digits-ascii/
draft: false
kb_aliases:
- 时间戳隐写
- mtime 隐写
- 文件修改时间隐写
- 时间戳末三位
- 空文件时间隐写
---

## 一句话结论

当一批 0 字节文件的修改时间呈现规律时，可把 Unix 时间戳的十进制末三位当作 ASCII 码：按文件名顺序读取 `stat().st_mtime % 1000` 再 `chr()`，就能还原隐藏消息。

## 原理

- **mtime 即 Unix 时间戳**：Linux/macOS 的 `stat.st_mtime` 是自 1970-01-01 UTC 起的秒数（Python 可能带小数）；Windows 也提供等价的最后修改时间。
- **编码方式**：选一个末三位为 `000` 的基准时间 `base`（如本题的 `1559202000`），令 `mtime = base + ord(char)`；只要 `ord(char) < 1000`，十进制末三位就等于字符码，不会进位。解码时 `int(mtime) % 1000`（或 `str(int(mtime))[-3:]`）即字符码。
- **为什么隐蔽**：文件管理器显示的是“2026-01-31 1:59”这类可读时间，不会显示 epoch 末三位；0 字节文件本身没有内容可看，常规 `ls`/`cat` 很难发现。
- **本题**：43 个 `0.txt`~`42.txt` 的 mtime 末三位依次为 110、111、...，`chr(110)='n'`、`chr(111)='o'`，拼出 `no flag but something useful:4,3,5`，其中 `4,3,5` 是下一步猫脸变换的参数提示。

## 触发条件

- 压缩包/目录中大量 0 字节文件，文件名多为数字编号，修改时间相同或非常接近。
- `stat`/`exiftool` 显示秒值奇怪（如 `3382314110`），或所有文件 mtime 都落在一个很小的区间内。
- 题目提示“时间/时间戳/文件属性/排序”。
- 压缩包保留了原始 mtime（ZIP 的 DOS 时间只有 2 秒精度，可能丢失秒级信息；tar/7z 通常保留更完整）。

## 利用步骤

1. 按文件名中的数字排序（不要按字典序，`10.txt` 会排在 `2.txt` 前）。
2. 读取每个文件的 `os.stat(path).st_mtime`，取整数部分。
3. 计算 `code = int(mtime) % 1000`，再 `chr(code % 128)`；若基准时间末三位不是 000，可先减去最小 mtime 或按相邻差值解码。
4. 拼接字符，检查 `flag{`、`no flag`、参数提示等可读内容。
5. 若末三位是十进制但字符码超过 127，尝试 `code` 本身、`code-100`、或把末三位按 BCD/反转处理。
6. 同时检查 atime/ctime、文件大小、文件名编码，排除多信道组合。

## PoC

```python
import os

folder = "stego"
chars = []
for i in range(43):
    p = os.path.join(folder, f"{i}.txt")
    if not os.path.exists(p):
        continue
    mtime = int(os.stat(p).st_mtime)
    code = mtime % 1000
    chars.append(chr(code % 128))
print("".join(chars))
```

说明：PoC 按原文的 `0.txt`~`42.txt` 与 `mtime % 1000` 思路重写；若基准时间末三位非 000，需先对齐基准或改用差值。未在本机对附件复跑。

## 变体与关联

- **atime/ctime**：同样可承载数据；Windows 的创建时间/访问时间也可被 `SetFileTime` 修改。
- **ns 精度**：ext4/NTFS 支持纳秒字段，可把更多位藏进小数部分；Python `st_mtime_ns` 可读。
- **差值编码**：不直接取末三位，而是用相邻文件 mtime 的差值表示字符码，避免基准对齐问题。
- **ZIP 时间戳**：ZIP 的 DOS 时间精度为 2 秒，秒级信息可能被截断；优先用 tar/7z/原始目录。
- **关联**：[[ctf-misc-pptx-slide-image-binary-separator]]（按顺序从文件/图片序列取数据）、[[ctf-forensics-registry-numbered-values-alternating-shift]]（编号值+偏移编码）。

## 检测与防御

- 打包/上传前统一 mtime（如 `touch -d` 或 `tar --mtime`），可消除该信道；但取证时要保留原始时间戳。
- 检测：统计目录内文件 mtime 的末三位分布；正常文件的末三位近似均匀，若大量落在 32–126 的可打印 ASCII 区间，或与文件名序号强相关，即可疑。
- 取证：用 `stat`/`find -printf` 导出 mtime、atime、ctime 与 ns 字段，按时间线分析；不要用会重写时间戳的复制工具（`cp -p` 可保留，普通 `cp` 不一定）。
