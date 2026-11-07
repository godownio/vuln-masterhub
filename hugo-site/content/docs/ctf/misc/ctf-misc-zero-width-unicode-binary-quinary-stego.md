---
id: ctf-misc-zero-width-unicode-binary-quinary-stego
title: 零宽字符隐写：U+200B/U+200C 二进制与五进制编码
type: scenario
domain: ctf
path: ctf/misc
technique: zero-width-unicode-binary-quinary-stego
tags:
- ctf
- misc
- stego
- unicode
- zero-width
- encoding
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:48:26+08:00'
  notes: 已对照原文「letter」「CyberPunk」两题核对：letter 的 U+200B/U+200C 各 96 字符按 0/1 每 8 位 ASCII 得 flag{hidden}；Moon.txt 以 U+200B 分隔、U+200E/200F/200C/200D/FEFF 映射 0..4，25 组三位五进制+1 组 1000(五进制)=125('}') 得 flag{butyouarenotbesideme}，PoC 与原文脚本一致。未验证点：未持附件复跑；无版本/CVE；frontmatter 无 sources/source_url。
url: /docs/ctf/misc/ctf-misc-zero-width-unicode-binary-quinary-stego/
draft: false
kb_aliases:
- 零宽字符隐写
- Zero-width steganography
- U+200B 二进制
- 五进制隐写
- 不可见字符编码
---

## 一句话结论

当文本末尾/正文中混入大量不可见 Unicode 字符时，先统计字符种类：若只有 `U+200B`/`U+200C` 两种，可按 0/1 二进制每 8 位转 ASCII；若 `U+200B` 作分隔符、其余零宽字符表示五进制数字，则按分组基数解码，可恢复隐藏的 flag。

## 原理

- **零宽字符不可见但可编码**：`U+200B`（零宽空格）、`U+200C`（零宽非连接符）、`U+200D`（零宽连接符）、`U+200E`/`U+200F`（左右方向标记）、`U+FEFF`（BOM/零宽不换行空格）在正常文本中不显示，但会被 UTF-8 原样保存，因此可作为隐写载体。
- **二进制映射**：两种字符正好表示 0/1；本题 `letter.txt` 署名后有 96 个 `U+200B`/`U+200C`，96/8=12 字节，按每 8 位 ASCII 解码得到 `flag{hidden}`。位序可以是 MSB-first 或 LSB-first，需按可读性尝试。
- **五进制映射**：`U+200B` 作为组分隔符；`U+200E→0`、`U+200F→1`、`U+200C→2`、`U+200D→3`、`U+FEFF→4`。每组 3 个五进制数字表示 `d0*25+d1*5+d2` 的 ASCII 码；本题 25 组三位数恢复 `flag{butyouarenotbesideme`，最后一组四位数 `1000`（五进制）=125=`}`。
- **为什么成立**：隐写只改变字符序列，不改变可见文本；解码是确定性的，只要字符集和分组规则识别正确即可。
- **识别信号**：文件大小/字符数异常、`cat` 看不到但 `xxd`/Python 能看到 `e2 80 8b` 等字节、文本行尾有大量同码点字符、复制到编辑器显示为空白但光标移动异常。

## 触发条件

- 文本文件包含大量不可见 Unicode 字符（U+200B–U+200F、U+FEFF 等）。
- 字符种类有限且重复模式明显；长度能被位宽/分组整除。
- 明文为 ASCII/flag 格式，可用可读性/花括号校验。
- 能按 UTF-8 读取原文件（不要用会丢弃零宽字符的编辑器/管道）。

## 利用步骤

1. 用 Python 按 UTF-8 读取文件，统计所有 `Cf`/零宽字符的码点与数量。
2. 如果只有两种字符：映射为 0/1，按 8 位分组转 ASCII；尝试 MSB-first 与 LSB-first、正反映射。
3. 如果有多字符与分隔符：先按分隔符分组，确定每个字符对应的数字（通常 0..k-1），再按进制权重求和转 ASCII。
4. 用 `flag{`/`}`、可打印字符比例验证；若出现乱码，调整位序、分组方向或映射顺序。
5. 本题两种编码分别得到 `flag{hidden}` 与 `flag{butyouarenotbesideme}`。

## PoC

二进制（U+200B=0，U+200C=1）：

```python
from pathlib import Path

text = Path("letter.txt").read_text(encoding="utf-8")
hidden = "".join(ch for ch in text if ch in {"\u200b", "\u200c"})
bits = "".join("0" if ch == "\u200b" else "1" for ch in hidden)
assert len(bits) % 8 == 0
plain = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
print(plain.decode("ascii"))          # flag{hidden}
```

五进制（U+200B 分隔，其余映射 0..4）：

```python
text = Path("Moon.txt").read_text(encoding="utf-8")
separator = "\u200b"
digits = {"\u200e": 0, "\u200f": 1, "\u200c": 2, "\u200d": 3, "\ufeff": 4}
hidden = "".join(ch for ch in text if ch == separator or ch in digits)
groups = [g for g in hidden.split(separator) if g]

plain = "".join(
    chr(digits[g[0]] * 25 + digits[g[1]] * 5 + digits[g[2]])
    for g in groups[:25]
)
plain += chr(sum(digits[ch] * 5 ** (3 - i) for i, ch in enumerate(groups[25])))
print(plain)                          # flag{butyouarenotbesideme}
```

## 变体与关联

- **变体（其他零宽字符集）**：U+2060、U+180E、U+00AD、变体选择符（U+FE00–U+FE0F）等都可编码；先统计码点再定映射。
- **变体（摩尔斯/二进制/多进制）**：两种字符可表示摩尔斯，多字符可表示任意进制；分组规则可能由题目 hint 给出。
- **变体（混合隐写）**：零宽字符与可见文本、图片 LSB、音频元数据组合；需要逐层剥离。
- **关联卡片**：[[pentest-recon-image-metadata-comment-hidden-path-hydra]]（图片元数据隐藏路径）、[[ctf-forensics-png-lsb-column-major-scan-order]]（PNG LSB 隐写）、[[crypto-classical-pigpen-variant-fence-column-decode]]（另一种符号编码）。
- **边界**：复制/粘贴或编辑器可能丢弃零宽字符；文件编码不是 UTF-8 时需先确认；分组/位序错误会得到乱码。

## 检测与防御

- **检测**：对下载文本/文档做 Unicode 零宽字符扫描（`Cf` 类别、U+200B–U+200F、U+FEFF），统计异常密度；DLP/邮件网关可标记。
- **防御**：对用户生成内容做 Unicode 规范化（NFKC）并移除 `Cf` 字符；展示层保留原文但导出时清洗。
- **CTF 识别**：看到“字里行间/不可见/信息隐藏”与异常字符数，优先按本卡提取；用 `xxd` 确认 UTF-8 字节。
