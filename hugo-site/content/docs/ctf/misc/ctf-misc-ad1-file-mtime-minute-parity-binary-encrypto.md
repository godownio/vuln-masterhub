---
id: ctf-misc-ad1-file-mtime-minute-parity-binary-encrypto
title: AD1 镜像批量文件时间戳分钟位二进制：两值映射为 0/1 还原 Encrypto 密码
type: scenario
domain: ctf
path: ctf/misc
technique: ad1-file-mtime-minute-parity-binary-encrypto
tags:
- ctf
- misc
- forensics
- ad1
- timestamp
- mtime
- binary
- encrypto
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:27+08:00'
  notes: '已对照原文 so much 段与图 45-47 核对：AD1 挂载密码 !@#￥%……&（1234567 的键盘 Shift 变换）、0.crypto~ 文件列表与 key is: 1234567、分/秒两值映射 0/1 得 700229c053b4ebbcf1a3cc37c389c4fa、Encrypto 解密 0/1 文件得 DASCTF{85235bd803c2a0662b771396bce9968f} 均一致。未验证点：未拿到 AD1 附件复跑；卡内标 confidence=medium。'
url: /docs/ctf/misc/ctf-misc-ad1-file-mtime-minute-parity-binary-encrypto/
draft: false
kb_aliases:
- so much
- 文件时间戳分钟位隐写
- 时间戳两值二进制
- AD1 镜像取证
- Encrypto 文件解密
---

## 一句话结论

AD1 镜像中有一批体积相同、时间非常接近的小文件时，若修改时间的分钟（或秒）字段只有两种取值，可把一种映射为 0、另一种映射为 1，按文件名顺序每 8 位一组转字节，得到一串 32 位十六进制密码；用它在 Encrypto 中解密编号对应的小文件，即可得到 flag。

## 原理

- **时间戳是多字段的信道**：文件系统保存年/月/日/时/分/秒（以及纳秒）。正常批量生成的文件时间戳通常连续或相同；如果某个字段（如分钟、秒）被刻意控制成只有 0/1 两种值，就可作为二进制位。
- **位序与分组**：文件名（0.crypto、1.crypto、…）提供稳定顺序；把每个文件的分钟值（或秒值/奇偶性）映射为 bit，按顺序每 8 位组成一个字节，再转 ASCII/十六进制。本例 32 个字节正好得到 32 个十六进制字符（16 字节），即 `700229c053b4ebbcf1a3cc37c389c4fa`。
- **密码来源**：AD1 镜像本身可能需要口令挂载（文件内容中可见提示）；镜像内的 `.crypto` 文件由 Encrypto 加密，密码就是时间戳信道解出的十六进制串。用密码解密编号 0、1 的文件即得 flag。
- **为什么隐蔽**：文件内容看起来是加密数据，时间戳只差几分钟/几秒，肉眼容易忽略；只有把时间字段的取值分布做统计，才会发现“只有两种值”的异常低基数。

## 触发条件

- 题目给 AD1/镜像/磁盘取证附件，内部有大量命名规律的小文件（如 `0.crypto`~`N.crypto`），内容不可直接读。
- 文件时间戳高度集中，但某个字段只有两种取值（分钟 0/1、秒 0/1、或奇偶），与文件编号顺序相关。
- 存在 Encrypto 等文件加密工具生成的 `.crypto` 文件；密码可能是十六进制/短字符串。
- 挂载/解密密码可能藏在镜像文件头、文件名、二进制可见字符串中（本例为键盘 Shift 变换后的字符）。

## 利用步骤

1. 用 FTK Imager/其他工具挂载 AD1 或直接解析镜像；若需要密码，先在镜像/文件中找提示（如 `key is: 1234567`），并尝试键盘 Shift 变换（`1234567` → `!@#￥%……&`）。
2. 导出文件列表及全部时间戳（mtime/atime/ctime）；按文件名中的数字排序（不要按字典序）。
3. 统计每个时间字段的取值集合：年/月/日/时/分/秒。寻找只有两种取值的字段（本例为分钟或秒）。
4. 选一种值映射为 1、另一种为 0（两种都试），按文件顺序拼接 bit，每 8 位转一个字节；尝试 ASCII 与十六进制两种解释。
5. 用得到的字符串作为 Encrypto 密码，解密编号最小/最可疑的文件（如 `0.crypto`、`1.crypto`）；若失败，尝试 bit 取反、LSB-first、换字段（秒/分钟/奇偶）。
6. 明文即 flag；用同样方法批量解密其余文件，确认结果一致。

## PoC

```python
import os

files = sorted(
    [f for f in os.listdir("extracted") if f.endswith(".crypto")],
    key=lambda x: int(os.path.splitext(x)[0]),
)
minutes = [(int(os.stat(os.path.join("extracted", f)).st_mtime) // 60) % 60 for f in files]
print("unique minutes:", sorted(set(minutes)))

def decode(bits, label):
    data = bytes(int("".join(bits)[i:i+8], 2) for i in range(0, len(bits) - 7, 8))
    print(label, data)

# 两种映射都试；也可换秒/奇偶字段
lo, hi = min(minutes), max(minutes)
decode(["1" if m == hi else "0" for m in minutes], "map_hi=1")
decode(["1" if m == lo else "0" for m in minutes], "map_lo=1")
```

```text
# 该题示例：二进制串按 8 位分组解码得到
# 700229c053b4ebbcf1a3cc37c389c4fa
# 用该串在 Encrypto 中解密 0.crypto/1.crypto，得到：
# DASCTF{85235bd803c2a0662b771396bce9968f}
```

## 变体与关联

- **字段变体**：分钟、秒、小时、毫秒/纳秒、atime/ctime；也可能是字段的奇偶性（`minute % 2`）而不是具体值。
- **顺序变体**：文件名数字序、目录项顺序、按时间升序、按大小；需逐一尝试。
- **编码变体**：bit 直接转 ASCII、转十六进制、取反、LSB-first、每 4 位/6 位分组（十六进制/Base64）。
- **密码使用变体**：Encrypto、VeraCrypt、ZIP、KeePass；解出的字符串可能是密码、密钥或下一层提示。
- **关联卡片**：[[ctf-misc-mtime-last-three-digits-ascii]]（mtime 末三位 ASCII）、[[ctf-misc-mtime-ordered-filename-base64-fragments]]（mtime 排序文件名碎片）、[[ctf-misc-broken-docx-zip-mtime-thumbnail-stego]]（ZIP 条目 mtime 隐写）、[[defense-forensics-mysql-binlog-delete-row-recovery]]（取证时间线分析）。
- **边界**：时间戳被压缩包/镜像格式截断精度（ZIP DOS 时间 2 秒精度）、被统一重置、或字段取值多于两种时，需要重新找信道；Encrypto 密码错误时无法解密。

## 检测与防御

- **检测**：统计目录内文件时间戳各字段的唯一值数量；正常文件应分散，若某字段只有 0/1 或两值且与编号强相关，即可疑；检查 `.crypto` 等加密文件与时间戳的对应关系。
- **防御/取证**：打包/上传前统一时间戳（`touch -d`、`tar --mtime`）会破坏该信道；取证时保留原始时间戳，不要用会重写元数据的复制工具。
- **CTF 技巧**：先导出全部元数据做低基数字段统计，再按文件顺序做位映射；二进制解不出时尝试十六进制/ASCII/取反/换字段。
