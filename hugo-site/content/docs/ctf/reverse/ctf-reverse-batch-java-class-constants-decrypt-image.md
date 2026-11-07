---
id: ctf-reverse-batch-java-class-constants-decrypt-image
title: 1264 个 Java class 各自解密小段字节：批量反编译拼接 PNG
type: scenario
domain: ctf
path: ctf/reverse
technique: batch-java-class-constants-decrypt-image
tags:
- ctf
- reverse
- java
- class
- jadx
- batch
- xor
- image
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:05:33+08:00'
  notes: 已对照原文与图片核对：enc/iArr、rol8、逆减法与异或、1264类拼接与PNG flag一致；原文口述4字节与代码8字节差异已在卡内说明；未本机执行。
url: /docs/ctf/reverse/ctf-reverse-batch-java-class-constants-decrypt-image/
draft: false
kb_aliases:
- 风吹桶屋
- Chal0000
- 批量 class 逆向
- Java 字节码批量解密
- 千类拼接
---

## 一句话结论

题目给出 1264 个 `Chal0000.java` 式的小类，每个类用自己的 `enc[8]` 常量数组和 `iArr[8]` 参数做“循环异或 + 减法”变换，解密出一小段字节；批量导出反编译源码、按类名顺序逐个重放变换并拼接输出，即可得到一张 PNG，查看图片得到 flag。

## 原理

- **每类独立密钥**：每个 `ChalXXXX` 类都有 `private static final byte[] enc = {...}` 与 `int[] iArr = {...}`，长度均为 8；`main` 从标准输入读 8 字节，先与 `iArr[i]` 的循环移位值异或，再减去 `iArr[(i + add_off) % 8]`。由于参数逐类不同，不能用一个固定密钥解全部类。
- **循环移位表达式**：反编译代码为 `readNBytes[i2] = (byte)(readNBytes[i2] ^ ((byte)((iArr[i] >> 7) | (iArr[i] << 1))))`。这个表达式本质是把 `iArr[i]` 的低 8 位循环左移 1 位（`rol8(x,1)`）：`x >> 7` 取最高位，`x << 1` 左移，两者按位或。原文的解析脚本把 `>> 7` 与 `<< 1` 分别捕获为 `xor_r`、`xor_l`，因此不能硬编码 3/5。
- **加法偏移**：第二段循环为 `readNBytes[i4] = (byte)(readNBytes[i4] - iArr[(i3 + add_off) % 8])`，`add_off` 也逐类不同，需从源码正则提取。
- **批量拼接**：类名 `Chal0000` 到 `Chal1263` 给出顺序；每个类解出 8 字节，按序号拼接得到完整文件。原文口述“每个 class 是四个字节”，但截图代码显示 `readNBytes(8)`、`enc[8]`、`iArr[8]`，以代码为准（每类 8 字节）；若拼接结果头部不是 PNG 魔数，先检查是否需要每类只取前 4 字节或调整顺序。
- **为什么可行**：这是“把一个大文件切成很多小段、每段用独立轻量变换隐藏”的典型 CTF 逆向题。单类分析没有意义，必须自动化提取常量并重放；反编译工具（jadx）批量导出伪代码后，正则解析比逐类手工抄写可靠。

## 触发条件

- 附件是大量（成百上千）命名规律的小 class/java 文件，单类代码结构高度相似。
- 每个类都含 `private static final byte[] enc`、`int[] iArr` 和 `main`，且 `main` 中出现异或、移位、减法等逐字节变换。
- 类名/文件名带递增序号（`Chal0000`、`Chal0001`…），提示需要按序拼接。
- 拼接结果以常见文件魔数开头（PNG 为 `89 50 4E 47`，JPEG 为 `FF D8 FF`）。

## 利用步骤

1. 用 `jadx-gui` 打开 class 目录/jar，使用“导出源码”得到每个类的 Java 伪代码；确认类名与文件序号的对应关系。
2. 对每个文件用正则提取：`enc` 数组、`iArr` 数组、异或的右移/左移位数、减法使用的加法偏移。
3. 按类中 `main` 的实际顺序重放逆变换：先逆异或（`b ^= rol8(iArr[i], r)`），再逆减法（`b = (b - iArr[(i + off) % 8]) & 0xFF`）；注意原代码是先异或后减法，逆向时顺序要反过来。
4. 把每个类的结果按 `Chal` 序号从小到大拼接，写入 `flag.png`；检查 PNG 魔数与 IHDR，确认图片可打开。
5. 若图片花屏/错位，尝试每类只取前 4 字节、交换异或/减法顺序、或把 `rol8` 改为 `ror8`；以 PNG 魔数与 CRC 为校验。
6. 打开图片读取 flag（原文得到 `sknb{now_you_can_say_bye_bye_bytecode_...}` 形式）。

## PoC

按原文脚本整理（未在本机对附件执行）：

```python
import re
from pathlib import Path

SRC_DIR = Path("src/sources/p000")
OUT = Path("flag.png")

def java_int(s: str) -> int:
    s = s.strip()
    if s == "Byte.MIN_VALUE":
        return -128
    if s == "Byte.MAX_VALUE":
        return 127
    return int(s)

def extract(java_file: Path):
    text = java_file.read_text(encoding="utf-8")
    enc = re.search(r"private static final byte\[\] enc\s*=\s*\{([^}]*)\}", text)
    iarr = re.search(r"int\[\] iArr\s*=\s*\{([^}]*)\}", text)
    if not enc or not iarr:
        return None
    enc = [java_int(x) for x in enc.group(1).split(",")]
    iarr = [java_int(x) for x in iarr.group(1).split(",")]

    xor_m = re.search(r"readNBytes\[i2\].*\^.*iArr\[i\].*>>\s*(\d+).*<<\s*(\d+)", text)
    add_m = re.search(r"readNBytes\[i4\].*\+.*iArr\[\(i3\s*\+\s*(\d+)\)\s*%\s*8\]", text)
    xor_r, xor_l = (int(xor_m.group(1)), int(xor_m.group(2))) if xor_m else (7, 1)
    add_off = int(add_m.group(1)) if add_m else 1
    return enc, iarr, xor_r, xor_l, add_off

def decrypt(enc, iarr, xor_r, xor_l, add_off):
    arr = enc[:]
    # 逆减法
    for i in range(len(arr)):
        arr[i] = (arr[i] - iarr[(i + add_off) % 8]) & 0xFF
    # 逆循环异或
    out = []
    for i, v in enumerate(arr):
        key = ((iarr[i] >> xor_r) | (iarr[i] << xor_l)) & 0xFF
        out.append((v ^ key) & 0xFF)
    return bytes(out)

buf = bytearray()
for i in range(1264):
    f = SRC_DIR / f"Chal{i:04d}.java"
    if not f.exists():
        continue
    parsed = extract(f)
    if parsed:
        buf += decrypt(*parsed)
OUT.write_bytes(buf)
print("wrote", OUT, len(buf))
```

## 变体与关联

- **变换变体**：先减后异或、`ror8` 代替 `rol8`、加法偏移作用于 `enc` 下标而非 `iArr`、每类 4/8/16 字节。
- **打包变体**：类文件不以源码形式给出，而是 jar/class 字节码；可用 CFR/Procyon 批量反编译，或用 ASM 直接读常量池。
- **拼接变体**：类名序号有跳号/乱序，需要按 `Chal` 编号排序；或每类输出带长度/校验头，需先剥离。
- **关联**：[[ctf-reverse-java-string-hash-8digit-bruteforce]]（Java 逐字符校验）、[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（rol8/加法逆向）、[[ctf-reverse-multi-witness-partial-constraint-base32-enumeration]]（分片约束拼接）。
- **边界**：原文的正则依赖 jadx 的变量命名（`i2`/`i4`/`i3`），换反编译器可能不匹配；应以语义（异或/移位/减法）为准，不要死盯变量名。

## 检测与防御

- **CTF 识别**：成百上千个结构相同的小类、每类自带常量数组、类名递增，是“批量小段加密”的强特征；先抽样 2–3 个类确认变换模板，再写脚本。
- **自动化要点**：优先用反编译器的批量导出，不要逐类手动打开；正则解析后抽样验证 1–2 个类的手算结果，再用输出文件魔数/CRC 做全局校验。
- **防御（真实系统）**：这种“分片 + 轻量混淆”不是加密，字节码中常量可完整恢复；若用于保护敏感数据，应使用标准加密并避免把密钥与密文放在同一产物中。
- **出题思路**：用大量重复结构迫使选手自动化；把参数藏在每个类的常量里，避免一个全局密钥被一次性提取。
