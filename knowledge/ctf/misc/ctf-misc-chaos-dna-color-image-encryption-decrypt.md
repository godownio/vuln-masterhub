---
id: ctf-misc-chaos-dna-color-image-encryption-decrypt
title: CTF 彩色图像混沌+DNA 加密题解密：PWLCM/Lorenz 两次置乱 + Chen 选 DNA 规则与迭代异或
type: scenario
domain: ctf
path: ctf/misc
technique: chaos-dna-color-image-encryption-decrypt
aliases:
- 混沌图像加密
- DNA 编码图像加密
- PWLCM 置乱
- Lorenz 置乱
- Chen 超混沌
- SHA-256 图像密钥
- 彩色图像加密 CTF
- 多媒体安全
tags:
- ctf
- misc
- multimedia
- image-encryption
- chaos
- pwlcm
- lorenz
- chen
- dna
- sha256
- crypto
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V506
  verified_at: '2026-11-11T04:45:43+08:00'
  notes: 已对照原文 content.md 与全部 21 张截图逐张核对：题目噪声图、ScienceDirect 论文页、PWLCM/Lorenz/Chen 公式与轨迹、8 种 DNA 规则表、DNA XOR 表(A=00/G=01/C=10/T=11)、DNA_Encode/Decode 代码、加密流程图、CK 公式、排序置乱示意、q0=0.8313904198460218 与 ...99460218(第10位差1e-10)的错误密钥噪声图/解密图、最终 flag 图(flag{5b9f5fa1951f2a97})均与卡片一致；img15 为纯黑截图（密钥生成段截图无有效内容），卡片密钥生成描述以原文代码块为准，已在此备注。核对中修正一处：原文 Chen 的 U 序列代码只有 4 个分支，实际映射 4 种编码规则(AGCT/ACGT/GATC/CATG)，原卡写 8 种，已修正并注明 8 种规则表 rules 用于 XOR 迭代按 start 循环引用；X 解码规则明确为 GTAC/TGCA/CTAG/TCGA。卡片最小 PoC 已用 2000 组随机像素自测加解密可逆(0 失配)。dedup：与库内 ctf-reverse-quadratic-swap-image-encryption-rounds、ctf-misc-png-trailing-data-lcg-xor-base62、Arnold 猫脸变换、螺旋像素置乱等 verified 卡均非同链。affected_versions 不适用(CTF 题/自定义算法)，未设置。未运行原文完整加解密脚本(原文存在运算符优先级/分段公式疑点)，仅自测卡片 PoC。
---

## 一句话结论

遇到按论文实现的彩色图像加密题，先识别方案：SHA-256(原图) 与 KEY 共同生成混沌初值，PWLCM 对 RGB 扁平数组做第一次全局排序置乱、Lorenz 分通道做第二次置乱，再用 Chen 超混沌序列为每个像素选择 DNA 编码规则、XOR 起始位置/迭代次数与解码规则，经多轮 DNA 互补异或扩散；解密时按加密逆序撤销 DNA 迭代异或、逆 DNA 编解码、逆两次排序置乱并合并通道。混沌系统对初值极敏感（q0 差 1e-10 即得到完全不同的噪声图），需从题目线索恢复/爆破正确初值，正确解密后即可看到图片中的 flag。

## 原理

- **密钥生成**：对原图字节求 SHA-256，取十六进制摘要：前 224 位分成 8 块、每块 7 个 hex 数字，除以 2^34 得到 m1..m8；最后 8 个 hex 数字除以 2^38 得到 d；`CK = (a0+p0+u0+v0+w0+x0+y0+z0+q0) mod 1`。每个混沌初值按 `key[i]=(key[i]+m[i]+CK) mod 1`、`key[8]=(key[8]+d+CK) mod 1` 修正后，分别作为 PWLCM、Lorenz、Chen 的初值与参数。密钥依赖原图哈希，因此解密要么持有同一张原图（或其哈希），要么从题目获得/爆破混沌参数。
- **第一次置乱（PWLCM）**：把 R/G/B 三通道合并成 1×3wh 的一维数组；PWLCM 迭代 3wh 次得到序列 A；按 A 的值对像素做 `argsort` 排序（等价于按混沌序列位置重排）；排序后按 `1..wh`、`wh..2wh`、`2wh..3wh` 切回 R/G/B。
- **第二次置乱（Lorenz）**：Lorenz 系统（σ=10、ρ=28、β=8/3）生成 Y/Z/Q 三个序列，丢弃前 t 个值；分别用 Y/Z/Q 对 R/G/B 三个通道的像素做排序重排。
- **DNA 扩散（Chen 超混沌）**：Chen 系统参数 a=36、b=3、c=28、d=16、k=0.2，生成 U/V/W/X 四个序列并按 t 丢弃前段；U 按区间映射为 4 种编码规则之一（AGCT/ACGT/GATC/CATG，原文代码 4 个分支），用于把每个像素编码成 4 个碱基；V 决定 XOR 起始规则位置 `start = int(V*1e12) % 8`，W 决定迭代次数 `times = int(W*1e12) % 8`；随后像素的 DNA 串依次与从 start 开始循环的 8 种规则表 `rules` 做互补异或；X 选择解码规则（GTAC/TGCA/CTAG/TCGA），把 DNA 串解码回 0–255 像素值。
- **DNA 规则与互补异或**：8 种规则是 00/01/10/11 到 A/C/G/T 的 8 种满足 Watson-Crick 互补的映射；DNA 异或可等价为按规则解码成 2 位二进制后做普通异或，再按另一规则编码。加密链是“encode(U) → 迭代 XOR → decode(X)”，解密必须反向：先用 X 规则 encode 密文像素，再按 `rules=(start+times-1)%8` 开始逐次递减做 XOR，最后用 U 规则 decode。
- **两次置乱的逆**：排序置乱是可逆的排列；解密时用同样的混沌序列计算 `argsort` 得到置换，再把排序后的数组按置换散射回原位置（先逆 Lorenz 分通道置乱，再逆 PWLCM 全局置乱）。
- **初值敏感性**：Lorenz/Chen 对初值极端敏感，图中 q0=0.8313904198460218 能解出原图，而 q0=0.8313904199460218（第 10 位不同）解出的是噪声；因此未知参数需要利用题目给出的精度/线索或按最后几位爆破，并用“是否出现可读图像/flag 格式”作为判别。
- **实现注意**：原文代码里 PWLCM 第二段与 `int(U[i] % 1/0.05)` 等写法存在运算符优先级/分段公式疑点，DNA_XOR 固定用 AGCT 解码也依赖具体实现；复现时应以论文公式与加密脚本为准，逐段对齐，否则会出现“能跑但解不出”的情况。

## 触发条件

- CTF 题目给出加密后的彩色图像（通常为高熵噪声图）与算法提示（论文名、加密脚本或部分参数）。
- 能实现/获得与题目一致的 PWLCM、Lorenz、Chen 迭代（步长、丢弃前 t 个值、参数）。
- 知道或能恢复密钥生成所需的原图哈希/KEY 参数（题目可能给出原图、KEY，或只给部分初值让爆破）。
- 图像尺寸、通道数与加密时一致（如 512×512×3）；缩放/格式转换会破坏像素值。

## 利用步骤

1. 从题目描述/附件识别方案：搜索 PWLCM、Lorenz、Chen、DNA、SHA-256 等关键词，确认论文与加密流程。
2. 实现 DNA 编解码与互补异或（8 种规则表），并用简单像素值自测（如 155 在 TCGA 下编码为 GCGA）。
3. 实现 PWLCM、Lorenz、Chen 迭代，注意与加密脚本相同的步长、初始值、丢弃前 t 个值。
4. 复现密钥生成：读取原图字节 → SHA-256 → 8×7 hex 块与末尾 8 hex → 修正各混沌初值；若原图未知，先从题目线索确定 q0 等参数。
5. 解密扩散：按 X 规则 encode 密文像素 → 按 `(start+times-1)%8` 逆序迭代 XOR → 按 U 规则 decode，得到置乱后的像素。
6. 逆第二次置乱（Lorenz），再逆第一次置乱（PWLCM），合并 R/G/B。
7. 保存图像并查看 flag；若为噪声，检查初值/步长/丢弃段/规则表是否与加密脚本一致，或对未知初值做小范围爆破（以图像可读性/flag 格式筛选）。

## PoC

```python
# DNA 编解码与异或（最小实现，规则表见 8 种互补映射）
RULES = ['ACGT', 'CATG', 'GTAC', 'TCGA', 'CTAG', 'AGCT', 'TGCA', 'GATC']

def dna_encode(pixel, rule):
    bits = bin(pixel)[2:].zfill(8)
    return ''.join(rule[int(bits[i:i+2], 2)] for i in range(0, 8, 2))

def dna_decode(base, rule):
    return int(''.join(format(rule.index(ch), '02b') for ch in base), 2)

def dna_xor(a, b):
    return dna_encode(dna_decode(a, 'AGCT') ^ dna_decode(b, 'AGCT'), 'AGCT')

# 解密单个像素的扩散：密文像素先按 X 规则编码，再逆序异或，最后按 U 规则解码
def decrypt_pixel(cipher_pixel, U_rule, X_rule, start, times):
    s = dna_encode(cipher_pixel, X_rule)
    r = (start + times - 1) % 8
    for _ in range(times):
        s = dna_xor(s, RULES[r])
        r = (r - 1) % 8
    return dna_decode(s, U_rule)
```

```text
# 逆置乱（示意）：
# 加密：sorted_pixels = [pixels[i] for i in argsort(chaos_seq)]
# 解密：orig[argsort(chaos_seq)[k]] = sorted_pixels[k]
# 先逆 Lorenz 三通道置乱，再逆 PWLCM 全局置乱，最后按 R/G/B 合并。
```

## 变体与关联

- 变体：同一论文的不同实现可能改混沌参数、DNA 规则顺序、置乱次数或丢弃前 t 个值；以题目加密脚本为准。
- 变体：若只给密文与部分参数，可对初值最后几位爆破，并用图像熵/可读性/flag 格式做 oracle（原文演示 q0 第 10 位差异导致完全不同的结果）。
- 关联：[[ctf-reverse-quadratic-swap-image-encryption-rounds]]（另一种图像置乱加密的逆向）、[[ctf-misc-low-frequency-image-downscale-blur-reveal]]（图像低频/缩放取证）、[[ctf-misc-png-bitplane-zip-base85-shellcode-c2]]（图像位平面隐写）。
- 边界：缺少原图哈希/KEY 且初值未知、图像被缩放或重新压缩、加密脚本与论文不一致且未拿到脚本时，解密会很困难或不可行。

## 检测与防御

- 这是 CTF/多媒体分析技巧，不是通用漏洞；对出题方而言，若想让题目可解，应给出足够线索（论文/脚本/参数范围），否则会退化为不可解爆破。
- 分析侧：高熵彩色噪声图 + 论文关键词是识别此类题目的主要特征；先复现加密脚本再解密，比直接猜参数更可靠。
- 安全启示：图像加密若把密钥绑定到原图哈希、且初值空间可枚举，攻击者可利用已知明文/暴力搜索恢复；真实场景应使用标准密码与足够大的密钥空间，不要依赖自定义混沌方案的“初值敏感性”。
