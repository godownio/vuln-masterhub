---
id: code-analysis-reverse-firmware-uboot-bindiff-symbol-custom-base58
title: 剥离符号 U-Boot 固件逆向：同版本源码编译 + BinDiff 恢复 main_loop 符号，逆 XOR 0x72 与自定义 Base58 表
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: uboot-bindiff-symbol-recovery-custom-base58
tags:
- reverse
- firmware
- uboot
- bindiff
- base58
- symbol-recovery
- arm
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V246
  verified_at: '2026-11-07T12:58:28+08:00'
  notes: 已对照原文及25张图核对：U-Boot 去符号+同版本源码 BinDiff 恢复 main_loop、sub_60813F74 对37字节 ^0x72、自定义表 Base58、CyberChef 输出 LILCTF{Ub007_1s_v3ry_ez} 均一致；未验证点：未实际编译/BinDiff，完整58字符表原文截断，需从样本提取。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-uboot-bindiff-symbol-custom-base58/
draft: false
kb_aliases:
- Oh_My_Uboot
- u-boot bindiff
- U-Boot 符号恢复
- 自定义 Base58 表
- 0x72 XOR
---

## 一句话结论

拿到去掉符号的 U-Boot 镜像时，先判断版本并拉取同版本源码，用相同架构/配置编译出带符号的参考镜像，再用 BinDiff 对齐函数恢复 `main_loop` 等符号；本题由 `main_loop` 跟踪到校验函数，它把 37 字节常量逐字节 XOR 0x72 后用自定义字母表做 Base58 比较，按“自定义表 Base58 解码 → 逐字节 XOR 0x72”即可得到 flag。

## 原理

- U-Boot 是版本化、可复现编译的引导程序；同一版本、同一架构、相近配置编译出的镜像与目标镜像函数结构高度相似。BinDiff 按函数签名/调用图/指令特征匹配，能把无符号函数的地址映射到源码符号，从而恢复 `main_loop`、`printf`、命令解析等关键函数。
- `main_loop` 是 U-Boot 的主循环，通常包含控制台读入、命令解析和循环条件；在反编译中表现为一个持续读取字符、处理回车（13）和退格（8）的循环，容易与普通函数区分。
- 本题核心函数（文章 `sub_60813F74`）先把一个 38 字节常量 `memcpy` 到栈缓冲，再对前 37 字节执行 `*v2++ ^= 0x72`；之后读取用户输入（回车结束、退格删除、回显 `*`），调用 `sub_60813E3C` 做 Base58 编码，最后 `sub_60864138(a2, "5W2b...")` 与固定串比较；不匹配则主循环继续。
- 比较串使用的是**自定义 Base58 字母表**，不是 Bitcoin 的标准表；文章给出的表形态为 `0123456789:;<=>?@ABC...XYZ[]^_`...` 一类自定义顺序（完整 58 字符表以二进制中提取的为准）。标准 Base58 解码会因字母表不同而失败。
- 正确的解密顺序是“先按自定义表 Base58 解码，再逐字节 XOR 0x72”：解码得到的是 XOR 后的字节，XOR 是对称的，再异或一次即得明文。文章用 CyberChef 的 `From Base58`（自定义 alphabet）+ `XOR 0x72` 得到 `LILCTF{Ub007_1s_v3ry_ez}`，可据此确认方向。
- 反编译伪代码中 `memcpy(result, ..., 38, dword_608864E4)` 出现 4 个参数，是类型缺失/优化导致的失真；应以汇编的寄存器/栈数据流为准。
- 成立条件：能判断目标 U-Boot 版本并取得同版本源码；能编译出相近配置的带符号镜像；BinDiff/IDA 可用；目标中有固定比较串。

## 触发条件

- 目标为无符号 U-Boot 或包含 U-Boot 的固件镜像，镜像中可见版本 banner/字符串。
- 可获取 u-boot/u-boot 同版本源码，并能按目标架构编译（ARM/MIPS 等）。
- 镜像中存在固定长度比较、自定义 Base58 字母表或固定 XOR key 的校验逻辑。

## 利用步骤

1. 用 `strings`/十六进制查看 U-Boot banner、版本字符串、编译时间，确定版本与架构。
2. 拉取对应版本 u-boot 源码，用相近 defconfig/工具链编译出带符号的 ELF 或镜像；保留符号表。
3. 在 IDA 中同时加载目标无符号镜像与带符号参考镜像，运行 BinDiff（或 Diaphora），按相似度匹配函数，恢复 `main_loop` 等关键符号。
4. 从 `main_loop` 的交叉引用/调用图定位校验函数（本题 `sub_60813F74`），确认：38 字节常量、37 次 `^= 0x72`、字符读入循环、Base58 编码调用与固定比较串。
5. 从二进制 `.rodata` 提取完整 58 字符自定义 Base58 表；从比较调用处提取固定串。
6. 按自定义表 Base58 解码固定串，再逐字节 XOR 0x72，得到 flag；用“flag XOR 0x72 后按同一表 Base58 编码”做闭环验证。
7. 若目标镜像版本无法精确匹配，可先用字符串/调用图定位 `main_loop`，再用局部 BinDiff 或手动比对相邻函数提高置信度。

## PoC

```python
# alphabet 必须从目标二进制中提取；下例仅示意自定义表解码流程
alphabet = "<从 .rodata 提取的 58 字符自定义字母表>"
s = "5W2b9PbLE6SIc3WP=X6VbPI0?X@HMEWH;"

n = 0
for ch in s:
    n = n * 58 + alphabet.index(ch)
raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
print(bytes(b ^ 0x72 for b in raw).decode("utf-8", "replace"))
# 期望得到 37 字节左右的 flag
```

CyberChef 等价配方：`From Base58`（Alphabet 填二进制中提取的自定义表，勾选 Remove non-alphabet chars）→ `XOR`（Key `0x72`, Standard）。

说明：文章截图中的字母表字段被截断，完整表需自行从样本提取；不要在未确认表顺序时套用标准 Bitcoin Base58 表。

## 变体与关联

- 版本/配置不一致：若无法精确复刻编译配置，BinDiff 相似度会下降；可先用 U-Boot 版本字符串缩小范围，再用函数调用图与字符串交叉引用辅助定位。
- 编码变体：Base58 表可替换为 Base64/Base62；比较前可能是 XOR、加常量或按位取反，按比较函数的数据流确定方向。
- 校验位置变体：校验可能位于 U-Boot 命令处理函数、环境变量读取或启动脚本中；从 `main_loop`/命令表交叉引用回溯。
- 关联：[[code-analysis-reverse-firmware-vxworks-symbol-table-base]]（固件符号表恢复的另一路线）、[[code-analysis-reverse-windows-legit-dll-modification-bindiff]]（BinDiff 定位差异函数的用法）、[[ctf-forensics-iso-isolinux-base58-hidden]]（Base58 解码基础）。
- 边界：BinDiff 只恢复“相似函数”的符号，不保证语义完全一致；关键结论仍需回到目标镜像的汇编验证。

## 检测与防御

- 分析侧：先恢复符号再读代码，比在无符号镜像上逐函数硬啃效率高得多；BinDiff 结果要结合字符串/调用图交叉验证。
- 固件设计侧：自定义 Base58 表与固定 XOR 只是编码混淆，不能作为安全边界；敏感校验应使用带密钥的密码学算法并保护密钥。
- 检测思路：固件中出现 U-Boot banner、Base58 字符集比较、固定 XOR 循环与硬编码比较串，可作为 CTF/固件题目的识别特征。
