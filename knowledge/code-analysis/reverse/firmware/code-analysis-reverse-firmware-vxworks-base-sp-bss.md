---
id: code-analysis-reverse-firmware-vxworks-base-sp-bss
title: VxWorks 初始化结构恢复基址：_sysInit 初始栈指针与 usrInit BSS 清零
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: vxworks-base-sp-bss
aliases:
- 初始栈指针基址
- SP 获取基址
- BSS 清零基址
- usrInit
- _sysInit
- RAM_LOW_ADRS
tags:
- reverse
- firmware
- vxworks
- stack-pointer
- bss
- base-address
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:15:24+08:00'
  notes: 已对照原文与截图核对：NOE-711 _sysInit lis r1,1; addi r1,r1,-0x10; b sub_1CD94 得 r1=0x10000，NOE-771 r3=0x339418、r4=0x490D2C-0x339418=0x157914、4721964=0x480D2C、base=0x10000 均一致（原文一处 0x49D02C 为笔误，卡片按截图与最终计算写 0x490D2C）；未实际运行。
---

## 一句话结论

VxWorks 的 `_sysInit` 在跳转 `usrInit` 前会把栈指针设为初始化栈地址（`RAM_LOW_ADRS`），该地址就是固件加载基址；另一条路是利用 `usrInit` 首先清零 BSS：找到 BSS 清零函数的起始/结束地址，用 `BSS 结尾 - 固件镜像长度` 也可得到基址。

## 原理

- VxWorks 启动：`_sysInit`（汇编，sysALib.s）设置初始硬件状态，然后跳转 `usrInit`（第一个 C 函数）；内存布局中 Initial Stack 位于 `RAM_LOW_ADRS`，System Image（text/rodata/data/bss）紧邻其上。
- 因此 `_sysInit` 设置的栈指针 `r1`（PPC）或 `sp`（ARM/MIPS）就是固件加载基址；示例 NOE-711（PowerPC 大端）中 `lis r1,1; addi r1,r1,0` 得到 `r1=0x10000`，再 `addi r1,r1,-0x10` 开辟 0x10 栈空间，随后 `b sub_1CD94`（usrInit），基址即 0x10000。
- BSS 法：`usrInit` 第一步把 BSS 段清零；在反汇编中找到清零函数（如 `sub_1C400`），其参数寄存器给出 BSS 起始与长度。示例：`r3=0x339418`（BSS 起始），`r4=0x490D2C-0x339418=0x157914`（长度），BSS 结尾 `0x490D2C`。
- 固件镜像大小可从文件系统 `ls -l` 得到（示例 4721964 字节 = 0x480D2C）；VxWorks 内存布局中 BSS 结尾紧接镜像末尾，因此 `base = BSS_end - image_size = 0x490D2C - 0x480D2C = 0x10000`。
- 两种方法互相验证：SP 法直接给出初始栈地址，BSS 法用镜像长度反推；结果一致时可确认基址。

## 触发条件

- 目标是 VxWorks 固件（binwalk 可见 VxWorks 版本/符号），且能定位 `_sysInit`/`usrInit` 或 BSS 清零函数。
- 有架构对应的调用约定（PPC r1/r3/r4、ARM sp/r0-r3、MIPS sp/a0-a3）。
- 固件镜像大小已知（文件长度），且 BSS 结尾可从清零函数参数得到。
- 能确认初始栈/ BSS 在内存布局中的位置（参考 VxWorks 文档）。

## 利用步骤

1. `binwalk -A` 确认架构与大小端；`binwalk -e` 提取固件镜像。
2. 定位入口/`_sysInit`：查看固件首部代码，找设置栈指针后跳转 `usrInit` 的片段。
3. SP 法：记录栈指针值（如 `r1=0x10000`），该值即基址；注意是否减去栈空间（如 `-0x10`）。
4. BSS 法：在 `usrInit` 中找第一个调用的清零函数，记录 BSS 起始/长度/结尾。
5. 计算 `base = BSS_end - firmware_size`；与 SP 法结果对比。
6. 在 IDA 中 rebase 到该基址，检查函数/字符串引用是否正常。

## PoC

```text
# PPC 示例（NOE-711）
lis   r1, 1          ; r1 = 0x10000
addi  r1, r1, 0
addi  r1, r1, -0x10  ; 开辟 0x10 初始栈
b     sub_1CD94      ; usrInit
# => base = 0x10000

# BSS 示例（NOE-771）
r3 = 0x339418                 # BSS start
r4 = 0x490D2C - 0x339418      # BSS length = 0x157914
BSS_end = 0x490D2C
image_size = 4721964 = 0x480D2C
base = BSS_end - image_size = 0x490D2C - 0x480D2C = 0x10000
```

## 变体与关联

- 变体：ARM/MIPS 的栈指针寄存器不同（sp、$sp），但“初始栈地址=加载基址”的思路相同。
- 变体：BSS 清零可能被内联/优化，需找 `memset` 调用或循环清零片段。
- 变体：镜像被压缩/加密时，先解压再按实际镜像长度计算。
- 关联：[[code-analysis-reverse-firmware-vxworks-base-jump-table]]（跳转表法）、[[code-analysis-reverse-firmware-vxworks-symbol-table-base]]（符号表法）、[[code-analysis-reverse-firmware-stm32-hal-function-identification]]（固件函数识别）。

## 检测与防御

- 检测：固件首部设置固定栈指针、BSS 清零函数、VxWorks 内存布局特征。
- 防御：固件加载地址随机化/位置无关、剥离符号、压缩/加密镜像；但初始化结构仍可能泄露基址。
- 响应：确认基址泄露后，评估固件敏感逻辑/密钥暴露，升级固件保护。
