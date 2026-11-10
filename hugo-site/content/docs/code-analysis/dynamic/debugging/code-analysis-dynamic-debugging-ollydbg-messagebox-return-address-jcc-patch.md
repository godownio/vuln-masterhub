---
id: code-analysis-dynamic-debugging-ollydbg-messagebox-return-address-jcc-patch
title: OllyDbg 爆破注册框：MessageBoxA 断点取栈返回地址定位关键跳转，je 改 jmp 后复制所有修改保存补丁
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: ollydbg-messagebox-return-address-jcc-to-jmp-patch
tags:
- reverse
- ollydbg
- dynamic-analysis
- breakpoint
- patch
- crackme
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V411
  verified_at: '2026-11-09T14:48:16+08:00'
  notes: 已对照原文与截图核对：Ctrl+N 名称窗口可见 GetDlgItemTextA/MessageBoxA（04）、MessageBoxA 输入函数断点（05/06）、命中时栈返回地址 004013C1（07）、跟随回 00401387 的 je short 0040139C 并汇编为 jmp（08-12）、第二处 00401243 je short 0040124C 改 jmp（30）、复制到可执行文件→所有修改→全部复制→保存 CRACKME_modified.EXE（16/18/19/20）、Good work 成功（21）均一致；74→EB 两字节同长替换表述正确。未验证点：PoC 未实际执行；修复后『任意输入』成功依赖第一处 401387 改 jmp 从而跳过整个字母校验循环，卡片已按多级校验描述。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-ollydbg-messagebox-return-address-jcc-patch/
draft: false
kb_aliases:
- OllyDbg 爆破
- 无情破解
- 一路通天
- MessageBoxA 断点
- je 改 jmp
- 关键跳转修改
---

## 一句话结论

对用弹窗提示“注册失败/成功”的原生 Win32 注册程序，在 `MessageBoxA` 下断点，程序停在失败弹窗时从栈上取返回地址，跟随回调用点即可找到 `MessageBoxA` 前的条件跳转；把 `je` 改成 `jmp`（或反转条件跳转）跳过失败分支，用 OllyDbg“复制到可执行文件→所有修改”保存补丁，即可让任意输入都走成功路径。

## 原理

- **弹窗即锚点**：程序无论输入什么都要通过 `MessageBoxA` 显示结果，失败弹窗的调用点就位于校验逻辑之后；在 `MessageBoxA` 上断点，命中时栈顶保存的返回地址就是“调用 MessageBoxA 的下一条指令”，它所在的函数即校验函数。
- **返回地址回溯定位分支**：在栈窗口选中返回地址 → 在反汇编窗口跟随，向上分析可看到 `je short <成功分支>` 之类的条件跳转：条件成立（校验通过）时跳过失败弹窗，不成立时落入失败 `MessageBoxA`。把该 `je` 改为 `jmp`，无论校验结果如何都跳向成功路径。
- **多级校验同样处理**：注册程序常先校验 Name 格式（如必须为纯字母），再校验 Serial；每次失败弹窗都在 `MessageBoxA` 断点处停住，按同样方法回溯并修改对应 `je`，直到所有失败分支被绕过。
- **补丁固化**：OllyDbg 的修改默认只在内存中；需要“复制到可执行文件→所有修改→全部复制”，在补丁窗口另存为新 EXE，才能得到永久生效的破解文件。
- **机器码层面**：`je short` 是 `0x74 rel8`，`jmp short` 是 `0xEB rel8`，两者都是两字节、只改操作码；OllyDbg 汇编窗口的“使用 NOP 填充”可在指令长度不一致时补齐。

## 触发条件

- 目标为原生 Win32 GUI 程序（可直接看到 `MessageBoxA` 导入），注册结果通过弹窗呈现。
- 程序未加壳或已脱壳、无代码完整性校验/反调试，允许 OllyDbg 附加与修改内存。
- 校验逻辑存在可被跳过的条件分支（而非“正确/错误都必须执行”的加密验证）。

## 利用步骤

1. 运行程序，点击注册入口，观察不同输入下的弹窗数量与内容，推断存在 Name 格式校验与 Serial 校验两级逻辑。
2. OllyDbg 载入程序，`Ctrl+N` 打开“当前模块中的名称”，找到 `USER32.MessageBoxA`，右键“在输入函数上切换断点”。
3. `F9` 运行，触发注册；程序停在 `MessageBoxA` 时，在右下角栈窗口找到返回地址（如 `0x004013C1`），右键“在反汇编窗口中跟随”。
4. 在调用点向上分析：找到控制是否执行失败 `MessageBoxA` 的 `je short <成功地址>`；选中该行按空格，把 `je` 汇编为 `jmp short <同一目标>`（或改反条件跳转）。
5. `F9` 继续，第二次失败弹窗触发时重复 3-4，修改第二处 `je`（如 Name/Serial 校验各一处）。
6. 在反汇编窗口右键“复制到可执行文件→所有修改”，弹窗中“全部复制”，在补丁窗口右键“保存文件”，另存为 `xxx_modified.exe`。
7. 运行补丁文件，输入任意 Name/Serial，确认直接弹出成功提示。

## PoC

```text
# 典型两处补丁（字节级）
74 xx   je  short +xx   ->  EB xx   jmp short +xx

# OllyDbg 操作链
Ctrl+N -> USER32.MessageBoxA -> 切换断点 -> F9
栈返回地址 -> 在反汇编窗口跟随 -> 向上找 je -> 空格汇编 je 为 jmp
右键 -> 复制到可执行文件 -> 所有修改 -> 全部复制 -> 保存文件
```

## 变体与关联

- 变体：`je` 改 `jmp` 之外，可改反条件（`je`→`jne`）、把失败 `call MessageBoxA` 整个 NOP 掉、或把校验函数开头 `ret` 掉；对 `MessageBoxW` 程序同理。
- 关联：与 [[code-analysis-dynamic-debugging-ollydbg-memory-breakpoint-registration-keygen]] 是同一类 crackme 的两种路线——本卡为“爆破补丁”，那张为“算法还原写注册机”；与 [[code-analysis-dynamic-debugging-software-breakpoint-int3-byte-patch]] 的断点字节修改同属 OllyDbg 内存补丁操作。
- 与 [[code-analysis-reverse-windows-hardcoded-serial-lstrcmp-api-breakpoint]] 的区别：后者针对 `lstrcmp` 硬编码序列号比较，本卡针对弹窗前的分支跳转。

## 检测与防御

- 检测：可执行文件哈希与签名变化；`MessageBoxA` 调用前的条件跳转被改为无条件跳转；程序导入表中 `MessageBoxA` 被频繁断点/被调试器附加。
- 防御（软件保护侧）：校验结果不要只用一个可跳过的分支决定，成功路径应依赖解密后的授权数据而非布尔分支；加入代码完整性自校验/签名验证与反调试；关键校验放在服务端。
- 分析侧注意：OllyDbg 修改仅存于内存，必须“复制所有修改”另存才持久；对加壳程序需先脱壳。
