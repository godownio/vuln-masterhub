---
id: code-analysis-reverse-anti-debug-command-line-argument-md5-gate
title: 命令行参数门禁：要求 --type driver 且参数 MD5 匹配硬编码值才继续
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: command-line-argument-md5-gate
aliases:
- 参数门禁
- --type driver
- 参数 MD5
- 命令行校验
- 沙箱规避
tags:
- reverse
- anti-debug
- anti-sandbox
- command-line
- md5
- malware
- evasion
- windows
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T07:52:19+08:00'
  notes: 已对照原文与21张图核对：--type driver 参数门禁、参数MD5与硬编码 E2D45D57C7E2941B65C6CCD64AF4223E 多次比对、失败退出均与原文一致；PoC未执行
---

## 一句话结论

样本启动后先检查命令行参数是否包含 `--type driver`，并对参数做 MD5 与硬编码值（原文 `E2D45D57C7E2941B65C6CCD64AF4223E`）比对，不匹配就直接终止；沙箱、双击或误启动通常不会带正确参数，因此不会触发后续恶意行为，而加载器/攻击者可以按预期参数启动。

## 原理

- **参数门禁**：恶意加载器由漏洞利用/投放器拉起时，会传入约定参数（原文期望 `--type driver`）；样本在入口处检查命令行，只有包含该参数才继续，否则退出。这样安全沙箱自动运行样本（默认无参数）或用户误双击时看不到后续行为。
- **MD5 二次校验**：仅比较字符串容易被静态提取/直接传参，样本还对参数值计算 MD5 并与硬编码哈希（`E2D45D57C7E2941B65C6CCD64AF4223E`）比较，且多次计算/比对，确保启动参数与预期完全一致，也提高了 patch 的门槛。
- **为什么是有效的反分析**：沙箱通常以默认命令行执行样本；样本静默退出会被判为“无行为/低风险”，从而漏掉后续的 DLL 侧加载、载荷解密与 C2。对分析者而言，必须先从样本中还原正确参数或 patch 掉门禁，才能进入主逻辑。
- **与常见环境检查的区别**：它不是检测调试器/虚拟机，而是要求“由正确的父进程以正确参数启动”；因此绕过方式也不同——不是隐藏调试器，而是补上参数或改跳转。
- **局限**：参数与哈希通常以明文/常量形式存在于样本中，逆向即可拿到；对动态分析只需按正确参数启动或 patch 分支，防御强度有限。

## 触发条件

- 样本入口会解析命令行（`GetCommandLineA/W`、`CommandLineToArgvW` 或 CRT `argv`），并对参数做字符串/哈希比较。
- 存在硬编码的期望参数（如 `--type driver`）与 MD5 常量；比较失败路径直接退出/`ExitProcess`。
- 样本由加载器/投放器按约定参数启动；分析者可修改命令行或 patch。
- 无额外的强反调试阻止 patch/调试（或已绕过）。

## 利用步骤

> 本卡为逆向分析/绕过视角；“利用步骤”即恢复执行条件。

1. 在入口/初始化函数中定位命令行解析与字符串 `--type`/`driver`，或搜索 MD5 常量与 MD5 调用点。
2. 分析比较逻辑：确认是“参数包含子串”还是“整个参数值的 MD5 等于常量”；记录期望值。
3. 动态分析：用调试器启动样本并传入正确参数（如 `sample.exe --type driver`），或直接在比较处改寄存器/ZF/跳转。
4. 静态分析：patch 掉失败分支（把条件跳转改成无条件跳转/NOP），或把 MD5 比较结果强制为相等。
5. 继续跟进后续 DLL 侧加载、配置解密与载荷加载逻辑；注意样本可能有其他环境检查（父进程、路径、时间等）串联。

## PoC

启动参数与 patch 思路（以原文为例）：

```text
# 正确启动方式（从样本中还原出的期望参数）
sample.exe --type driver

# 或调试器中在 MD5 比较处下断：
#   - 比较前把两个操作数改成相同值
#   - 或把 jz/jnz 改成 jmp/反面条件
#   - 或把失败分支的 ExitProcess 调用 NOP 掉
```

字符串/哈希定位：

```text
strings sample.exe | findstr /i "type driver"
# 搜索 MD5 常量：E2 D4 5D 57 C7 E2 94 1B 65 C6 CC D6 4A F4 22 3E
```

## 变体与关联

- **变体**：门禁可检查参数个数、特定子串、完整参数值的 MD5/SHA1、父进程名/父进程路径、启动目录、环境变量、互斥体；也可把参数作为解密密钥的一部分（参数不对则配置解密失败）。
- **关联卡片**：[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（时间/桌面/主机名/DebugPort 等环境检查）；[[code-analysis-reverse-anti-debug-getcurrentdirectoryw-root-trailing-backslash]]（利用当前目录路径差异让样本在子目录提前退出）；[[code-analysis-reverse-anti-debug-windows-sandbox-fingerprint-parent-check]]（父进程/沙箱指纹检查）；[[code-analysis-reverse-anti-debug-defender-emulator-sandbox-checks]]（综合模拟器检测）。
- **区分**：本卡的核心是“命令行参数 + 参数 MD5”门禁，不是调试器/虚拟机检测。

## 检测与防御

- **检测**：EDR 记录进程命令行，识别 `--type driver` 等异常参数与“参数→MD5→分支”的代码模式；沙箱可尝试常见参数/模糊测试命令行以触发样本。
- **动态分析**：在 `GetCommandLineA/W`、`CommandLineToArgvW`、MD5 调用点下断，观察期望参数与比较结果。
- **防御**：对未知样本的启动参数做日志与关联分析；限制可疑父进程拉起子进程；结合行为检测而非仅依赖“样本是否退出”。
- **局限**：参数门禁只是低成本反分析，不能阻止定向分析者 patch；应与完整性校验、反调试组合使用。
