---
title: 逆向工程
weight: 1
---

# 逆向工程

## 这层是什么

二进制/应用逆向、脱壳、反调试、混淆与虚拟机保护。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- [脱壳](unpacking/) —— 壳识别、手动/自动脱壳、内存 dump 与重建。
- [反调试](anti-debug/) —— 反调试检测与绕过、反反调试。
- [混淆](obfuscation/) —— 控制流平坦化、字符串加密、指令替换与还原。
- [虚拟机保护](vm/) —— VMProtect/Themida 等 VM 保护的分析与还原。
- [固件逆向](firmware/) —— 固件提取、文件系统、启动链、模拟/仿真与漏洞分析（含 IoT 固件）。
- [Windows 逆向](windows/) —— PE、驱动、系统机制与调试。
- [Linux 逆向](linux/) —— ELF、内核模块、系统调用与调试。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Go 二进制逆向基础：string/slice/map 内存布局、调用约定与 stripped 符号恢复](code-analysis-reverse-go-binary-layout-symbol-recovery/) | verified | high | 2026-11-06 |
| [Go 接口与 SwissMap 反汇编识别：eface/iface/itab、slice interface 与 runtime.mapassign/mapaccess](code-analysis-reverse-go-interface-swissmap-disassembly/) | verified | medium | 2026-11-06 |
| [Unity IL2CPP CTF 链：CE 改内存触发内嵌资源释放 + 十六进制 PE 还原与凯撒/XOR 逆推](code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe/) | verified | high | 2026-11-06 |
| [Unity IL2CPP 逆向：GameAssembly/libil2cpp + global-metadata 经 Il2CppDumper 恢复符号并导入 IDA/Ghidra](code-analysis-reverse-unity-il2cpp-dumper-symbol-recovery/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
