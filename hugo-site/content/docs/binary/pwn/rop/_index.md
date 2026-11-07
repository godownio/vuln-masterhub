---
title: ROP
weight: 1
---

# ROP

## 这层是什么

ROP/JOP/COP、gadget 与链构造。

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

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Hexagon DSP ROP：trap0 系统调用 gadget + 两级栈迁移读取 /flag](binary-pwn-rop-hexagon-dsp-trap0-two-stage-pivot/) | verified | high | 2026-11-06 |
| [ret2csu 写 /bin/sh 到 bss：libc 符号偏移正确但字符串偏移不一致时的栈溢出利用](binary-pwn-rop-ret2csu-bss-binsh-libc-offset-mismatch/) | verified | high | 2026-11-05 |
| [system("$0") 绕过 sh 关键字过滤：借 argv[0] 拉起 shell](binary-pwn-rop-system-dollar0-bypass-sh-filter/) | verified | high | 2026-11-06 |
| [无 libc 泄露 + seccomp 禁 execve：magic gadget（add [rbp-0x3d], ebx）配合 CSU 写 BSS 伪造参数，调用 fopen/fread/send 读 flag](binary-pwn-rop-magic-gadget-csu-bss-write-orw-no-libc-leak/) | verified | high | 2026-11-06 |
| [无 pop rdx 的 ORW 第三参数：用 mov dl, imm; ret 设置 rdx 低字节](binary-pwn-rop-mov-dl-imm-set-rdx-lowbyte/) | verified | high | 2026-11-06 |
| [栈溢出 ROP：借 mov %rsp,%rdi + jmp *%r13 的自定义函数调用 system](binary-pwn-rop-mov-rsp-rdi-jmp-r13-system/) | verified | high | 2026-11-05 |
| [静态链接无 PIE 栈溢出：用二进制内置 system 与 /bin/sh 直接 ROP](binary-pwn-rop-static-link-ret2system-sh/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
