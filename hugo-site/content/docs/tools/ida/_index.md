---
title: IDA
weight: 1
---

# IDA

## 这层是什么

反汇编、脚本与插件。

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
| [IDA FLIRT/FLAIR 自定义静态库签名：从 .lib/.a 生成 .pat/.sig 恢复库函数名](tools-ida-flirt-flair-custom-library-signature/) | verified | high | 2026-11-06 |
| [IDA Hex-Rays ctree 宏还原：把 LIST_ENTRY 自指初始化折叠为 InitializeListHead(&x)](tools-ida-hexrays-ctree-initialize-list-head-fold/) | verified | high | 2026-11-06 |
| [IDA Trace 三种粒度：指令/基本块/函数级跟踪并导出文本供脚本处理](tools-ida-trace-instruction-basicblock-function-export/) | verified | high | 2026-11-06 |
| [IDA 堆栈不平衡报错修复：Alt+K 把 SP 差值设为 0，消除 positive sp value](tools-ida-positive-sp-stack-imbalance-altk/) | verified | high | 2026-11-06 |
| [IDA 条件断点用 IDAPython 判断寄存器：call rand 后 rax==16949 才断下](tools-ida-python-conditional-breakpoint-register/) | verified | high | 2026-11-06 |
| [IDA 还原 bison/flex 生成 parser：批量重命名 yypact/yytable/yycheck 并导入 yy_buffer_state/yyguts_t](tools-ida-bison-flex-parser-table-struct-recovery/) | verified | high | 2026-11-06 |
| [IDA-Fork 双进程调试：把子进程首指令 patch 成死循环，附加后 SetIP 恢复](tools-ida-fork-child-loop-patch-attach/) | verified | high | 2026-11-06 |
| [IDAPython 批量解密调用点 XOR 字符串：回溯 mov r8d/lea rdx 参数并自动注释](tools-ida-xor-string-call-arg-backtrack-decrypt/) | verified | high | 2026-11-06 |
| [内核驱动逆向：用源码结构体在 IDA Local Types 导入并校正 Hex-Rays 反编译](tools-ida-kernel-source-struct-import-decompiler-cleanup/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
