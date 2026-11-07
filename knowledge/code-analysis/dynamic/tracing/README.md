# 跟踪

## 这层是什么

系统调用、API、指令级跟踪。

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
| [DongTai IAST 误报定位：污点 hash 碰撞把常量标成可控，先回溯 source 节点](code-analysis-dynamic-tracing-iast-taint-hash-collision-false-positive-triage.md) | verified | medium | 2026-11-07 |
| [eBPF 协议栈透视：起点函数+线程ID把数据包绑定到内核函数调用链](code-analysis-dynamic-tracing-ebpf-protocol-stack-packet-callchain.md) | verified | medium | 2026-11-07 |
| [ETW Hook 内核级 syscall 监控：替换 HalPrivateDispatchTable.HalCollectPmcCounters，栈上改写 SSDT 调用地址](code-analysis-dynamic-tracing-etw-hook-haldispatch-pmc-syscall-monitor.md) | verified | medium | 2026-11-07 |
| [ftrace function_graph 定位 syscall 内核错误返回点：strace→函数图追踪→gdb 断点](code-analysis-dynamic-tracing-ftrace-function-graph-syscall-error-locate.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
