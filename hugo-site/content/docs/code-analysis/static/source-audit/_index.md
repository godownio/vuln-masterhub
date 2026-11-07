---
title: 源码审计
weight: 1
---

# 源码审计

## 这层是什么

按语言/框架的审计思路与危险模式。

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
| [AI+SAST 挖掘 Java gadget 链：JavaParser 符号解析 + CHA 数据流 + Neo4j 图谱 + AI 筛选](code-analysis-source-audit-ai-sast-java-gadget-chain-mining/) | verified | medium | 2026-11-05 |
| [DSL/配置模板攻击面审计：Sprintf 把用户配置拼进 nginx/VCL 解释器，14+3 处注入点批量排查](code-analysis-source-audit-dsl-config-sprintf-injection/) | verified | high | 2026-11-05 |
| [Java 代码审计：从鉴权配置枚举匿名与排除路径，快速定位未授权前台接口](code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration/) | verified | medium | 2026-11-06 |
| [JSF 老 OA 源码审计：*.jsf→*.jsp 路由、ExtAbstractManagedBean 控制器与危险 Servlet 定位](code-analysis-source-audit-jsf-legacy-oa-audit/) | verified | medium | 2026-11-05 |
| [Rust soundness 缺陷审计：四类失效机理与 Miri 验证零 unsafe 代码的 UB](code-analysis-source-audit-rust-soundness-miri/) | verified | high | 2026-11-05 |
| [Struts2 DispatchAction 继承链鉴权审计：沿 execute→init 覆写链找出未授权 Action 与 JSP 直连入口](code-analysis-source-audit-struts2-dispatchaction-init-auth-chain/) | verified | medium | 2026-11-07 |
| [从 1day 特征代码复用批量挖同系统 0day：Multipart 强转与 setOrder 特征全局搜索](code-analysis-source-audit-feature-code-reuse-sibling-sink-mining/) | verified | high | 2026-11-07 |
| [修复链断裂审计：CVE patch 只加校验不删能力，底层攻击面持续存活并反复出新 CVE](code-analysis-source-audit-additive-cve-fix-chain/) | verified | high | 2026-11-05 |
| [双路径分歧审计：长度计算/执行共享状态导致缓冲区长度不一致，或编译/运行时编码不一致](code-analysis-source-audit-double-path-state-divergence/) | verified | high | 2026-11-05 |
| [大型 JDBC/HQL 项目的拼接注入审计：预编译基线与 .append(... + ...) 正则筛选](code-analysis-source-audit-jdbc-hql-concat-regex/) | verified | medium | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
