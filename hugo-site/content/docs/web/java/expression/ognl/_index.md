---
title: OGNL
weight: 1
---

# OGNL

## 这层是什么

OGNL 注入与 Struts2 利用。

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
| [OGNL expressionMaxLength 长度限制绕过：@ognl.Ognl@applyExpressionMaxLength 覆盖静态上限](web-java-expression-ognl-expression-maxlength-apply-bypass/) | verified | high | 2026-11-11 |
| [OGNL 出网加载远程 Spring XML：new ClassPathXmlApplicationContext 使目标拉取攻击者 XML 并实例化 bean](web-java-expression-ognl-classpathxmlapplicationcontext-remote-xml-rce/) | verified | medium | 2026-11-11 |
| [OGNL 高版本黑名单反射绕过：Class.forName + Method.invoke 调用 Runtime](web-java-expression-ognl-high-version-reflection-invoke-bypass/) | verified | high | 2026-11-05 |
| [OGNL 黑名单 JShell 绕过：@jdk.jshell.JShell@create().eval() 执行任意 Java](web-java-expression-ognl-jshell-eval-bypass/) | verified | high | 2026-11-05 |
| [泛微 E10 testExecute1 的 Arthas OGNL 执行：serverId+input 调 Runtime.exec（依赖 JDK 环境）](web-java-expression-ognl-weaver-e10-testexecute1-arthas-rce/) | verified | medium | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
