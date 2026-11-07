---
title: 表达式注入
weight: 1
---

# 表达式注入

## 这层是什么

SpEL、OGNL、MVEL、EL 等表达式注入。

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

- [SpEL](spel/) —— Spring Expression Language 注入与利用。
- [OGNL](ognl/) —— OGNL 注入与 Struts2 利用。
- [MVEL](mvel/) —— MVEL 表达式注入。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Java ScriptEngine 的 isJson 校验直接 eval 字符串：_json 参数经 BaseResult 构造器直达 Nashorn 代码执行](web-java-expression-scriptengine-isjson-eval/) | verified | medium | 2026-11-05 |
| [JSP EL 表达式注入的 WAF 绕过与 Scanner 回显](web-java-expression-el-injection-waf-bypass-scanner-echo/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
