# GraphQL

## 这层是什么

introspection、批量查询、注入与授权缺陷。

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
| [GraphQL importPaste 命令注入：host/port/path/scheme 拼进 curl，path=/; sleep 10 在服务端执行任意命令](web-generic-graphql-importpaste-command-injection.md) | verified | high | 2026-11-08 |
| [GraphQL 批量查询/别名放大暴力破解：单 HTTP 请求内 100 个别名或 100 条批量 mutation，绕过每请求/IP 速率限制](web-generic-graphql-batch-alias-rate-limit-brute-force.md) | verified | high | 2026-11-08 |
| [GraphQL 操作名授权绕过：允许未认证的 operationName=getPastes，却夹带未授权 systemHealth 字段直接读数据](web-generic-graphql-operation-name-authz-field-bypass.md) | verified | high | 2026-11-08 |
| [GraphQL 端点发现与 schema 枚举：__typename 探测 + introspection + Clairvoyance 建议重建 + graphw00f 引擎指纹](web-generic-graphql-endpoint-discovery-schema-enumeration.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
