---
title: Node.js 模板注入
weight: 1
---

# Node.js 模板注入

## 这层是什么

EJS、Pug、Handlebars 等模板注入。

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
| [EJS 模板 <%= %> 注入：公告板内容字段被服务端渲染导致 Node.js 任意命令执行](web-nodejs-ssti-ejs-announcement-content-rce/) | verified | high | 2026-11-06 |
| [Express PUT 任意文件写入 + res.render(templ) 模板名可控：上传 EJS 到 views 实现 RCE](web-nodejs-ssti-express-put-upload-res-render-template-name-rce/) | verified | high | 2026-11-07 |
| [Handlebars 编译 AST 对象注入导致模板代码执行](web-nodejs-ssti-handlebars-ast-injection/) | verified | high | 2026-11-05 |
| [JWT 弱密钥伪造用户名触发 EJS 模板注入 RCE](web-nodejs-ssti-jwt-weak-secret-ejs-username-rce/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
