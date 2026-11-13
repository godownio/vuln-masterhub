---
title: Confluence
weight: 1
---

# Confluence

## 这层是什么

Confluence OGNL/模板注入与历史漏洞。

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
| [Confluence CVE-2022-26134 OGNL 注入 RCE：URI ${...} 无认证执行命令并回显](web-java-component-confluence-cve-2022-26134-ognl-rce/) | verified | high | 2026-11-07 |
| [Confluence CVE-2023-22515 未授权提权：OGNL 参数覆盖 setupComplete 重开安装流程创建管理员](web-java-component-confluence-cve-2023-22515-setupcomplete-admin-creation/) | verified | high | 2026-11-13 |
| [Confluence CVE-2023-22518 认证绕过：skipAccessCheck 参数后门 + /json 继承 /admin//setup 路由 + SetupRestoreAction 重置站点接管后台](web-java-component-confluence-cve-2023-22518-auth-bypass-setup-restore/) | verified | medium | 2026-11-13 |
| [Confluence CVE-2023-22527 未授权 Velocity 模板注入：text-inline.vm 的 label 参数经 OGNL 执行命令并回显](web-java-component-confluence-cve-2023-22527-text-inline-ognl-rce/) | verified | high | 2026-11-12 |
| [Confluence ServletRequestListener 内存马：OGNL defineClass 定义类 + ServletActionContextCompatManager 取 StandardContext 注册动态代理](web-java-component-confluence-servlet-request-listener-memshell/) | verified | high | 2026-11-11 |
| [Confluence 后渗透：confluence.cfg.xml 取数据库凭据 + cwd_user PKCS5S2 哈希破解/替换](web-java-component-confluence-config-db-pkcs5s2-credential/) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
