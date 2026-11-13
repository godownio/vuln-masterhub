---
title: IIS
weight: 1
---

# IIS

## 这层是什么

IIS 配置、短文件名、WebDAV 与历史漏洞。

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
| [IIS WebDAV 开启时 PUT 写文件 + MOVE 改后缀落地 ASP WebShell](web-dotnet-iis-webdav-put-move-webshell/) | verified | high | 2026-11-04 |
| [IIS 上传 web.config 自解析执行：*.config 映射 asp.dll 或 PageBuildProvider，带参数执行任意 ASP/ASP.NET 代码](web-dotnet-iis-webconfig-handler-self-execution/) | verified | high | 2026-11-12 |
| [IIS 托管模块后门：bin 目录投放 IISModule DLL + web.config 注册 modules，请求即执行命令](web-dotnet-iis-managed-module-backdoor-bin-webconfig/) | verified | medium | 2026-11-08 |
| [上传目录禁执行绕过：上传 web.config 把 handlers accessPolicy 改为 Read,Write,Execute,Script，让落地的 SOAP/ASPX 生效](web-dotnet-iis-upload-dir-accesspolicy-override/) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
