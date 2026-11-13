---
title: .NET Web
weight: 1
---

# .NET Web

## 这层是什么

ViewState、BinaryFormatter、IIS 与 .NET 反序列化。

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

- [.NET 反序列化](deserialization/) —— BinaryFormatter、LosFormatter、ObjectStateFormatter 等。
- [IIS](iis/) —— IIS 配置、短文件名、WebDAV 与历史漏洞。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [ASP.NET WebShell 编译产物免杀：反射调用 RijndaelManaged/Assembly.Load + 变异 base64 字符串，绕过对 Temporary ASP.NET Files 动态编译 DLL 的查杀](web-dotnet-aspnet-webshell-compiled-assembly-evasion/) | verified | high | 2026-11-08 |
| [CSharpCodeProvider 内存编译 + BuildManager 缓存注入的 ASMX WebService 内存马](web-dotnet-csharpcodeprovider-asmx-memshell-cache-injection/) | verified | high | 2026-11-05 |
| [JHSoft OA EditMain.aspx 后台 add/id 参数控制路径：StreamWriter 任意文件写入 GetShell](web-dotnet-jhsoft-editmain-arbitrary-file-write/) | verified | medium | 2026-11-07 |
| [REST 管线鉴权开关短路与请求头参数覆盖导致未授权 SQL 注入](web-dotnet-rest-auth-bypass-header-parameter-override/) | verified | high | 2026-11-04 |
| [SmarterMail ConnectToHub 匿名接入恶意 Hub：响应中的 CommandMount 经 sudo 执行任意命令（CVE-2026-24423）](web-dotnet-smartermail-connect-to-hub-mount-command-rce/) | verified | high | 2026-11-05 |
| [畅捷通 T+ Global.asax 鉴权短路：preload=1 直接 return，URL 含 login/token/静态后缀关键字也放行](web-dotnet-tplus-global-asax-preload-url-whitelist-auth-bypass/) | verified | high | 2026-11-11 |
| [畅捷通 T+ Upload.aspx 仅校验 Content-Type：路径穿越上传 + 预编译站点投 bin 程序集拿 RCE](web-dotnet-tplus-upload-aspx-precompiled-dll-bin-rce/) | verified | high | 2026-11-11 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
