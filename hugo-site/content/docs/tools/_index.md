---
title: 工具
weight: 1
---

# 工具

## 这层是什么

安全工具的高级用法与脚本。

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

- [Burp Suite](burp/) —— 插件、拦截、扫描与扩展。
- [Nmap](nmap/) —— 扫描、脚本与规避。
- [Metasploit](metasploit/) —— 模块、payload 与利用。
- [Frida](frida/) —— Hook、插桩与自动化。
- [IDA](ida/) —— 反汇编、脚本与插件。
- [Ghidra](ghidra/) —— 反编译、脚本与协作。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Apktool decodeUnknownFiles 路径穿越：APK 内 unknown 文件条目名 ../../../ 逃逸输出目录任意写文件](tools-apktool-unknownfiles-decode-path-traversal-arbitrary-write/) | verified | high | 2026-11-12 |
| [Apktool XML 解析 XXE：loadDocument 未禁用 DOCTYPE/外部实体，解析恶意 AndroidManifest/strings.xml 时读取本地文件并外带](tools-apktool-xml-parser-xxe-manifest-strings/) | verified | medium | 2026-11-12 |
| [Apktool 路径穿越修复在 Windows 上被正斜杠绕过：detectPossibleDirectoryTraversal 只查反斜杠，资源名用 ../ 仍任意写文件](tools-apktool-detect-possible-directory-traversal-windows-bypass/) | verified | high | 2026-11-12 |
| [CVE-2024-21633 Apktool 资源名路径穿越：resources.arsc 中篡改资源名，decode 时任意文件写入](tools-apktool-cve-2024-21633-resource-name-path-traversal-write/) | verified | high | 2026-11-12 |
| [JADX XXE（CVE-2022-0219）：XmlSecurity 已实现但 parseXml 未调用，恶意 APK 内 XML 触发外部实体读取与外带文件](tools-jadx-xxe-xmlsecurity-not-used-manifest-parser/) | verified | high | 2026-11-12 |
| [sqlmap --os-shell 后门上传成功但命令不回显时的兜底：复用 stager 上传链接或 --file-write 投递 php-reverse-shell / 下载执行脚本](tools-sqlmap-os-shell-stager-upload-file-write-webshell-fallback/) | verified | high | 2026-11-12 |
| [Yakit fuzztag 注入本地文件读取外带（CVE-2023-40023）：恶意网页的 {{base64enc(file(...))}} 被插件渲染后随镜像请求发出](tools-yakit-fuzztag-file-tag-local-file-exfiltration/) | verified | high | 2026-11-11 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
