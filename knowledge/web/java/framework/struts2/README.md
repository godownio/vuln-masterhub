# Struts2

## 这层是什么

Struts2 OGNL 与历史漏洞。

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
| [Struts2 2.0.11.2 旧版本匹配 S2-016/S2-015：redirect/redirectAction 前缀 OGNL 未授权 RCE](web-java-framework-struts2-s2-016-legacy-version-ognl-rce.md) | verified | medium | 2026-11-05 |
| [Struts2 ActionProxy 取值流入 OGNL 执行：getMethod/getNamespace/getActionName 注入链](web-java-framework-struts2-actionproxy-ognl-injection.md) | verified | medium | 2026-11-05 |
| [Struts2 S2-001 表单回填二次 OGNL 解析：%{...} 提交值在 UIBean 渲染时被再次求值导致 RCE](web-java-framework-struts2-s2-001-form-repopulate-ognl-rce.md) | verified | high | 2026-11-08 |
| [Struts2 S2-066（CVE-2023-50164）：上传文件名参数覆盖导致路径穿越](web-java-framework-struts2-s2-066-upload-filename-param-override.md) | verified | high | 2026-11-05 |
| [Struts2 S2-067（CVE-2024-53677）：top.uploadFileName OGNL 绕过上传文件名修复](web-java-framework-struts2-s2-067-ognl-upload-filename-bypass.md) | verified | high | 2026-11-05 |
| [Struts2 S2-069 (CVE-2025-68493)：xwork DomHelper.parse XXE 文件读取](web-java-framework-struts2-s2-069-domhelper-xxe.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
