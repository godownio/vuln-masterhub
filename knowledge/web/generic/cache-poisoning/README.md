# Web 缓存投毒

## 这层是什么

缓存键、缓存欺骗与投毒链。

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
| [Chromium 缓存键 cn_ 绕过实现顶层文档 XSS](web-generic-cache-poisoning-chromium-cn-cache-key-xss.md) | verified | high | 2026-11-04 |
| [Host 头缓存投毒：重复 Host 让缓存响应引用攻击者脚本](web-generic-cache-poisoning-host-header-ambiguous-request.md) | verified | high | 2026-11-05 |
| [Web 缓存欺骗：CDN 静态判定与源站归一化错位](web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch.md) | verified | high | 2026-11-04 |
| [请求走私缓存投毒：把带攻击者 Host 的 301 藏进后端请求，前端按下一请求 URL 缓存重定向，静态 JS 请求被导向利用服务器](web-generic-cache-poisoning-smuggling-redirect-static-asset.md) | verified | high | 2026-11-12 |
| [请求走私缓存欺骗：走私 GET /my-account 让后端以受害会话渲染私有页，前端却按受害者请求的静态 URL 缓存，攻击者再从缓存取 API Key](web-generic-cache-poisoning-smuggling-private-response-deception.md) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
