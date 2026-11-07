# XS-Leaks 与 CSS 注入

## 这层是什么

跨站侧信道、帧计数、CSS 选择器外带与浏览器解析差异。

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
| [CSS 注入属性选择器逐字符外带页面数据](web-generic-xs-leaks-css-attribute-selector-exfil.md) | verified | medium | 2026-11-05 |
| [XS-Leaks 帧计数配合 CSS pattern:valid 盲注窃取页面 Token](web-generic-xs-leaks-css-pattern-valid-frame-counting-token.md) | verified | high | 2026-11-05 |
| [XS-Leaks 帧计数：读取跨域窗口 window.length 推断页面状态](web-generic-xs-leaks-window-length-frame-counting.md) | verified | high | 2026-11-07 |
| [XS-Leaks 状态码 oracle：script onload/onerror 跨站区分 200 与 4xx/5xx](web-generic-xs-leaks-script-onload-status-code-oracle.md) | verified | high | 2026-11-07 |
| [XS-Leaks 登录状态探测：img onload/onerror 判断重定向终点是否为图片](web-generic-xs-leaks-img-onload-onerror-login-detect.md) | verified | high | 2026-11-07 |
| [XS-Leaks 缓存探测：用缓存命中与加载时间判断跨站状态相关资源](web-generic-xs-leaks-cache-probing.md) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
