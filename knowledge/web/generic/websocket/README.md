# WebSocket

## 这层是什么

跨站 WebSocket 劫持、认证与消息注入。

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
| [browser-tools-mcp /extension-ws 无 Origin 校验 CSWSH 替换 Chrome 扩展连接，经 fullPath 拼接 AppleScript 命令注入 RCE](web-generic-websocket-browser-tools-mcp-cswsh-osascript-rce.md) | verified | high | 2026-11-06 |
| [Cloud CLI（Claude Code UI）WebSocket Shell 命令注入：默认 JWT 密钥伪造 + projectPath/initialCommand 直拼 bash（CVE-2026-31975）](web-generic-websocket-claudecodeui-ws-shell-command-injection.md) | verified | high | 2026-11-06 |
| [Dokploy v0.26.6 修复遗漏 /docker-container-logs：tail/since 未校验导致 WebSocket 命令注入](web-generic-websocket-dokploy-container-logs-tail-since-injection.md) | verified | high | 2026-11-05 |
| [Dokploy 容器终端 WebSocket 的 containerId/activeWay 直拼 shell：认证用户经 docker.sock 逃逸到宿主机（CVE-2026-24841）](web-generic-websocket-dokploy-container-terminal-command-injection.md) | verified | high | 2026-11-05 |
| [Vite 开发服务器 WebSocket 免 Origin 免 Token 调用 fetchModule 任意文件读取（CVE-2026-39363）](web-generic-websocket-vite-invoke-fetchmodule-file-read.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
