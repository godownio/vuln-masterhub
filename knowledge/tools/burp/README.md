# Burp Suite

## 这层是什么

插件、拦截、扫描与扩展。

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
| [autoDecoder 自定义加解密脚本：Flask /encode /decode 接口、bytes/str 与 Base64 编码、PKCS 填充及 JSON 字段处理](tools-burp-autodecoder-flask-custom-encrypt-decrypt-script.md) | verified | high | 2026-11-07 |
| [Burpy：Burp 经 PyRO 调用 Python 脚本自动加解密请求/响应（Burpy 类接口与三个常见报错）](tools-burp-burpy-pyro-python-auto-encrypt-decrypt.md) | verified | high | 2026-11-07 |
| [Hermes Agent 接入 Burp MCP：WSL 端口桥接、Origin 403 与异步 SSE 排障](tools-burp-hermes-mcp-wsl-sse-integration.md) | verified | high | 2026-11-05 |
| [JS Hook + 本地 Bridge + Burp 扩展：不还原算法直接加解密 Web 流量](tools-burp-js-hook-bridge-traffic-encrypt-decrypt.md) | verified | high | 2026-11-06 |
| [加密 API 测试代理链：上下游 mitmproxy 透明解密/重签，绕过防重放与 AES 参数加密](tools-burp-encrypted-api-proxy-decrypt-resign.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
