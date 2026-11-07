---
title: AI 网关安全
weight: 1
---

# AI 网关安全

## 这层是什么

Kong、Higress、APISIX 等 AI 网关的 provider 密钥存放、去向与归属，插件与上游转发安全。

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
| [AI 网关密钥加密声明的落盘核查：APISIX encrypt_fields 漏声明与 Kong OSS encrypted 空实现](ai-security-gateway-security-apisix-kong-secret-at-rest-audit/) | verified | high | 2026-11-05 |
| [CLIProxyAPI 默认 API Key 未改：your-api-key-1 直接调用模型接口与 flag 模型](ai-security-gateway-security-cliproxyapi-default-api-key/) | verified | high | 2026-11-06 |
| [Higress ai-proxy 内部信号头可伪造：客户端提供 x-higress-fallback-from 令伪装的 X-HI-ORIGINAL-AUTH 透传到下游](ai-security-gateway-security-higress-ai-proxy-internal-header-forgery/) | verified | medium | 2026-11-05 |
| [Kong ai-proxy upstream_url 请求头模板展开导致 provider 密钥外泄](ai-security-gateway-security-kong-ai-proxy-upstream-template-key-leak/) | verified | high | 2026-11-05 |
| [LiteLLM Custom Code Guardrail 注入 http_get/http_post：全读 SSRF 与内部数据外带](ai-security-gateway-security-litellm-custom-guardrail-http-primitive-ssrf/) | verified | high | 2026-11-05 |
| [LiteLLM 公开路由与 DEBUG 日志信息泄露：版本、路由表、OpenAPI 与 API key 哈希](ai-security-gateway-security-litellm-public-routes-debug-log-disclosure/) | verified | high | 2026-11-05 |
| [第三方 LLM 中转站系统提示词投毒：上下文膨胀、模型造假与 Agent 静默执行](ai-security-gateway-security-llm-relay-system-prompt-poisoning/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
