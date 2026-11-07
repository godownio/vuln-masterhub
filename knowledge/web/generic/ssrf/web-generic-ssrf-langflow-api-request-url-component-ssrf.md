---
id: web-generic-ssrf-langflow-api-request-url-component-ssrf
title: Langflow API Request / URL 组件只校验 URL 格式：工作流运行者经 httpx/RecursiveUrlLoader 触发内网 SSRF（CVE-2025-68477）
type: scenario
domain: web
path: web/generic/ssrf
technique: langflow-url-input-ssrf
aliases:
- CVE-2025-68477
- Langflow SSRF
- Langflow API Request SSRF
- Langflow URL 组件 SSRF
- Langflow 内网探测
- RecursiveUrlLoader SSRF
tags:
- ssrf
- langflow
- ai-framework
- httpx
- recursiveurlloader
- cloud-metadata
- internal-network
- cve-2025-68477
cve:
- CVE-2025-68477
severity: high
confidence: high
status: verified
affected_versions: Langflow ≤ 1.6.9（原文环境 1.6.9，原文称 1.6.9 及之前版本受影响）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T11:45:15+08:00'
  notes: 已对照原文与 8 张图核对：图01 release 1.6.9、图02 本地 7860 flows、图03-04 组件文档、图05 API Request→Chat Output、图06 API Request 访问 http://127.0.0.1:8000/test.txt 且宿主机 http.server 日志 GET 200、图07 URL 组件同地址日志 GET 200、图08 组件输出回显 test。卡内 api_request.py _normalize_url/validators.url、url.py URL_REGEX/RecursiveUrlLoader、follow_redirects 默认 True、两组件合并逻辑均与原文一致；CVE-2025-68477、受影响版本 ≤1.6.9 与原文一致。4 个关联 wikilink 目标均存在，路径 web/generic/ssrf 合法。未验证点：仅验证环回地址读取，云元数据 169.254.169.254 为原文未验证的通用延伸（卡内已注明）；PoC 未本机复跑。
---

## 一句话结论

Langflow ≤ 1.6.9 的 `API Request` 与 `URL` 两个数据源组件只校验 URL 语法，不拦截环回/私网/链路本地地址；能够运行工作流（Playground 或携带 `x-api-key` 调 `/api/v1/run/{flow_id}`）的用户可让服务端向 `127.0.0.1`、内网 IP、`169.254.169.254` 等地址发起请求，并把响应经组件输出回显，形成可读内网服务与云元数据的 SSRF。

## 原理

- `API Request` 组件（`components/data/api_request.py`）的 `_normalize_url()` 只判断字符串是否以 `http://`/`https://` 开头，没有则补 `https://`；随后 `validators.url(url)` 只验证 URL 格式。两者都不检查 hostname 是否为环回、私网、链路本地或云元数据地址。
- 校验通过后直接 `httpx.AsyncClient().request(method, url, ...)`，没有出口白名单、DNS 解析后二次校验或重定向目标校验；`follow_redirects` 默认 `True`，即使后续只做首跳校验，也可由攻击者控制的 302 跳到内网。
- `URL` 组件（`components/data/url.py`）用 `URL_REGEX` 校验，正则允许 `127.0.0.1`、`localhost`、`192.168.x.x` 等主机形式；随后把 URL 原样交给 `RecursiveUrlLoader(url=...)` 发起请求。`prevent_outside=True` 只约束“爬取链接不跨出根域”，对初始 URL 本身没有 SSRF 防护，根域是内网时反而会把内网链接继续爬下去。
- 组件输入在 Langflow 中可作为 Tool Mode 参数暴露给 Agent/MCP 调用，也可由 Playground 或 `/api/v1/run` 的输入驱动；抓取结果会进入组件的 `Data`/`DataFrame`/`Message` 输出，再流向 Chat Output 或后续节点，因此请求结果对调用者可见。
- SSRF 的价值在于服务端网络位置：Langflow 常部署在容器/云主机内，可访问同机管理端口、内网 Redis/MySQL/API、Kubernetes Service，以及云厂商元数据端点（IMDSv1 可直接取临时凭证）。

## 触发条件

- Langflow 版本在受影响范围（原文验证 1.6.9，并称 1.6.9 及之前版本受影响）。
- 工作流中包含 `API Request` 或 `URL` 组件，且其 URL/URLs 输入可由攻击者控制（直接组件输入、Agent Tool Mode、MCP 工具参数，或 API 运行输入）。
- 攻击者能运行该工作流：持有有效 `x-api-key`、已登录 Playground，或目标开启了可匿名运行/自动登录的配置。
- Langflow 进程到目标内网地址网络可达；组件输出会返回给调用者（默认会）。

## 利用步骤

1. 确认目标为 Langflow，枚举可运行的工作流 ID；获取或猜测 `x-api-key`（也可直接在 Playground 中操作）。
2. 选择包含 `API Request` 或 `URL` 组件的工作流；若可编辑，把 URL 设为 `http://127.0.0.1:<port>/<path>`、`http://localhost:<port>` 或 `http://192.168.x.x:<port>`。
3. 通过 Playground 运行，或向 `/api/v1/run/{flow_id}` 发送带 `x-api-key` 的请求，让输入落到组件的 URL 参数。
4. 从 `API Response` / `Extracted Pages` / Chat Output 读取响应体、状态码和错误信息；用不同端口/路径的响应差异做内网端口与服务探测。
5. 对云主机尝试 `http://169.254.169.254/latest/meta-data/`（AWS）、`http://metadata.google.internal/`（GCP）等元数据路径；成功时结合 IMDSv1 读取临时凭证。
6. 若目标后续加了首跳 URL 校验，用攻击者控制的外网 URL 返回 302 跳转到内网地址，利用默认跟随重定向绕过。

## PoC

通过 API 运行工作流（`flow_id`、`x-api-key`、`session_id` 用占位符替换）：

```http
POST /api/v1/run/<flow_id> HTTP/1.1
Host: target:7860
x-api-key: <api-key>
Content-Type: application/json

{"output_type":"chat","input_type":"chat","input_value":"get file from http://127.0.0.1:8000/test.txt?","session_id":"<uuid>"}
```

组件 URL 直接填内网目标（Playground 或流程配置）：

```text
http://127.0.0.1:8000/test.txt
http://localhost:3306
http://192.168.1.1:8080
http://169.254.169.254/latest/meta-data/
```

预期结果：Langflow 所在主机向目标发起请求，目标访问日志出现对应 `GET`；组件输出中回显响应体（原文验证 `http://127.0.0.1:8000/test.txt` 返回 `test`）。

## 变体与关联

- 变体：`URL` 组件把 `max_depth` 调到 2 以上，初始 URL 指向内网页面后递归爬取同域内网链接，扩大可读范围。
- 变体：`follow_redirects=True` + 攻击者外网 302，绕过只校验首跳 URL 的修复；也可用 DNS 解析到内网的域名绕过字面 IP 黑名单。
- 变体：通过 Agent/MCP 的 Tool Mode，把 URL 作为自然语言工具参数传入，无需直接编辑流程。
- 关联：[[web-generic-ssrf-chainlit-custom-element-url-fetch-ssrf]]（AI 应用组件 URL 直连 SSRF）、[[web-generic-ssrf-dify-remote-files-upload-unauth]]、[[web-generic-ssrf-lobechat-botmessage-attachment-fetchurl]]、[[web-generic-ssrf-vllm-media-connector-urlparse-aiohttp-differential]]（同类 AI 应用 SSRF 入口）。
- 边界：若部署层已用 egress 策略禁止访问私网/元数据地址，或组件被限制为固定白名单 URL，则本场景不成立；原文未验证云元数据实际读取，该部分为 SSRF 通用延伸。

## 检测与防御

- 修复/加固：在 URL 校验阶段解析 hostname，拒绝环回、私网、链路本地、保留地址与云元数据 IP（包括 IPv6 `::1`、`fc00::/7`、`fe80::/10`）；DNS 解析后对实际连接的 IP 再校验一次。
- 加固：`follow_redirects=False`，或对每一跳重定向重新做地址校验；只允许 http/https，禁止 `file://`、`gopher://` 等协议。
- 加固：为 Langflow 配置出口代理/网络策略，默认禁止访问内网与 `169.254.169.254`；云上强制 IMDSv2。
- 权限：`/api/v1/run` 与 Playground 严格鉴权，不把含 URL 输入的组件以 Tool Mode 暴露给不可信用户；多租户场景下隔离工作流执行网络。
- 检测：Langflow 进程的出站连接日志出现 `127.0.0.1`、`localhost`、私网段、`169.254.169.254`；组件 URL 参数含上述地址或重定向到内网；短时间大量不同端口请求（端口扫描特征）。
