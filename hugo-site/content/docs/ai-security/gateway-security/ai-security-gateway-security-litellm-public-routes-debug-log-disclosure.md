---
id: ai-security-gateway-security-litellm-public-routes-debug-log-disclosure
title: LiteLLM 公开路由与 DEBUG 日志信息泄露：版本、路由表、OpenAPI 与 API key 哈希
type: scenario
domain: ai-security
path: ai-security/gateway-security
technique: litellm-public-route-debug-log-disclosure
tags:
- ai-security
- ai-gateway
- litellm
- information-disclosure
- recon
- debug-log
- api-key-hash
- spend-logs
- fastapi
severity: medium
confidence: high
affected_versions: LiteLLM v1.40.0（原文审计版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V103
  verified_at: '2026-11-05T22:38:10+08:00'
  notes: 已对照原文与10张提取截图核对：/health/readiness 泄露 litellm_version=1.40.0、/routes 与 openapi.json 1.40.0、首页 Swagger、20次 /health/liveliness 全200、audit.sh 结果均一致；DEBUG 日志截图可见 receiving data 含请求体与 Authorization，卡片已注明 /spend/logs 需 master_key。v1.40.0 为审计版本，未复跑。
url: /docs/ai-security/gateway-security/ai-security-gateway-security-litellm-public-routes-debug-log-disclosure/
draft: false
kb_aliases:
- LiteLLM 信息泄露
- /health/readiness 版本泄露
- /routes 路由表泄露
- openapi.json 暴露
- DEBUG 日志 user_api_key
- /spend/logs key 哈希
---

## 一句话结论

LiteLLM 的公开路由 allowlist 允许未认证访问 `/health/readiness`（返回 `litellm_version`）、`/routes`（完整路由表）、`/openapi.json` 与 `/`（Swagger/接口文档）；开启 `LITELLM_LOG=DEBUG` 时还会把完整请求体写进日志，其中 `user_api_key` 哈希是明文。攻击者不传认证头即可完成“版本指纹 → CVE 匹配 → 端点枚举 → 参数构造”；若再拿到 master_key，`/spend/logs` 还会返回 API key 哈希前缀、用户名、消费记录，可用于离线爆破、确认 key 是否存在或社工。

## 原理

- **公开路由 allowlist**：`_types.py:254-261` 定义了一组无需 API Key 的公开路由；原文逐条验证，`/health/liveness`、`/health/readiness`、`/routes`、`/`、`/openapi.json` 均可未认证访问。
- **版本指纹**：`/health/readiness` 返回 `litellm_version`；攻击者用版本号去 GitHub Advisory/CVE 库检索，可直接匹配到该版本对应的 Critical/High 漏洞（原文用 1.40.0 匹配到 3 个 Critical 认证绕过）。
- **路由表与接口文档**：`/routes` 返回所有注册路由（比 openapi.json 更全，包含未收录的内部端点），等于给攻击者一张攻击面地图；`/openapi.json` 和首页 Swagger 给出所有 API 的参数、返回值、认证方式，攻击者不需要猜参数。
- **DEBUG 日志泄露**：`proxy_server.py:4055` 的 `verbose_proxy_logger.debug("receiving data: %s", data)` 会把完整请求体写进日志；设置 `LITELLM_LOG=DEBUG` 后，日志中 API Key 本身会脱敏，但 `user_api_key` 哈希是完整明文。类似 debug 日志还有几十处（sending response、routing decision、auth check），生产环境误开 DEBUG 就成了凭证泄露源。
- **`/spend/logs` 的哈希泄露**：该端点不是 FastAPI 标配，是 LiteLLM 自带的用量查询端点；默认需要 master_key（不是无认证）。返回结构包含 `api_key` 哈希前缀（如 `sk-...-1c89`）、`user`、`spend`、`model`、`timestamp`。攻击者可用哈希前缀做离线爆破范围匹配、确认某个 key 是否注册过（比调用 chat/completions 更隐蔽，不消耗 token/不触发限流）、结合 user 字段社工。
- **中心化凭证风险**：LiteLLM 的 admin 端点（`/spend/logs`、`/config/update`、`/key/generate`、`/user/new`）都依赖 master_key 单一凭证；master_key 一旦通过日志/配置泄露，所有 admin 端点一起沦陷。原文建议把“配置变更”和“只读审计”拆成不同 token。
- **速率限制缺失**：`/health/liveliness` 连续 20 次请求全部 200、不到 1 秒完成；LiteLLM 没有失败锁定/IP 封禁机制。API Key 格式为 `sk-` + 32 位十六进制，测试环境短 Key 可被逐步爆破（原文估算 6 位纯数字 100 万组合最多 14 小时）。
- **`/config/yaml` 有惊无险**：路由可访问但返回 422（参数校验失败），没有直接暴露 config.yaml 里的 master_key 哈希；如果该端点公开，危害会进一步升级。
- **与其他攻击面的关系**：版本/路由/OpenAPI 是 SSRF、Host Header、SSTI 等后续攻击的前置侦察；DEBUG 日志/`/spend/logs` 的 key 哈希是凭证泄露面；三者组合成“先情报、再凭证、后利用”的链路。

## 触发条件

- LiteLLM v1.40.0（原文审计版本），公开路由 allowlist 未收紧。
- 目标可从外网访问 4000 端口（默认监听 `0.0.0.0:4000`，防火墙未限制）。
- 生产环境误开 `LITELLM_LOG=DEBUG`，或日志文件/日志平台可被攻击者读取。
- `/spend/logs` 场景还需要 master_key（内部用户、配置泄露、日志泄露等）；它不是未认证端点。
- 速率限制缺失，攻击者可高频探测/爆破；目标 API Key 空间较小或格式可预测时更危险。

## 利用步骤

1. 未认证请求 `/health/readiness`，提取 `litellm_version`；用版本号匹配 GitHub Advisory/CVE。
2. 未认证请求 `/routes`，获取完整路由表；请求 `/openapi.json` 与 `/`，获取参数/认证方式。
3. 根据路由表找未认证端点、admin 端点、SSTI/SSRF 入口；构造后续 payload（如 `api_base` SSRF、`/prompts/test` 模板注入）。
4. 若目标日志开启 DEBUG 且可读，搜索 `receiving data`、`user_api_key`，提取 key 哈希；分析日志中的模型/路由/认证信息。
5. 若拿到 master_key，调用 `/spend/logs`，收集 API key 哈希前缀、user、消费记录；用哈希前缀做离线匹配/确认 key 存在/社工。
6. 用泄露信息爆破/猜测低熵 API Key（利用无速率限制），或直接使用泄露的 master_key 访问 admin 端点。
7. 进入 SSRF/横向移动阶段（见关联卡）。

## PoC

原文的未认证侦察请求（未在本机执行）：

```bash
# 1) 版本指纹
curl -s http://TARGET:4000/health/readiness | python3 -m json.tool
# 返回包含 "litellm_version": "1.40.0"

# 2) 路由表
curl -s http://TARGET:4000/routes | python3 -m json.tool
# 返回 /openapi.json, /, /docs/oauth2-redirect, /redoc, /ui 等

# 3) 接口文档
curl -s http://TARGET:4000/openapi.json | python3 -c \
  "import sys,json;d=json.load(sys.stdin);print(d.get('info',{}).get('title'), d.get('info',{}).get('version'))"
```

```bash
# 4) /spend/logs（需要 master_key，不是未认证）
curl -s http://TARGET:4000/spend/logs \
  -H "Authorization: Bearer <MASTER_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "sk-test-fake-key"}' | python3 -m json.tool
```

```json
{
  "response": [
    {
      "id": "...",
      "api_key": "sk-...-1c89",
      "user": "alice",
      "spend": 0.0234,
      "model": "gpt-3.5-turbo",
      "timestamp": "2026-07-17T10:23:45.123456+00:00",
      "request_id": "chatcmpl-..."
    }
  ],
  "total_spend": 12.34,
  "total_count": 234
}
```

```text
# DEBUG 日志（LITELLM_LOG=DEBUG）：
# receiving data: {... "user_api_key": "<完整哈希>" ...}
# API Key 本身脱敏，但 user_api_key 哈希明文
```

## 变体与关联

- **产品变体**：其他 AI 网关（Portkey、Helicone、Lunary 等）也可能公开 health/docs/routes/version；审计时先看公开路由 allowlist，再看 DEBUG 日志与 admin 端点。
- **泄露变体**：`/health/readiness` 版本、`/routes` 路由表、`/openapi.json`、Swagger UI、`/config/yaml`（本例 422）、DEBUG 日志、`/spend/logs` 哈希、错误堆栈、指标端点。
- **凭证变体**：master_key、低权 API Key、OIDC token、JWT、provider key；中心化凭证一旦泄露会解锁多个 admin 端点。
- **关联卡片**：[[ai-security-gateway-security-litellm-api-base-request-ssrf]]（拿到 key 后的 SSRF 利用）、[[ai-security-gateway-security-kong-ai-proxy-upstream-template-key-leak]]（网关 provider 密钥外泄）、[[web-generic-auth-ollama-unauth-api-model-management]]（未认证 AI 服务管理面）。
- **边界**：`/spend/logs` 需要 master_key，原文明确“不是无认证端点”；不要把该卡误解为未认证 API key 泄露。PoC 未在本机执行，不同版本路由 allowlist/日志格式可能变化。

## 检测与防御

- **公开路由最小化**：只保留必要的 liveness/readiness；生产设置 `NO_DOCS=true` 关闭 Swagger/OpenAPI；`/routes`、`/openapi.json`、`/` 加认证或仅内网访问。
- **版本隐藏**：health/readiness 不返回精确版本/构建号，或只返回聚合状态；减少攻击者匹配 CVE 的信息。
- **日志**：生产日志级别设为 WARNING，禁止 DEBUG；对请求体/响应体做字段级脱敏，尤其是 `user_api_key`、Authorization、api_key、provider key；日志平台最小权限。
- **凭证拆分**：master_key 只用于配置变更；`/spend/logs` 使用独立只读 token；admin 端点分权、可轮换、可审计。
- **速率限制与锁定**：公开端点在前置代理层限流；API key 认证失败计数、IP/账号锁定、异常枚举告警。
- **检测**：监控未认证访问 `/routes`、`/openapi.json`、`/health/readiness` 的高频请求；搜索日志中的 `user_api_key`/API key 哈希；监控 `/spend/logs` 异常查询与 API key 爆破模式。
- **部署面**：不要默认监听 `0.0.0.0:4000` 暴露公网；防火墙/安全组只放行必要来源；反向代理固定 Host 头并加一层认证。
