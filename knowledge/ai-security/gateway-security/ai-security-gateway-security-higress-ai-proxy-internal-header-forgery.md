---
id: ai-security-gateway-security-higress-ai-proxy-internal-header-forgery
title: Higress ai-proxy 内部信号头可伪造：客户端提供 x-higress-fallback-from 令伪装的 X-HI-ORIGINAL-AUTH 透传到下游
type: scenario
domain: ai-security
path: ai-security/gateway-security
technique: ai-gateway-internal-signal-header-forgery
aliases:
- Higress x-higress-fallback-from 伪造
- X-HI-ORIGINAL-AUTH 凭证注入
- AI 网关内部信号头
- ai-proxy 原始凭证头透传
- internal_only_headers 缺失
tags:
- ai-security
- higress
- ai-gateway
- header-injection
- credential-injection
- trust-boundary
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Higress v2.2.4
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:26:35+08:00'
  notes: 已对照原文核对：main.go:161-197 仅在 fallback-from 为空时重锚定、saveContextsToHeaders 因 ctx 为空跳过覆盖、util/http.go 中 X-HI-ORIGINAL-AUTH 优先于 Authorization；A/B 实测 B 组 FORGED-BBB 原样到下游（emb10）。下游 key-auth 身份接管仅为代码依据，卡片 confidence=medium 已如实标注；未复跑
---

## 一句话结论

Higress v2.2.4 的 ai-proxy 把客户端可传入的 `x-higress-fallback-from` 当作“本网关内部重定向”的信号：只要该头非空，插件就跳过从当前 `Authorization` 重新锚定原始凭证的分支；随后因上下文为空又跳过覆盖 `X-HI-ORIGINAL-AUTH` 的步骤，客户端伪造的原始凭证头因此原样透传到下游，并在下游取值函数中优先于真实 `Authorization`。

## 原理

- `plugins/wasm-go/extensions/ai-proxy/main.go:161-197` 先用 `headerToOriginalHeaderMapping` 清掉映射中的头，然后读取 `x-higress-fallback-from`：
  - 为空：视为“首次进入网关”，删除 `X-HI-ORIGINAL-AUTH`，从当前 `Authorization` 取出值并写入 `ctxOriginalAuth`；
  - 非空：视为“内部重定向回入”，整段重锚定逻辑跳过。
- `main.go:199-217` 的 `saveContextsToHeaders` 只有在 `ctxOriginalAuth` 非空时才 `ReplaceHttpRequestHeader` 覆盖 `X-HI-ORIGINAL-AUTH`。重锚定被跳过时 `ctxOriginalAuth` 未被赋值，取到默认空串，覆盖步骤也随之跳过，客户端给的值保留。
- `util/http.go:204-212` 的 `GetOriginalRequestAuth` 先读 `X-HI-ORIGINAL-AUTH`，非空直接返回；否则才回退到 `Authorization`。因此伪造头在下游的“原始凭证”语义中优先级更高。
- 代码注释本身写明了安全依赖：该信号可靠的前提是“外部调用者无法提供 `x-higress-fallback-from`”；保障方法是把 `x-higress-fallback-from` 与 `x-hi-original-auth` 列入 HCM 的 `internal_only_headers`，但注释把它归为 defense-in-depth，默认部署并不满足这个前提。
- 这不是单个函数写错，而是四步各自正确的逻辑串起来形成的凭证注入：客户端带信号头 → 重锚定分支跳过 → 上下文为空 → 覆盖分支跳过 → 伪造头活到下游。任何下游消费者使用 `GetOriginalRequestAuth`（例如注释点名的 key-auth 在重定向后的重新认证）都会拿到攻击者给的值。

## 触发条件

- Higress v2.2.4 部署启用 ai-proxy 插件（原文以 openai 类型、customDomain/customPath 指向 mock 上游验证）；
- HCM 未把 `x-higress-fallback-from` 与 `x-hi-original-auth` 列入 `internal_only_headers`（默认部署如此）；
- 攻击者能向网关路由发送请求，并可自带上述两个请求头；
- 下游存在使用 `GetOriginalRequestAuth` 或直接读取 `X-HI-ORIGINAL-AUTH` 做鉴权/记账的消费者。

## 利用步骤

1. 确认目标网关运行 Higress ai-proxy，且请求可到达插件处理链路。
2. 发送两组请求做差分：A 组只带伪造的 `X-HI-ORIGINAL-AUTH`；B 组同时带 `x-higress-fallback-from: 1`。
3. 观察下游收到的头：A 组的伪造值应被替换为当前 `Authorization`（防护生效）；B 组的伪造值应原样保留。
4. 若下游有基于 `X-HI-ORIGINAL-AUTH` 的鉴权、限流或记账逻辑，则攻击者可用 B 组构造任意“原始凭证”身份；具体能否接管身份取决于该消费者的实现。

## PoC

```bash
# A 组：伪造 X-HI-ORIGINAL-AUTH，不带 fallback-from
curl -X POST http://<gateway>/v1/chat/completions \
  -H 'Host: mock.local' \
  -H 'Authorization: Bearer CLIENT-REAL-AUTH' \
  -H 'X-HI-ORIGINAL-AUTH: FORGED-AAA' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'

# B 组：同样两个头，加上内部信号头
curl -X POST http://<gateway>/v1/chat/completions \
  -H 'Host: mock.local' \
  -H 'Authorization: Bearer CLIENT-REAL-AUTH' \
  -H 'X-HI-ORIGINAL-AUTH: FORGED-BBB' \
  -H 'x-higress-fallback-from: 1' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

下游记录头部的 mock 预期结果：

```text
A 组：x-hi-original-auth = Bearer CLIENT-REAL-AUTH
       x-higress-fallback-from = (absent)
B 组：x-hi-original-auth = FORGED-BBB
       x-higress-fallback-from = 1
```

原文还观察到插件会把 `Authorization` 替换为自己的 provider token；因此 B 组下游同时能看到 provider token（`Authorization`）与攻击者伪造的原始凭证头（`X-HI-ORIGINAL-AUTH`）。

## 变体与关联

- 变体：级联网关。上游网关自身可能处于 internal_redirect 链中再转发到本网关，此时更应把内部信号头列为 internal-only，否则级联链路上的任意客户端都可能注入。
- 变体：任何把“某个请求头是否存在”当作内部信号的实现。信号头一旦可被外部提供，依赖它的分支就会被外部控制。
- 关联 [[ai-security-gateway-security-kong-ai-proxy-upstream-template-key-leak]]（密钥去向可被请求控制）与 [[ai-security-gateway-security-apisix-kong-secret-at-rest-audit]]（密钥存放声明的落盘核查），本卡对应密钥/凭证在网关内部的“归属”环节。
- 证据边界：原文实测确认伪造的 `X-HI-ORIGINAL-AUTH` 能活到下游；从“头透传”到“下游身份被换掉”还依赖下游消费者读取该头，原文未搭建完整的 key-auth 链路，因此本卡按 confidence: medium 标注，不把下游接管写成已实测。

## 检测与防御

- **配置修复**：把 `x-higress-fallback-from` 和 `x-hi-original-auth` 同时列入 HCM 的 `internal_only_headers`，让外部请求无法提供；这应成为默认配置而不是可选加固。
- **代码/设计**：不要用客户端可达的请求头作为“内部信号”；若必须使用，应在入口默认剥离，或改用不可伪造的签名/上下文标记。
- **下游排查**：审计所有调用 `GetOriginalRequestAuth` 或直接读取 `X-HI-ORIGINAL-AUTH` 的消费者（key-auth 重认证、审计、计费），确认其是否会把该头当作可信身份。
- **检测**：在网关日志中标记同时出现 `x-higress-fallback-from` 与外部来源的请求；对携带内部头的外部请求告警；检查 ai-proxy 上游请求中 `X-HI-ORIGINAL-AUTH` 与当前 `Authorization` 不一致的情况。
