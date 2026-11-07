---
id: ai-security-agent-security-openclaw-trusted-proxies-localhost-auth-bypass
title: OpenClaw 反向代理未配置 trustedProxies：外部请求被当作 127.0.0.1 本机连接绕过 Gateway 鉴权
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: openclaw-gateway-trusted-proxies-localhost-auth-bypass
aliases:
- OpenClaw 未授权访问
- Clawdbot trustedProxies
- 反代 localhost 信任绕过
- Gateway auth bypass
- X-Forwarded-For 本机信任
tags:
- ai-security
- agent
- openclaw
- gateway
- reverse-proxy
- auth-bypass
- localhost
- trusted-proxies
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T09:58:49+08:00'
  notes: '已对照原文与 7 张图核对：文章为静态分析，核心证据是修复提交的 hasUntrustedProxyHeaders && resolvedAuth.mode==="none" 拒绝逻辑与回归测试，原文未在真实反代环境打通完整利用链，也未给出精确版本区间；卡片已用 confidence: medium 并在边界中明确该限制，PoC 标为验证思路，未夸大为现成 exploit。其余描述（反向代理改写源地址、本机信任、Gateway operator 控制面）与原文一致'
---

## 一句话结论

OpenClaw（原 Clawdbot/Moltbot）部署在 NGINX、Caddy 等反向代理之后、却没有配置 `gateway.trustedProxies` 时，代理会把外部请求的源地址改写成 `127.0.0.1`；Gateway 默认信任来自 localhost 的连接并自动授予本地权限，于是外部攻击者无需 Gateway Token/密码即可连上控制平面，进而修改沙箱与工具策略、调用 Agent 工具，最终在宿主机执行命令。

## 原理

- OpenClaw 的 Gateway 是单例控制平面，默认绑定 `127.0.0.1:18789`，通过 WebSocket 提供会话、调度、工具调用等管理能力；认证支持共享 `token` 或 `password`，未配置认证时本应 fail-closed。
- Gateway 同时有“本地连接可信”的便利逻辑：来自 loopback 的连接可自动批准设备配对/获得 operator 权限，以避免本机 CLI/Control UI 每次都要手工审批。
- 当应用位于反向代理之后时，TCP 连接的对端是代理（通常是 127.0.0.1），真实客户端地址由 `X-Forwarded-For`/`X-Real-IP` 等头传递。正确实现应只在 `gateway.trustedProxies` 明确列出代理地址时才信任这些头；旧版本在没有该配置时仍把代理连接当成“本机连接”。
- 于是攻击链变成：外部请求 → 反向代理 → 源地址被改写为 127.0.0.1 → Gateway 认为是本地管理员 → 跳过 token/设备身份校验 → 攻击者获得 operator 控制面。
- 修复提交在握手阶段增加了判断：`hasUntrustedProxyHeaders && resolvedAuth.mode === "none"` 时直接 `close(1008, "gateway auth required")`，并提示配置 `gateway.auth` 或 `gateway.trustedProxies`。这反证了修复前“代理头 + 无认证”会被放行。
- 本质：把“网络位置（loopback）”当成身份凭证；而反向代理会让外部流量在网络位置上“变成”本机流量，除非应用显式维护可信代理列表。

## 触发条件

- OpenClaw/Clawdbot 版本存在该旧逻辑（文章称可能属于早期 Clawdbot 版本；未给出精确版本区间）。
- 实例部署在 NGINX/Caddy 等反向代理后，且 `gateway.trustedProxies` 未配置或配置错误。
- Gateway 未启用 `token`/`password` 认证（或认证模式为 `none`），依赖“本机信任”放行。
- 代理会把客户端源地址改写为 127.0.0.1（或应用从代理头推断出 loopback），使 Gateway 判定为本地连接。
- 攻击者能访问代理暴露的 Gateway WebSocket 入口。

## 利用步骤

1. 指纹识别：访问目标，观察 WebSocket 关闭原因，常见字符串包括 `device identity required`、`control ui requires HTTPS or localhost (secure context)`、`unauthorized: gateway token missing`；这些表明是 OpenClaw Gateway。
2. 判断部署形态：若目标在 NGINX/Caddy 后，尝试直接建立无 token 的 WebSocket 连接，观察是否被当作本地连接放行（返回 health/connected，而不是 `gateway auth required`）。
3. 连接成功后以 operator 身份读取/修改配置：查看 `gateway.auth`、`gateway.trustedProxies`、沙箱与工具策略；把 sandbox/tool policy 调整为允许执行，或直接调用 Agent 的 exec/system.run 类工具。
4. 通过工具调用在宿主机执行命令（如 `id`、读 flag、反弹 shell），完成从“未授权控制面”到“宿主机 RCE”。
5. 若 Gateway 只监听 127.0.0.1 且代理未暴露，可尝试通过受害者的浏览器/Control UI 的 `gatewayUrl` 链路（见关联卡片）从本机发起连接。

## PoC

```text
# 文章没有给出完整的 WebSocket connect 帧，最小验证思路：
# 1) 经反向代理访问目标 Gateway（不要带 token/password）
# 2) 发起 WebSocket 握手，观察返回：
#    - 修复后：close 1008, "gateway auth required behind reverse proxy"
#    - 存在漏洞：正常建立，可收到 {"type":"event","event":"health",...}
```

```javascript
// 修复提交中的回归测试形态（修复前会失败/被放行，修复后应拒绝）
const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
  headers: { "x-forwarded-for": "203.0.113.10" },
});
await new Promise((resolve) => ws.once("open", resolve));
const res = await connectReq(ws);
// 修复后：res.ok === false，错误包含 "gateway auth required"
```

```text
# 若代理把源地址改写为 127.0.0.1 且未配置 trustedProxies，
# 旧版本会把该连接视为本地连接，直接授予 operator 权限；
# 之后即可通过 Gateway 的配置/工具接口调用 exec 类能力。
```

## 变体与关联

- 伪造头变体：`X-Forwarded-For: 127.0.0.1`、`X-Real-IP: 127.0.0.1`、`Forwarded: for=127.0.0.1`、IPv6 `::1`；是否生效取决于代理是否覆盖/追加以及应用是否信任。
- `gateway.trustedProxies` 配置成过宽网段（如 `0.0.0.0/0`）时，任意来源都能伪造代理头，效果类似。
- 关联：[[ai-security-agent-security-openclaw-control-ui-gatewayurl-token-leak-rce]]（Control UI 的 gatewayUrl 令牌外带，可从受害者浏览器侧接管 Gateway）、[[ai-security-agent-security-openclaw-node-invoke-approval-field-injection-rce]]（拿到 Gateway 后绕过 system.run 审批）、[[ai-security-agent-security-openclaw-webfetch-multistage-prompt-injection-rce]]（Agent 工具链的提示注入 RCE）。
- 边界：文章未给出完整 WebSocket 利用帧和精确受影响版本；若实例已配置 `gateway.auth`、正确设置 `gateway.trustedProxies`，或代理不改写源地址，本手法不成立。实际测试需在授权环境验证。

## 检测与防御

- 检测：审计配置中的 `gateway.auth` 与 `gateway.trustedProxies`；对“存在代理头但未配置可信代理”的组合告警；从外部探测无 token 的 WebSocket 连接是否被放行；检查 WebSocket 关闭原因是否为 `gateway auth required`。
- 修复：升级到包含该修复的版本；启用 `gateway.auth` 的 token/password；把 `gateway.trustedProxies` 精确配置为代理地址；在代理层确保外部请求不能被伪造为 loopback。
- 加固：Gateway 只绑定 127.0.0.1，通过 SSH 隧道/Tailscale 访问；反向代理层做认证；不要依赖“本机连接”做授权，设备身份与 operator 作用域都应显式校验。
