---
id: web-generic-auth-fastify-badurl-shared-404-handler-bypass
title: Fastify 畸形 URL 直调最后注册的 404 处理器，绕过封装前缀认证（CVE-2026-76169）
type: scenario
domain: web
path: web/generic/auth
technique: fastify-badurl-shared-404-handler-auth-bypass
tags:
- fastify
- nodejs
- auth-bypass
- cve-2026-76169
- url-parsing
- lifecycle-hooks
- not-found-handler
- encapsulation
- access-control
cve:
- CVE-2026-76169
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: fastify >= 4.0.0 且 < 5.12.2（修复版本 5.12.2；4.x 无补丁版本）
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:49:31+08:00'
  notes: 已对照原文核对；双路由器结构、主路由器无方法树、safeDecodeURI 先解码后匹配、_routeEventHandler 最后注册者胜出、arrange404 的 bind 死代码、直调绕过生命周期、Docker 双版本复现（5.12.1 返回 200 private canary、5.12.2 返回 400 FST_ERR_BAD_URL）与计数器/日志证据，均与正文和 23 张图逐项一致；受影响版本与 CVE 编号正确，affected_versions 已按原文设置。原文为作者原创且端到端复现，非理论链。
url: /docs/web/generic/auth/web-generic-auth-fastify-badurl-shared-404-handler-bypass/
draft: false
kb_aliases:
- CVE-2026-76169
- GHSA-p68q-wchp-6fh7
- Fastify 404 鉴权绕过
- onBadUrl 绕过
- '%c0 绕过认证'
- FST_ERR_BAD_URL
- Fastify 封装绕过
- 共享 handler 指针
---

## 一句话结论

Fastify `>= 4.0.0, < 5.12.2` 中，404 路由器在解码畸形 URL 失败时，会用一个跨插件共享的 handler 指针直接调用“最后注册”的自定义 404 处理器；调用不经过任何生命周期钩子、也不携带该处理器所属前缀的 context。攻击者从任意前缀、以未认证状态发送 `DELETE /public/%c0` 这类路径即可读取受保护前缀 404 处理器的响应（CVE-2026-76169，CVSS 7.5）。

## 原理

- Fastify 进程内有两个 find-my-way 路由器：主路由器持有业务路由，404 路由器按前缀持有各插件的自定义 404 处理器（注册为 `/private/*` 等通配路由）。
- 主路由器 `find()` 先取 `trees[method]`；方法没有注册过路由时直接返回 null，不读取路径、不做解码，转 `defaultRoute` 把原始请求交给 404 路由器。
- 404 路由器 `find()` 在树匹配之前先调用 `safeDecodeURI()`。路径段内出现非法百分号编码（如 `%c0`：合法十六进制但不是合法 UTF-8 引导字节）时 `decodeURI` 抛 `URIError`，进入 `onBadUrl` 分支——此时前缀匹配尚未发生，请求的“前缀身份”已经丢失。
- 5.12.1 给 404 路由器的 `onBadUrl` 装的是 `createRouteEventHandler()` 闭包：它用根实例的（空）404 context 重建 Request/Reply，然后直接调用模块级共享变量 `_routeEventHandler(request, reply)`。
- `_routeEventHandler` 在每次 `setNotFoundHandler` 时被赋值为当前处理器，因此只保存“最后注册者”，与前缀、调用者身份无关。`arrange404` 中的多次 `bind` 由于 `Function.prototype.bind` 首次绑定后不可覆盖，实际是死代码，`this` 永远是根实例。
- 直调路径不启动 `routeHandler`，不执行 `onRequest`、`preParsing`、`preValidation`、`preHandler` 中的任何一个。认证钩子仍完好保存在 privateContext.preHandler 数组里，但没有任何代码去执行它。
- 修复 5.12.2 把 404 路由器的 `onBadUrl` 改为复用主路由器已有的 fail-closed 守卫（默认 400 `FST_ERR_BAD_URL`），并删除共享指针与直调闭包；畸形 URL 在进入任何处理器前被拒绝。

## 触发条件

1. 应用用 `setNotFoundHandler()` 注册了自定义 404 处理器，且把认证放在它的 `preHandler`（或其他生命周期钩子）里；受保护处理器是“最后注册”的那个（只注册一个时自动满足，全局注册同样受影响）。
2. 攻击方法在主路由器中没有对应的方法树（如应用只注册 GET/HEAD，则 DELETE、OPTIONS、PUT、PATCH 等可用）。
3. 请求路径的**路径段内**存在 `decodeURI` 会抛异常的百分号编码（`%c0`、`%zz`、`%e0%80`、截断的 `%c` 或末尾孤立 `%`）；放在 `?` 之后的查询串里无效。
4. 受保护 404 处理器的响应包含有价值的数据，或处理器有可被未认证驱动的副作用。

## 利用步骤

1. 探测应用使用的 Fastify 版本（`package.json` / 响应特征 / `instance.version` 不可靠，5.12.2 包内曾残留 `VERSION='5.12.1'`）。
2. 枚举主路由器未注册的方法：OPTIONS、DELETE、PUT、PATCH、TRACE、PROPFIND 等；避开会触发主路由器 400 守卫的 GET/HEAD。
3. 选一个路径段内的非法编码载荷（`%c0` 最常用），请求任意前缀甚至不存在的前缀，路径可用 `--path-as-is` 防止客户端改写。
4. 不带 Authorization/Cookie，观察是否返回受保护 404 处理器的数据而不是 401/302。
5. 用负对照确认：同一载荷改用 GET/HEAD 应返回 400；把非法编码放到 `?` 后应走正常 404 生命周期。
6. 若响应内容依赖处理器，尝试枚举更多前缀/方法，评估泄露面；不要对生产环境做破坏性方法（如 DELETE 可能触发处理器副作用）。

## PoC

```bash
# 受影响版本：未认证读取 /private 前缀 404 处理器的 canary
curl -i -X DELETE --path-as-is 'http://target:3000/public/%c0'
# => HTTP 200, body: private canary

# 负对照：主路由器有 GET 树，自家守卫拦截
curl -i -X GET --path-as-is 'http://target:3000/public/%c0'
# => HTTP 400 FST_ERR_BAD_URL

# 负对照：合法编码走正常 public 404 生命周期
curl -i -X DELETE --path-as-is 'http://target:3000/public/%41'
# => HTTP 404 public not found

# 修复版本：fail-closed
curl -i -X DELETE --path-as-is 'http://target:3001/public/%c0'
# => HTTP 400 FST_ERR_BAD_URL
```

```text
# 其他可用载荷：%zz、%e0%80、%c0%af、%c（截断）、结尾孤立的 %。
# 其他可用方法：OPTIONS、PUT、PATCH、TRACE、PROPFIND、MKCOL 等主路由器无树的方法。
# 前缀不影响：/private/%c0、/%c0、/totally-unknown/%c0 同样触发。
```

## 变体与关联

- 变体：编码形态任意，判据只是 `decodeURI` 是否抛异常；黑名单拦 `%c0` 无法覆盖 `%zz`、`%e0%80`、截断 `%` 等。
- 变体：注册顺序决定受害者——共享指针指向最后注册者；把 public/private 注册顺序对调，泄露消失（被调用的是 public 处理器）。
- 变体：仅根实例全局注册一个 404 处理器同样被直调，不存在“架构简单就安全”。
- 变体：`return` 返回值风格的处理器在直调路径上返回值无人接管，响应不发送、连接挂起，形成轻量 DoS；`reply.send` 风格则表现为数据泄露。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（另一框架中“原始 URI/路径解析与路由不一致”导致鉴权绕过，可对照其路径变体思路）。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（路径前缀放行 + 规范化差异的同类逻辑）。
- 边界：未注册自定义 404 处理器、认证不在钩子里而在处理器函数体首行、或应用对所有方法都注册了主路由树时，该链不成立或危害受限。

## 检测与防御

- 修复：升级到 fastify 5.12.2+（4.x 无补丁，必须跨大版本升级）；升级后畸形 URL 统一返回 400 `FST_ERR_BAD_URL`，依赖自定义 404 覆盖畸形路径的应用需改用 `frameworkErrors` 或 `routerOptions.onBadUrl`。
- 缓解（无法立即升级）：网关/反向代理在语法层拒绝非法百分号编码（百分号后必须两个合法十六进制且解码为合法 UTF-8），不要用特征黑名单；代理层只放行业务实际使用的方法。
- 缓解：全局搜索 `setNotFoundHandler`，确保处理器不返回受保护数据；把认证从钩子移到处理器函数体首行（直调也绕不过函数体内的检查）。
- 注意：根实例全局 `addHook('onRequest', auth)` 不能作为缓解——这条路径不执行任何钩子。
- 检测：同一 reqId 下出现处理器日志但缺少 “incoming request”/“request completed”；畸形 URL 返回非 400；大量 DELETE/OPTIONS/PUT 打到不存在路径却拿到 200；升级后可用 `curl -X DELETE 'http://target/%c0'` 应返回 400 作为冒烟测试。
- 审计模板：列出框架中所有不经过主分发/生命周期而构造 Request/Reply 的出口（错误回调、URL 解析失败、连接层错误、OPTIONS/HEAD 回退等），逐个检查其 context 与钩子语义是否被保留。
