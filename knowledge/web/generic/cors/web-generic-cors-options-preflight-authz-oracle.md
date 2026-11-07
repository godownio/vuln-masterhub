---
id: web-generic-cors-options-preflight-authz-oracle
title: OPTIONS 预检鉴权缺失导致对象/方法/请求头枚举
type: scenario
domain: web
path: web/generic/cors
technique: options-preflight-authz-oracle
aliases:
- OPTIONS 越权
- 预检鉴权缺失
- CORS 预检枚举
- 对象存在性探测
- Access-Control-Request-Headers 回显
tags:
- cors
- options
- preflight
- authz
- enumeration
- idor
- api
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:36:29+08:00'
  notes: 已对照原文核对：204/404存在性差异、方法泄露、请求头回显与修复版对比均与13张截图一致；原文为本地lab验证，卡片已如实标注真实写请求仍受业务鉴权约束，未过度声称数据读取；无组件版本信息，未设versions；未执行PoC
---

## 一句话结论

OPTIONS 预检常被 CORS 中间件/网关提前处理并跳过登录态校验；如果预检分支还会查询业务对象、按路由/角色生成方法策略、或原样回显 `Origin` 与 `Access-Control-Request-Headers`，它就从“跨域询问”变成了一个未授权 oracle：存在对象返回 204、不存在返回 404，可枚举对象、探测方法和敏感请求头；若同时允许 Credentials 与写方法，还可能为跨源写请求铺路。

## 原理

- 浏览器跨源发送非简单请求前会先发 OPTIONS 预检，询问“这个源、这个方法、这些请求头是否允许”。预检本身不应携带 Cookie/Authorization，服务端也不应依赖它完成用户身份判断。
- 正常实现应返回与具体对象无关的静态 CORS 策略：不查对象表、不按用户角色变化、不回显任意请求头。
- 缺陷实现把预检写成“按实际路由和实际对象生成策略”：识别 OPTIONS → 跳过登录态 → 匹配 `/api/orders/{id}` → 查询订单是否存在 → 返回 `Allow`/`Access-Control-Allow-Methods` → 回显请求头 → 204。
- 于是即使真实 GET/PATCH 对当前低权限用户返回 403，同一资源的 OPTIONS 仍返回 204；不存在的资源返回 404。这个差异就是对象级存在性泄露，且不需要任何凭证。
- 若预检还动态回显任意 `Origin`、设置 `Access-Control-Allow-Credentials: true`、放行写方法，浏览器会认为跨源写请求被允许；后续真实请求是否成功仍取决于业务鉴权，但预检层已经不再提供阻断。
- 需要区分：OPTIONS 对“路由形态存在但对象不存在”返回 204 可以是正常的（只匹配路由模板）；只有响应随对象是否存在/归属变化时，才是对象级 oracle。

## 触发条件

- OPTIONS 由 CORS 中间件/网关/框架统一处理，且该分支跳过认证/授权。
- 预检处理逻辑读取了业务状态：对象是否存在、对象归属、租户、路由能力、用户角色等。
- 响应中的状态码/Allow/`Access-Control-Allow-Methods`/自定义头随对象编号或用户变化。
- 预检原样回显 `Origin` 或 `Access-Control-Request-Headers`；同时允许 Credentials 与写方法时风险更高。
- 真实业务方法本身有对象级鉴权（否则直接越权，不需要该 oracle）。

## 利用步骤

1. 用低权限账号请求自己的对象、他人的对象、不存在的对象，记录 GET/PATCH 状态码（如 200/403/404）。
2. 对同一路径发送不带 Authorization 的 OPTIONS，带 `Origin`、`Access-Control-Request-Method`、`Access-Control-Request-Headers`。
3. 比较 OPTIONS 状态码：存在但无权访问的对象返回 204、不存在返回 404 → 对象存在性 oracle 成立。
4. 批量遍历对象编号，按 204/404 差异枚举有效对象。
5. 改变 `Access-Control-Request-Headers`，观察 `Access-Control-Allow-Headers` 是否原样回显；探测 `x-tenant-id`、`x-forwarded-user`、`x-admin-token` 等敏感头是否被放行。
6. 检查是否回显任意 `Origin`、是否 `Access-Control-Allow-Credentials: true`、是否允许 PATCH/PUT/DELETE；若满足，评估跨源写请求的实际业务鉴权。
7. 记录 `Allow`/`X-Policy-Route` 等响应头泄露的方法/路由策略。

## PoC

```bash
# 1) 真实方法：Alice 读 Bob 的订单 -> 403（业务鉴权正常）
curl -i http://target/api/orders/1002 -H 'Authorization: Bearer alice-token'

# 2) 同一路径的 OPTIONS 预检：不带 Authorization -> 204，暴露对象存在
curl -i -X OPTIONS http://target/api/orders/1002 \
  -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: PATCH' \
  -H 'Access-Control-Request-Headers: authorization,content-type,x-tenant-id'

# 3) 不存在的对象 -> 404，与 204 形成存在性差异
curl -i -X OPTIONS http://target/api/orders/1999 \
  -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: PATCH'

# 4) 批量枚举
for id in 1001 1002 1999 9001; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS \
    "http://target/api/orders/$id" \
    -H 'Origin: https://evil.example' \
    -H 'Access-Control-Request-Method: PATCH')
  printf 'order=%s options_status=%s\n' "$id" "$code"
done

# 5) 请求头回显探测
for h in x-tenant-id x-forwarded-user x-admin-token authorization; do
  echo "[$h]"
  curl -s -i -X OPTIONS http://target/api/orders/1002 \
    -H 'Origin: https://evil.example' \
    -H 'Access-Control-Request-Method: PATCH' \
    -H "Access-Control-Request-Headers: $h" \
    | grep -i '^Access-Control-Allow-Headers:'
done
```

说明：以上为验证结构，需替换目标地址与对象编号；批量枚举应控制频率并获得授权。PoC 未在目标环境执行。

## 变体与关联

- 变体：状态码差异可能是 204/404、200/404、401/403 等；关键是同一路由下响应随对象存在/归属变化。
- 变体：`X-Policy-Route: order-write` 等自定义响应头直接泄露路由/方法策略；`Allow` 头泄露支持的方法。
- 变体：动态回显 `Origin` + `Access-Control-Allow-Credentials: true` + 写方法，构成跨源写请求的预检放行；真实方法仍需鉴权。
- 变体：多租户系统可按 `x-tenant-id` 探测租户边界；若网关错误信任该头，风险进一步放大。
- 关联：[[web-generic-auth-api-signature-validation-differential-test]]（同为“看起来有校验、实际可被绕过”的对照测试思路）；[[web-generic-cache-poisoning-chromium-cn-cache-key-xss]]（CORS/浏览器边界相关的另一类跨源问题）。
- 关联：[[pentest-recon-webpack-apiurlkey-endpoint-extraction]]（先拿到端点清单再做 OPTIONS 探测）。

## 检测与防御

- 检测：对同一路由的不同对象发送 OPTIONS，比较状态码/Allow/自定义头是否随对象变化；对任意 Origin/请求头做回显测试。
- 检测：网关日志中大量 OPTIONS 请求覆盖连续对象编号；同一来源先 OPTIONS 枚举再访问真实接口。
- 防御：OPTIONS 只回答静态 CORS 策略，不访问对象表、不按用户角色生成方法、不查询对象归属；只校验路由形态。
- 防御：Origin 使用显式白名单，不原样回显任意 Origin；`Access-Control-Allow-Headers` 只返回白名单内的头，不回显请求头列表。
- 防御：不要同时使用 `Access-Control-Allow-Credentials: true` 与任意 Origin；写方法按最小必要放行；设置正确的 `Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers`。
- 防御：真实业务方法继续独立做身份、对象归属、租户边界与 CSRF 校验；OPTIONS 不是授权决策点。
