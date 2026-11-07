---
id: web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch
title: Web 缓存欺骗：CDN 静态判定与源站归一化错位
type: scenario
domain: web
path: web/generic/cache-poisoning
technique: web-cache-deception-url-normalization-mismatch
tags:
- cache-deception
- web-cache-deception
- cdn
- cache-key
- url-normalization
- semicolon
- nginx
- express
- cache-poisoning
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:49+08:00'
  notes: 已对照原文与 19 张图片核对；未在真实 CDN 复跑，变体有效性依框架/CDN 配置
url: /docs/web/generic/cache-poisoning/web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch/
draft: false
kb_aliases:
- WCD
- Web Cache Deception
- 缓存欺骗
- ;.css 变体
- 静态后缀嗅探
- 缓存键未规范化
---

## 一句话结论

当源站把 `;.css`、`.css`、`/.css`、`%3B`、`//` 等变体 URL 归一化后路由到私有接口，而 CDN 又因为 URL“长得像静态资源”或配置成“缓存所有 200”把它缓存、并用未规范化的原始 URI 当缓存键时，攻击者诱导已登录受害者访问一次变体 URL，随后匿名请求同一 URL 即可从缓存拿到受害者的私有数据。

## 原理

- 整条链没有单个环节“报错”，问题在于三个角色对同一个 URL 给出三种解释：
  - 浏览器原样发送 URL，不做修正；
  - CDN 按自己的字符串规则判断“是否缓存”和“缓存键是什么”；
  - 源站为兼容用户体验做宽容归一化，把变体路由到真实接口。
- 源站常见六条宽容规则：路径段内 `;` 之后被忽略（矩阵参数）；末尾 `name.ext` 剥成 `name`；末尾 `/.ext` 独立段被忽略；先做一次百分号解码；合并重复斜杠；大小写不敏感（框架相关）。因此 `/api/me/;.css`、`/api/me.css`、`/api/me/.css`、`/api/me%3B.css`、`/api/me%2F.css`、`//api/me` 等都可能落到私有路由 `/api/me`。
- CDN 侧常见两种误配置：
  - 静态后缀嗅探：对解码后的完整 URI 做 `\.(css|js|png|...)$` 匹配，或以分号判定静态资源，命中就缓存，完全不看源站的 `Cache-Control`；
  - 全量缓存：所有返回 200 的 GET 都缓存（如 Nginx `proxy_cache_valid 200`、部分云 CDN 的“缓存一切”）。
- 缓存键若直接用原始 `$request_uri`，`/api/me/;.css` 与 `/api/me` 是两个独立条目：前者是“静态资源”条目，后者是“私有接口”条目，攻击者可预测并直接复用前者。
- 关键顺序：受害者带 Cookie 的请求先把私有响应写进变体 URL 的缓存条目；攻击者匿名请求同一 URL 时 CDN 直接命中，源站完全收不到第二次请求，因此源站侧没有攻击者日志。
- 成立需要三条件同时满足：源站能归一化命中私有接口；CDN 认为该 URL 值得缓存；缓存键不做与源站一致的规范化。

## 触发条件

- 站点存在返回会话私有数据的接口（账户信息、订单、预签 URL、CSRF Token 等），且该接口可被某个变体 URL 归一化命中。
- 源站使用前缀挂载或宽容路由（如 Express `app.use('/api/me', ...)`、Nginx `merge_slashes`、框架默认大小写不敏感），而不是精确匹配。
- CDN/反向代理开启静态后缀自动缓存，或对所有 200 全量缓存；且缓存键使用原始 URI。
- 受害者处于登录态，并会被诱导访问攻击者构造的 URL（链接、短链、`<img>`/`<link>` 自动加载、二维码等）。
- 源站私有响应没有 `Cache-Control: private, no-store`，或 CDN 无视该头。

## 利用步骤

1. 找到返回私有数据的接口，确认其响应内容包含可识别的私有字段（如 `balance`、`email`、`token`）。
2. 用带受害者 Cookie 的请求直连源站，测试变体归一化：`/api/me/;.css`、`/api/me.css`、`/api/me/.css`、`/api/me%3B.css`、`/api/me%2F.css`、`/api/me..css`、`/api/me?foo=.css`、`/api/me/`、`/API/ME`、`//api/me`。
3. 通过 CDN 分别以受害者身份和匿名身份请求同一变体，比较状态码、`X-Cache`、响应体：受害者为 200 且匿名也为 200/HIT 且含私有字段，即 WCD 成立。
4. 用 tcpdump 或源站日志确认匿名请求没有回源，数据确实来自缓存。
5. 对真实用户投放变体 URL，等待其登录态访问后，匿名读取缓存；若响应含会话令牌、预签 URL、密码重置链接，可进一步以受害者身份操作。
6. 若静态嗅探不成立，观察是否“全量缓存”：此时连变体都不需要，受害者访问正常 `/api/me` 就会被缓存。

## PoC

```bash
# 1) 受害者带 Cookie 访问变体，CDN 将私有响应写入该 URL 的缓存条目
curl -s -i -b "session=victim" "http://cdn.example/api/me/;.css"
# 期望：200，X-Cache: STORED，X-Origin-Norm: /api/me，响应含私有 JSON

# 2) 攻击者匿名请求同一 URL，直接命中缓存
curl -s -i "http://cdn.example/api/me/;.css"
# 期望：200，X-Cache: HIT，响应仍是受害者的私有数据

# 3) 负向对照：攻击者直接请求真实接口应被拒
curl -s -i "http://cdn.example/api/me"
# 期望：401/403，X-Cache: MISS，证明攻击者本身无权限
```

最小判定逻辑：

```python
# 受害者拿到私有数据，且匿名请求也拿到同一私有数据并标记缓存命中
wcd = (victim_status == 200 and PRIV_MARK in victim_body
       and anon_status == 200 and PRIV_MARK in anon_body
       and anon_cache == "HIT")
```

真实组件复现要点：Express 5.x 用 `app.use('/api/me', handler)` 前缀挂载私有接口；Nginx `proxy_cache_key $scheme$proxy_host$request_uri` 保留原始 URI、`proxy_cache_valid 200 10m` 全量缓存。此配置下 `/api/me/;.css` 第一次 MISS/存储，第二次匿名 HIT，源站日志只出现受害者请求。

## 变体与关联

- 变体家族与实测结果（模拟 CDN，静态嗅探模式 10/13 成立，全量缓存模式 13/13 成立）：
  - 分号家族：`/api/me/;.css`、`/api/me;.css`；
  - 后缀家族：`/api/me.css`、`/api/me/.css`、`/api/me..css`；
  - 编码家族：`/api/me%3B.css`、`/api/me%2F.css`、`/api/me%2Ecss`；
  - query 家族：`/api/me?foo=.css`、`/api/me?callback=.css`（源站只按 path 路由，CDN 却对含 query 的完整 URI 做静态判定）；
  - 其他：`/api/me/`、`/API/ME`、`//api/me`（静态嗅探下不缓存，全量缓存下成立）。
- 变体是否有效取决于框架与 CDN 的具体实现：真实 Express 5.2.1 + Nginx 1.26.0 上 9 个测试中只有 5 个成立（`/;.css`、`/.css`、`/`、`?foo=.css`、`/API/ME`）；`/api/me;.css`、`/api/me.css` 因前缀挂载要求斜杠返回 404，`%2F.css` 因编码斜杠未参与解码匹配返回 404，`//api/me` 因无 URI 的 `proxy_pass` 原样转发而失配。不能把模拟环境的矩阵直接当成通用结论。
- 关联：`[[web-generic-cache-poisoning-chromium-cn-cache-key-xss]]` 讲浏览器侧缓存键分区；本卡讲 CDN/反向代理侧缓存判定与源站路由归一化的错位，两者都属于“缓存键与真实资源语义不一致”。
- 与其他漏洞的组合：泄露的响应若含预签 URL、临时令牌、会话级 CSRF Token，可把读泄露升级为写操作；若同时存在 XSS 或开放重定向，可降低诱导成本。

## 检测与防御

- 检测（外部）：对私有接口枚举上述变体，比较“受害者请求”和“匿名请求”的状态码、缓存头与响应体；重点看匿名请求是否 200 且包含本应需要登录的字段。
- 检测（日志）：同一 URL 先出现带 Cookie 的请求、随后出现无 Cookie 的命中缓存请求；但多数访问日志不记录 Cookie/身份，需在 CDN 侧关联缓存键与请求者。
- 检测（流量）：源站日志中攻击者请求缺失、CDN 返回大段 JSON 却标记为静态资源；匿名请求的响应体大小与静态资源不符。
- 修复第一层：所有私有/会话响应显式返回 `Cache-Control: private, no-store`；但面对无视该头的 CDN 配置，单靠这一层不够。
- 修复第二层：缓存键规范化。CDN 命中前按与源站相同的规则归一化 URL，若结果命中 `/api/` 等私有前缀则不缓存、不命中；缓存键也使用规范化后的路径，避免同一资源多个条目。
- 修复第三层：私有接口精确匹配。拒绝任何需要归一化才能命中的路径（`normalize(path) != path` 一律拒绝），不依赖前缀挂载的宽容匹配。
- 修复第四层：收紧 CDN 静态判定。关闭“自动静态缓存”或限定只缓存 `/static/`、`/assets/` 等托管目录；静态判定只针对 path，不对含 query 的完整 URI 做正则；对私有前缀设置缓存例外。
- 加固：平台层面把“登录态响应默认不可缓存”做成框架默认策略；出站/边缘层对 `;`、`%3B`、`%2F`、`%2E`、重复斜杠、大小写变体做归一化后再做安全判断。
- 回归：把变体矩阵接入 CI（`probe.py | grep "WCD 成立" && exit 1`），并定期对预发/生产 CDN 做只读匿名探测。
