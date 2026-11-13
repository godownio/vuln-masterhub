---
id: web-generic-ssrf-fragment-double-urlencode-allowlist-bypass
title: SSRF 白名单绕过：双重 URL 编码
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-fragment-double-urlencode-allowlist-bypass
aliases:
- '%2523 SSRF 绕过'
- 双重编码
- fragment 截断白名单
- localhost#@allowed-host
- URL 二次解码绕过
- 路径关键字双重编码
tags:
- ssrf
- allowlist-bypass
- url-parsing
- url-encoding
- fragment
- userinfo
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V492
  verified_at: '2026-11-11T00:36:09+08:00'
  notes: '已对照原文与49张图片核对：白名单基线(127.0.0.1 拦截/user@stock 放行)、单#被拒、%2523 返回500疑似连 username、localhost:80%2523@stock.../admin 成功、删除 carlos 成功、路径 /admin 双重编码 %25%36%31dmin 绕过黑名单，均与原文递进一致。dedup 判 likely_duplicate 的 userinfo 卡为 @ 前 userinfo 混淆(真实host在@后)，本卡为双重解码后 # 片段截断(真实host在片段前)，机制/触发/PoC 不同，--force 保留理由成立。其余跳过项均有既有卡覆盖(ip-notation、multi-layer-decode、fsockopen gopher mysql、redirect-chain)；路径双重编码作为同源''解码层级错位''变体写入本卡，未另拆。dup-scan.json(2026-11-08)早于建卡且无本卡 pair。原文非组件版本类，已--clear。未验证点：本卡未复现。'
---

## 一句话结论

当 SSRF 白名单只检查 URL 字符串中是否出现允许的域名、而真正发请求的客户端会多解码一层 URL 时，把 `#` 双重编码为 `%2523` 构造 `http://127.0.0.1:80%2523@allowed-host/admin`：校验器看到字符串里有 `allowed-host` 而放行，客户端解码出 `#` 后 `@allowed-host/admin` 变成片段，实际连接的主机是 `127.0.0.1`，从而访问仅限本地的管理接口。

## 原理

- URL 语义：`#` 之后是 fragment，不参与主机解析；客户端连接的是 authority 中的 host。`http://127.0.0.1:80#@allowed-host/admin` 的真实主机是 `127.0.0.1:80`，`@allowed-host/admin` 只是片段。
- 校验与执行解码次数不一致：白名单校验器按字符串匹配（或只解码一次），看到的是 `%2523@allowed-host`，认为目标包含允许域名；后端 HTTP 客户端再解码一次得到 `%23`（或再解码成 `#`），fragment 截断生效，authority 变成 `127.0.0.1:80`。
- 原文在实验环境中的验证递进：`http://username@stock.weliketoshop.net/` 被接受（userinfo 干扰）→ `http://username#@stock.weliketoshop.net/` 被拒绝 → `http://username%2523@stock.weliketoshop.net/` 返回 500 且疑似连接 “username”（证明客户端把 `%2523` 解成 `#` 后 host 只剩 username）→ `http://localhost:80%2523@stock.weliketoshop.net/admin` 成功访问本地 admin。
- 同一“编码层级错位”还可用于路径关键字黑名单：把 `/admin` 的字符双重编码（如 `%25%36%31dmin`，一次解码为 `%61dmin`、再解码为 `admin`），过滤器看不到 `/admin`，后端解码后仍访问到该路径。

## 触发条件

- 存在用户可控 URL 的 SSRF 入口（图片抓取、URL 预览、第三方集成、库存查询等）。
- 防护为字符串白名单/黑名单（检查域名或路径关键字），不是解析后按 hostname 精确比较。
- 执行请求的客户端/库与校验器对 URL 的解码次数或 fragment 处理不一致（常见的“校验解码一次、客户端再解码一次”）。
- 目标内网服务可从 SSRF 主机访问，且响应可回显。

## 利用步骤

1. 确认白名单基线：直接 `http://127.0.0.1/` 被拦截，而 `http://user@allowed-host/` 被接受，说明是字符串匹配且允许 userinfo。
2. 测试单层 `#`：`http://user#@allowed-host/` 被拒绝，说明校验器会把 `#` 当片段处理或过滤。
3. 测试双重编码：`http://user%2523@allowed-host/` 返回连接 `user` 一类错误，证明客户端把 `%2523` 解成了 `#`。
4. 构造 `http://127.0.0.1:<port>%2523@allowed-host/<internal-path>` 访问本地管理接口；如路径关键字也被过滤，再对路径字符做双重编码（如 `%25%36%31dmin`）。
5. 通过响应确认已到达内网/本地服务，再调用其管理接口（原文最终删除用户成功）。

## PoC

```text
# 白名单校验通过、实际连接 127.0.0.1:80
http://127.0.0.1:80%2523@stock.weliketoshop.net/admin

# 路径关键字 /admin 被黑名单时，对字符做双重编码
http://127.0.0.1/%25%36%31dmin
```

说明：原文在带白名单过滤的 SSRF 实验环境中按上述递进验证，最终通过 `localhost:80%2523@.../admin/delete?username=carlos` 完成删除操作；本卡未复现。

## 变体与关联

- [[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]：`trusted@evil.com` 型 userinfo 混淆；本卡反向利用——真实 host 在前、允许域名放进被截断的片段。
- [[web-generic-ssrf-url-parser-differential-allowlist-bypass]]：校验端与执行端解析器不同的通用形态。
- [[web-generic-ssrf-multi-layer-decode-dword-waf-bypass]]：多层解码错位用于 IP 表示的同类思路。
- [[web-generic-ssrf-redirect-chain-meta-refresh-error-body]]：重定向绕过白名单的另一种路径。
- 变体：`#` 可换成 `?`/`;` 等解析差异字符；双重编码可用于 host、path、query 任意位置；存在同站开放重定向时也可用 `allowed-host/redirect?url=http://127.0.0.1/...` 让客户端跟随跳转。
- 边界：校验器与客户端用同一解析器且只解码一次、禁止 fragment/userinfo、解析后按 IP 段校验、每跳重定向重新校验时失效。

## 检测与防御

- 解析后再比较：对 URL 完整解码一次后解析，只比较规范化 hostname（拒绝 userinfo、fragment、非标准端口），不要做字符串包含/前缀匹配。
- 统一解码层级：校验与执行使用同一解析库、同一解码次数；禁止二次解码。
- 网络侧：DNS 解析结果再做私网/环回/链路本地 IP 校验；重定向每跳重新校验。
- 检测：URL 参数中出现 `%2523`、`%25` 开头的双重编码、`@` 与白名单域名同现、fragment 中含域名；同一参数高频尝试编码变体。
- 防御：SSRF 代理只允许 http/https、固定端口与解析后的白名单 IP；对路径做规范化后再匹配规则。
