---
id: ctf-web-bot-urlblocklist-backslash-path-encoded-param-bypass
title: Puppeteer bot 的 URLBlocklist 黑名单绕过：反斜杠改写路由 + URL 编码参数名，让带管理员 cookie 的 bot 访问本应被拦的 /giveflag?token=
type: scenario
domain: ctf
path: ctf/web
technique: bot-urlblocklist-backslash-path-param-encoding-bypass
tags:
- ctf
- web
- bot
- puppeteer
- url-blocklist
- filter-bypass
- backslash
- url-encoding
- cookie
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:27:29+08:00'
  notes: 已对照原文核对：bot.js 的 URLBlocklist 配置( */giveflag、*?token=* )、必须以 localhost:1337 开头、反斜杠路由 + %74%6f%6b%65%6e 参数名绕过、nc 输出 Loading page/timeout、再用同一 token 打 /redeem 换 flag 均与原文及截图一致；卡内靶场域名/token 已替换为占位符，无 sources/source_url。未验证点：原文本环境实测，反斜杠归一化依赖服务端行为。
url: /docs/ctf/web/ctf-web-bot-urlblocklist-backslash-path-encoded-param-bypass/
draft: false
kb_aliases:
- URLBlocklist 绕过
- bot 黑名单绕过
- 反斜杠绕过路由限制
- token 参数名百分号编码
- 追加无关参数让 token 不再紧跟问号
- giveflag token 置 true
---

## 一句话结论

bot 侧用 `URLBlocklist` 形式黑名单（如 `*/giveflag`、`*?token=*`）限制访问路径与参数时，黑名单只做字符串匹配，而浏览器/服务端会对路径和查询串做归一化：把路径写成 `\giveflag`（反斜杠被服务器当作 `/` 处理）即可绕开 `*/giveflag`，把参数名写成 `%74%6f%6b%65%6e`（即 `token`）即可绕开 `*?token=*`，于是带管理员 cookie 的 bot 仍然访问到了 `/giveflag?token=...`，把该 token 标记为可用。

## 原理

- **黑名单是字面量匹配**：`{"URLBlocklist": ["*/giveflag", "*?token=*"]}` 由浏览器策略层对 URL 字符串做通配匹配，它不理解「同一路径的等价写法」，也不做解码后匹配。
- **路径等价写法**：多数 Web 服务器（IIS/部分框架/反向代理）会把反斜杠归一化为正斜杠，因此 `https://host/\giveflag` 与 `https://host/giveflag` 落到同一路由；而字符串里不含 `*/giveflag` 这个连续片段（中间是 `\`），通配规则不命中。
- **参数名等价写法**：查询串里的参数名可以百分号编码（`%74%6f%6b%65%6e` = `token`），服务端解码后仍是同名参数；黑名单里的 `*?token=*` 匹配不到编码后的字面量。追加无关参数（`?a=b&token=11`）也能让「`?` 后紧跟 `token=`」的字面规则失效。
- **为什么危害成立**：bot 用管理员 cookie 启动浏览器，只要请求真正到达 `/giveflag` 且携带合法 token 参数，服务端就把 `valid_tokens[token] = True`；随后攻击者用同一 token 调 `/redeem` 即可取 flag。黑名单被绕过 = 权限检查被绕过。

## 触发条件

- 存在一个会用管理员/高权 cookie 访问攻击者提交 URL 的 bot（Puppeteer 等），且只允许访问同源地址（如必须以 `http://localhost:1337/` 开头）。
- bot 的策略/代理层用字符串黑名单限制路径或参数（`URLBlocklist` 一类配置）。
- 目标服务端会把反斜杠归一化为 `/`，且查询串参数名可被百分号编码后正常解析。
- 攻击者能拿到一个未被置为 true 的 token（如通过 `/token` 接口）。

## 利用步骤

1. 先申请 token：访问 `/token` 得到随机 token（此时 `valid_tokens[token] = false`）。
2. 观察 bot 的黑名单与允许前缀（本场景 `http://localhost:1337/` 或 `https://.../`）。
3. 构造绕过 URL：路径用反斜杠（`https://host/\giveflag`），参数名改成编码形式（`%74%6f%6b%65%6e=`），或追加无关参数让 `?token=` 不再紧跟 `?`。
4. 把该 URL 提交给 bot 的 nc 端口，等其加载完成（本场景输出 `Loading page ...` 后 `timeout`）。
5. 在本地用同一 token 提交 `/redeem`，服务端返回 flag。
6. 若反斜杠被拒，换 `%2f` 编码路径，或多加一个参数（`?a=b&token=<token>`）。

## PoC

```text
# 1) 申请 token
GET /token            -> 401ad1xxxxxxxxxxxxxxxxxxxxxxxxxxdf

# 2) 提交给 bot（反斜杠改写路由 + 参数名百分号编码）
https://<target>/\giveflag?%74%6f%6b%65%6e=401ad1xxxxxxxxxxxxxxxxxxxxxxxxxxdf

# 3) bot 输出
== proof-of-work: disabled ==
Please send me a URL to open.
Loading page https://<target>/\giveflag?%74%6f%6b%65%6e=401ad1xxxxxxxxxxxxxxxxxxxxxxxxxxdf.
timeout

# 4) 用该 token 兑换
POST /redeem
token=401ad1xxxxxxxxxxxxxxxxxxxxxxxxxxdf   -> <flag>
```

PoC 未在本机执行；域名与 token 已替换为占位符，仅示意格式。

## 变体与关联

- **路径变体**：`\`、`%2f`、`//`、`/%2e/`、大小写、加尾随点/分号；取决于服务器归一化行为。
- **参数变体**：参数名百分号编码、追加无关参数、把 token 放到不同位置（`;`、`&`、POST body）以避开「`?token=`」字面规则。
- **更强做法**：若 bot 用同源校验加前缀匹配，可用重定向/`#` 片段/用户信息段（`https://host@evil`）等解析差异；也可用 URL 短链接让字符串前缀仍满足白名单。
- **关联**：[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（同一「解析差异绕白名单」原理，落点是 SSRF）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（同为「黑名单字面匹配 vs 解码后语义」）、[[ctf-web-bot-jku-csp-crlf-cookie-hijack-chain]]（另一条 bot + 管理员会话的链）。
- **边界**：bot 策略层若在归一化/解码后再做匹配（或直接白名单路由），本绕过无效；服务端不把 `\` 当 `/` 时路径变体失效；token 必须来自同一服务且未被消费。

## 检测与防御

- **策略侧**：bot 的黑名单应在 URL 归一化（解码 + 路径规范化）之后按「host + 规范化 path + 参数键」做结构化校验，而不是字符串通配；更稳的是路由白名单。
- **服务端**：`/giveflag` 这类状态变更接口不应依赖 cookie 即可信，应要求一次性 CSRF token 或 bot 侧签名；对同一 token 的状态变更做幂等校验。
- **检测信号**：访问日志中出现含 `\`、`%2f`、编码参数名（`%74%6f%6b%65%6e`）的请求；同一 IP 先 `/token` 再提交给 bot 再 `/redeem` 的固定三段式节奏。
- **加固**：将 bot 会话与「可被外部触发的状态变更」隔离（bot 只读），需要写操作时由 bot 内部逻辑直接完成而非接受外部 URL 驱动。
