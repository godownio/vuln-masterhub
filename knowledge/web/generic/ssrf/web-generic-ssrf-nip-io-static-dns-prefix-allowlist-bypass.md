---
id: web-generic-ssrf-nip-io-static-dns-prefix-allowlist-bypass
title: 静态 DNS 解析 nip.io 绕过仅前缀/包含式域名白名单：<可信前缀>.<IP>.nip.io 通过校验却解析到任意（内网）IP
type: scenario
domain: web
path: web/generic/ssrf
technique: wildcard-dns-prefix-allowlist-bypass
aliases:
- nip.io 绕过
- 静态 DNS 解析绕过
- 通配 DNS 域名白名单绕过
- trusted.com.127.0.0.1.nip.io
- 前缀域名校验绕过
- 过滤特殊字符后的白名单绕过
tags:
- web
- ssrf
- url-validation
- allowlist-bypass
- dns
- nip.io
- wildcard-dns
- open-redirect
- cors
- postmessage
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-8
  verified_at: '2026-11-08T01:07:24+08:00'
  notes: 已对照原文核对 PoC 打通边界：nip.io 绕过前缀白名单的原语有实测证据（图01 正则前缀匹配、图03/04 ping 127.0.0.1.nip.io 与 www.baidu.com.127.0.0.1.nip.io 均解析到 127.0.0.1、图08 构造域名通过服务域名前缀校验回到登录页、Java 校验器返回 true），卡片结论克制到绕过白名单，与证据一致，未把半链包装成 SSRF 打内网或 RCE/ATO 攻击面。端到端 SSRF（redis.192.168.1.1.nip.io、169.254.169.254 云元数据）仅为构造示例，原文与 12 张图均无回显证据，卡片已明确自承不含可直接回显数据的端到端 PoC 并标 confidence medium、severity medium，未夸大。实战案例中 URL 跳转（图11 baidu.com 带 ticket=ST）与 CAS ticket 截获（图13 Apache access.log ST-755166）打通，但用截获票据接管受害者账号明确失败（图14 TicketValidationException 未能够识别出目标票根），skipped 已正确排除该 ATO 半链未写卡。dedup_review 成立：3 个 related（dns-rebinding 两次解析、userinfo @、CNAME 内网拓扑）与最相近子域名前缀卡均非同一利用链，duplicate 为卡片自匹配。affected_versions=null 合理（通用技巧无受影响版本区间），路径 web/generic/ssrf 合法。未验证点：nip.io 端到端打内网/云元数据 SSRF 与 302 组合变体原文未复现。
---

## 一句话结论

当 URL 校验只做"是否以可信域名开头 / 是否包含可信域名"的字符串匹配（`^https?://trusted\.com.*`、`re.search(r'trusted\.com', url)`），并且过滤了 `@`、`?`、`#` 等可用于域名混淆的特殊字符时，仍可用静态 DNS 服务 nip.io 构造 `https://trusted.com.127.0.0.1.nip.io`：字符串前缀是 `trusted.com` 能通过校验，但 DNS 会把该域名解析到 `127.0.0.1`（或任意指定 IP），从而把 URL 跳转、CORS Origin、PostMessage origin、SSRF 的目标指向攻击者选定地址。

## 原理

- **校验对象与连接对象不一致**：只做字符串前缀/子串匹配的正则检查的是 URL 字面量开头，而实际网络请求走的是 DNS 解析后的 IP。只要能让"看起来以 trusted.com 开头"的主机名解析到别的地址，就能绕过。`trusted.com.attacker.com`、`trusted.com@evil.com` 同理，但前者要自己注册并配置 DNS、后者依赖 `@` 等特殊字符。
- **nip.io 的通配解析规则**：nip.io 把 `<anything>.<IP>.nip.io` 解析为 `<IP>`，也支持 `app-127-0-0-1.nip.io`（短横）、`0xC0A80101.nip.io`（十六进制）、`3232235777.nip.io`（十进制）等格式。关键是 `<anything>` 段可以是任意前缀，因此 `trusted.com.127.0.0.1.nip.io` 与 `www.baidu.com.127.0.0.1.nip.io` 都解析到 `127.0.0.1`（命令行 ping 实测）。把 `<IP>` 换成 `192.168.1.1`、`169.254.169.254` 即可指向内网/云元数据。
- **为什么能补上被过滤的特殊字符**：`https://trusted.com@hacker.com` 用 userinfo 绕过前缀校验需要 `@`；`https://trusted.com.hacker.com` 需要自己配域名解析。nip.io 域名只含字母、数字、点、短横，不使用 `@ ? #`，因此在"过滤一切特殊字符、仅前缀域名校验"的严格规则下仍合法且通过前缀匹配，却由第三方 DNS 服务把请求落到任意 IP——这是它相对子域名/特殊字符绕过的独特价值。
- **危害边界（不夸大）**：该技巧本身是"绕过白名单校验"的完整可用原语，DNS 解析行为确定；但能否形成 SSRF/CORS 数据窃取还取决于目标是否解析外部 DNS、是否跟随跳转、是否放行到该 IP 的出站流量。本文案例中只验证到构造域名通过服务域名前缀校验、命令行确认解析结果，未给出 nip.io 全链打内网的端到端回显，故 confidence 标 medium。

## 触发条件

- 目标用字符串前缀/子串匹配校验 URL、Origin 或 event.origin（如 `matches("^https?://trusted\\.com.*")`、`url.contains("trusted.com")`、`startsWith("https://trusted.com")`），而非解析出真实 host 后精确比对注册域名。
- 过滤/禁用了 `@`、`?`、`#`、反斜杠等可用于域名混淆的特殊字符，使常规 userinfo 绕过失效。
- 目标运行环境能解析外部 DNS（能访问 `*.nip.io`），且请求逻辑使用解析后的 IP 建立连接。
- 对 SSRF 场景：目标未对解析后的 IP 做二次内网/回环地址校验，也未限制出站目标。

## 利用步骤

1. 探测校验方式：把可信域名放到末尾（`http://evil.com?trusted.com`、`http://evil.com/trusted.com`、`http://evil.com.trusted.com`）看是否仍通过，判断是前缀还是后缀/包含校验；再试 `http://trusted.com@evil.com` 看特殊字符是否被过滤。
2. 确认为"仅前缀/包含匹配 + 特殊字符被过滤"后，选定要解析到的目标 IP（如 `127.0.0.1`、内网段、`169.254.169.254`），构造 `<可信前缀>.<IP>.nip.io`。
3. 用 `ping <可信前缀>.<IP>.nip.io` 确认解析结果指向目标 IP（文章实测 `www.baidu.com.127.0.0.1.nip.io` → 127.0.0.1）。
4. 按场景把构造域名填入：URL 跳转的 `service`/`redirect` 参数、CORS 的 `Origin` 头、PostMessage 的 `iframe.src` 与 `targetOrigin`、SSRF 的 URL 参数。
5. 触发请求：URL 跳转/CORS/PostMessage 观察是否跳到/信任攻击者地址；SSRF 观察是否访问到内网服务或云元数据。必要时组合 302 重定向（`http://<可信前缀>.1.2.3.4.nip.io/redirect` 返回 `Location: http://192.168.1.1/admin`）。

## PoC

最小化（Java 校验器 + 构造域名，演示"通过校验"与"解析到内网"的错位）：

```java
boolean isTrusted(String url) {
    return url.matches("^https?://trusted\\.com.*");
}

// 通过校验（返回 true），但 DNS 解析到 127.0.0.1 / 192.168.1.1
isTrusted("https://trusted.com.127.0.0.1.nip.io");      // true
isTrusted("http://redis.192.168.1.1.nip.io:6379");       // true，SSRF 指向内网 Redis
```

命令行确认解析：

```text
ping 127.0.0.1.nip.io                 -> 127.0.0.1
ping www.baidu.com.127.0.0.1.nip.io   -> 127.0.0.1
ping app-192-168-1-250.nip.io         -> 192.168.1.250
```

各场景构造示例：

```text
URL 跳转:  https://trusted.com.1.2.3.4.nip.io
CORS:      Origin: https://trusted.com.192.168.1.1.nip.io
PostMsg:   iframe.src = 'http://trusted.com.1.2.3.4.nip.io'
SSRF:      http://redis.192.168.1.1.nip.io:6379
           或 http://trusted.com.169.254.169.254.nip.io/latest/meta-data/
```

注意：这是"绕过校验"的最小化片段，不含可直接回显数据的端到端 PoC；真实利用需目标确实按解析后 IP 发起请求。

## 变体与关联

- **同类绕过（载体不同）**：`trusted.com.attacker.com` 子域名绕过（需自配 DNS、只能指向自己域名）、`trusted.com@evil.com` userinfo 绕过（需 `@`）、Nginx 把 `/trusted.com` 配为反向代理目录（针对后缀/包含校验）。nip.io 的独特之处是无特殊字符、无需自配 DNS、可直接指向任意 IP（含内网/回环）。
- **IP 编码变体**：nip.io 支持点分十进制 `192.168.1.1.nip.io`、短横 `192-168-1-1.nip.io`、十六进制 `0xC0A80101.nip.io`、十进制 `3232235777.nip.io`；与 SSRF 的八进制/十六进制/十进制/DWORD IP 表示绕过同属"字符串与真实地址语义差"。
- **组合 302**：把 nip.io 域名作为通过白名单的首跳，服务端返回 302 到内网地址，绕过只校验初始 URL 的实现。
- **局限**：部分企业网络拦截 `*.nip.io`；目标需支持 Host 头覆盖；HTTPS 下 nip.io 无匹配证书，需自签名/忽略证书校验；依赖外部 DNS 可用性。
- **关联**：[[web-generic-ssrf-hostname-subdomain-prefix-allowlist-bypass]]（子域名前缀绕过）、[[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]（userinfo 前缀绕过）、[[web-generic-ssrf-multi-layer-decode-dword-waf-bypass]]（nip.io 被拦截后改用 DWORD 编码）、[[web-generic-ssrf-ip-notation-blacklist-bypass]]（等价 IP 表示）。
- **实战案例边界**：某高校统一身份认证（WebVPN + CAS）的 `service` 参数用前缀域名校验，构造 `http://已注册service域名.nip.io/test/` 可通过校验（图中登录页正常）；但该案例最终用 `@` userinfo 版本验证跳转，且后续"用截获票据接管账号"的尝试明确失败，不属于本卡结论范围。

## 检测与防御

- **不要用字符串前缀/子串匹配做域名白名单**：解析 URL 取 `host`（去除 userinfo、端口），与注册域名做精确相等或严格的子域归属校验（如 `host == "trusted.com" || host.endsWith(".trusted.com")`），并注意 `endsWith` 仍需前面补点。
- **禁用/规范化 userinfo**：拒绝 URL 中带 `@` 的 userinfo 段，统一做 URL canonicalization 后再比对。
- **解析后二次校验**：对 SSRF，DNS 解析得到 IP 后再次校验是否为回环/私网/保留地址/云元数据地址，并校验重定向每一跳（防 nip.io + 302 组合）；限制出站目标与协议（禁 file/gopher/dict）。
- **DNS 层**：出站 DNS 拦截已知通配 DNS 服务（`*.nip.io`、`*.sslip.io` 等），或只允许内网 DNS 解析到受控域名。
- **CORS/PostMessage**：CORS 用精确 Origin 白名单、避免 `*` 与前缀匹配；PostMessage 用 `event.origin` 精确比对并校验 `event.source`，不要 `endsWith("trusted.com")`。
- **检测**：监控请求/Origin 中出现 `nip.io`、`sslip.io` 等通配 DNS 域名，以及主机名前缀为可信域名但解析到内网/回环 IP 的请求；对 `service`/`redirect` 类参数做白名单审计。
