---
id: web-generic-ssrf-ip-notation-blacklist-bypass
title: 等价 IP 表示绕过 SSRF 字符串黑名单
type: scenario
domain: web
path: web/generic/ssrf
technique: ip-notation-blacklist-bypass
aliases:
- 十六进制 IP SSRF
- 十进制 IP 绕过
- 八进制 IP
- startsWith 绕过
- FastGPT SSRF
tags:
- ssrf
- blacklist
- ip-encoding
- url-parsing
- fastgpt
- nodejs
- metadata
cve:
- CVE-2026-42345
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: FastGPT v4.14.11 及更早版本
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:20:33+08:00'
  notes: 已对照原文与7张图核对：isDevEnv 短路、metadataEndpoints startsWith 黑名单、CHECK_INTERNAL_IP 默认 false、127.0.0.1 被拦截、0xa9.0xfe.0xa9.0xfe:8080 触发 ENETUNREACH 169.254.169.254:8080 均一致；未在真实云环境读取凭证。版本按原文写入 FastGPT v4.14.11 及更早
---

## 一句话结论

当 SSRF 防护用 `startsWith("http://169.254.169.254/")` 这类字符串黑名单判断时，把同一 IP 写成十进制、十六进制或八进制形式即可绕过；Node 的 URL/网络库仍会把它解析成真实元数据地址并发起连接。

## 原理

- IPv4 地址有多种等价数值写法：`169.254.169.254` 可写成十进制 `2852039166`、十六进制 `0xa9.0xfe.0xa9.0xfe`、八进制 `0251.0376.0251.0376`（以及各段混写）。
- WHATWG URL 的主机解析会把纯数字/`0x`/前导零形式按 IPv4 规则归一化成同一个 32 位地址。校验端做的是字符串前缀匹配，看到的只是 `http://0xa9...`，与黑名单字面量不相等，因此放行。
- 放行后，执行端（Node `fetch`/`axios`/socket）重新解析 URL，得到真实 IP `169.254.169.254`，连接真正发出。
- 本案还有两层放大器：开发环境判断 `isDevEnv` 直接 `return false` 跳过校验；底层 `CHECK_INTERNAL_IP` 兜底默认为 `false`，使 IP 级校验根本不执行。黑名单因此成为唯一防线。
- 同类问题不限于元数据地址：任何“字符串黑名单”与“真实网络地址”之间的语义鸿沟都可被利用，例如 DNS 解析到内网、URL 编码、userinfo 混淆、IPv6 映射地址。

## 触发条件

- 应用允许用户控制出站请求 URL（工作流 HTTP 节点、Webhook、URL 预览、模型/插件配置等）。
- 防护采用字符串黑名单或 `startsWith`/`includes` 匹配主机字面量。
- 底层 HTTP 客户端会按标准重新解析 URL，且服务器具备出站能力。
- 兜底的内网 IP 校验被默认关闭或未实现。

## 利用步骤

1. 确认目标功能会代用户发起 HTTP 请求，并先用标准内网地址验证拦截行为（对照组）。
2. 将目标地址改写为等价数值形式，例如把 `169.254.169.254` 写成 `0xa9.0xfe.0xa9.0xfe`。
3. 提交请求，观察返回：若错误信息出现 `connect ENETUNREACH 169.254.169.254:...` 或实际收到内网响应，说明黑名单被绕过。
4. 在真实云环境把目标换成元数据路径，读取临时凭证；或扫描回环/私网端口。
5. 若目标只拦 IPv4 字面量，继续尝试 DNS 解析到内网、IPv6 映射、重定向到内网等形态。

## PoC

```text
# 对照组：被应用层拦截
http://127.0.0.1:8080
# -> {"message":"Request to private network not allowed"}

# 十六进制等价形式：绕过 startsWith 黑名单
http://0xa9.0xfe.0xa9.0xfe:8080
# -> connect ENETUNREACH 169.254.169.254:8080

# 其他等价写法
http://2852039166/
http://0251.0376.0251.0376/
http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/
```

```javascript
// 漏洞形态：只做字符串前缀匹配
const blocked = ['http://169.254.169.254/', 'http://metadata.google.internal/']
if (blocked.some(p => fullUrl.startsWith(p))) return deny()
return fetch(fullUrl) // 0xa9.0xfe.0xa9.0xfe 会在这里被解析为 169.254.169.254
```

## 变体与关联

- 变体：混合进制（`0xa9.254.0xa9.254`）、省略段、前导零；不同运行时的接受程度需实测。
- 变体：DNS 重绑定——校验时域名解析到公网，连接时解析到内网；只在连接前做一次 DNS 校验仍会被绕过。
- 变体：302 重定向到内网、URL 编码/大小写/尾点域名等字符串层绕过。
- 关联：[[web-generic-ssrf-url-parser-differential-allowlist-bypass]] 讲的是解析器分歧；本卡讲的是同一 IP 的多种字面表示，两者都源于“字符串判断代替真实地址判断”。

## 检测与防御

- 检测：请求 URL 的主机部分出现纯数字、`0x` 前缀、前导零分段、超长十进制等异常形式。
- 检测：不能只告警 `URL CONTAINS "169.254.169.254"`；应基于 DNS 解析结果、连接五元组或 egress 日志中的真实目的 IP 判断，否则与漏洞代码犯同样的“字符串信任”错误。
- 修复：不要扩充黑名单；解析 URL 取 hostname，做 DNS 解析得到 IP，按网段判断回环、RFC 1918 私网、链路本地 `169.254.0.0/16`、IPv6 本地地址等。
- 修复：把“校验时的 IP”固定为“连接时的 IP”（自定义 `lookup`/连接钩子），防止 DNS 重绑定；禁止或逐跳校验重定向。
- 加固：生产环境强制开启内网 IP 兜底校验，开发环境短路逻辑不得带入生产；出站流量默认拒绝，仅放行必要目的地；云元数据使用 IMDSv2/最小权限。
- 测试：把十进制、十六进制、八进制、混合进制、DNS 重绑定、重定向等用例写成“必须拦截”的回归测试。
