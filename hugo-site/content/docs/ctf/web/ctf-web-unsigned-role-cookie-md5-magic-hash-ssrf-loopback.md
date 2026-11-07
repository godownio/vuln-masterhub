---
id: ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback
title: 未签名角色 Cookie + PHP md5 魔术哈希双人复核 + loopback 预览 SSRF 读内网 flag
type: scenario
domain: ctf
path: ctf/web
technique: unsigned-role-cookie-md5-magic-hash-ssrf-loopback
tags:
- ctf
- web
- cookie
- auth-bypass
- php
- magic-hash
- ssrf
- loopback
- md5
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:22:46+08:00'
  notes: 已对照原文核对：mail_user/mail_role 未签名 Cookie 改 admin、download.php 泄露 preview-readme/route-index、240610708/QNKCDZO 过双人复核、target_url 127.0.0.1/internal/report?view=flag&slot=last 回显 ISCC{ACxmCnWgL3C7LqWImKfgtK6h}，均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/web/ctf-web-unsigned-role-cookie-md5-magic-hash-ssrf-loopback/
draft: false
kb_aliases:
- mail_role=admin
- 未签名 Cookie 提权
- 240610708 QNKCDZO
- md5 弱比较
- 本机预览 SSRF
- 127.0.0.1/internal/report
- 值班邮件台
---

## 一句话结论

服务端直接信任未签名的 `mail_role` Cookie，把 `user` 改成 `admin` 即进后台；后台预览要求两份“不同”凭据但用 PHP `md5($a) == md5($b)` 弱比较，`240610708` 与 `QNKCDZO` 的 MD5 都以 `0e` 开头可绕过；`target_url` 指向 `http://127.0.0.1/internal/report?view=flag&slot=last`，预览器以管理员视角从本机取回 flag。

## 原理

- **未签名角色 Cookie**：`mail_user`/`mail_role` 直接放在浏览器 Cookie 中，服务端不校验签名、不与服务端会话绑定；`mail_role=admin` 即被当作管理员。
- **PHP 魔术哈希**：`md5("240610708") = "0e462097431906509019562988736854"`、`md5("QNKCDZO") = "0e830400451993494058024219903391"`，两者经 `==` 比较时都被解析为 `0 × 10^n = 0`，因此 `md5($a) == md5($b)` 为真；而字符串本身不同，满足“两份凭据不能完全相同”的前置校验。
- **loopback SSRF**：后台预览器接受完整 URL 并发起请求；`127.0.0.1` 从服务端本机访问，绕过“仅内网开放”的限制，`/internal/report?view=flag` 返回 flag。
- **表单编码坑**：`target_url` 中的 `&slot=last` 如果直接拼在 `-d` 里会被外层表单拆成独立字段，必须整体 URL 编码（`--data-urlencode` 或 `requests` 的 `data=`）。

## 触发条件

- 角色/用户信息放在未签名 Cookie 中，服务端直接信任。
- 后台存在“双人复核/双凭据”逻辑，用 PHP 松散比较比较 MD5/SHA1 等摘要。
- 后台有 URL 预览/抓取功能，允许访问 loopback 或内网地址。
- 内部报告接口只允许本机访问，且回显 flag。

## 利用步骤

1. 访问首页，确认 Cookie 中的 `mail_user`/`mail_role` 与 `/admin.php` 入口；把 `mail_role` 改为 `admin`，确认 403 变 200。
2. 通过公开的 `download.php` 读取 `preview-readme.txt`、`route-index.txt`，拿到内部诊断别名（如 `final` 对应 `/internal/report`）。
3. 构造双凭据 `token_a=240610708`、`token_b=QNKCDZO`，满足 `md5($a)==md5($b)` 且两者不同。
4. 设置 `target_url=http://127.0.0.1/internal/report?view=flag&slot=last`，用 URL 编码整体提交，避免 `&` 被拆字段。
5. 从响应结果区正则提取 `ISCC{...}`；若预览器有协议/域名白名单，尝试 `localhost`、`[::1]`、十进制 IP、`127.1` 等变体。

## PoC

```python
import re, requests

s = requests.Session()
s.cookies.set("mail_user", "guest")
s.cookies.set("mail_role", "admin")

r = s.post("http://target:49103/admin.php", data={
    "token_a": "240610708",
    "token_b": "QNKCDZO",
    "target_url": "http://127.0.0.1/internal/report?view=flag&slot=last",
}, timeout=10)
print(re.search(r"(ISCC\{[^<\s]+\})", r.text).group(1))
```

## 变体与关联

- **Cookie 变体**：Base64/JSON 编码的角色字段、`role=admin` 放在 JWT 无签名段、`is_admin=1` 客户端可控。
- **魔术哈希变体**：`md5`/`sha1` 的 `0e` 碰撞值很多（`240610708`/`QNKCDZO`、`aabg7XSs`/`aabC9RqS` 等）；也可用数组参数让 `md5()` 返回 null 绕过；PHP 8 下 `0 == "foo"` 行为变化，但两个 `0e` 数字串仍相等。
- **SSRF 变体**：`127.0.0.1`、`localhost`、`[::1]`、`0.0.0.0`、十进制/八进制 IP、DNS rebinding、URL 解析差异（`http://127.0.0.1@evil`）。
- **关联卡片**：[[web-generic-auth-php-loose-comparison-token-0e-bypass]]（PHP 0e 松散比较）、[[web-generic-auth-cookie-base64-identity-forgery]]（Cookie 身份伪造）、[[web-generic-ssrf-fe-proxyservletutil-url-echo]]（SSRF 回显）。
- **边界**：若 Cookie 有 HMAC 签名、摘要用 `hash_equals`/`===` 严格比较、预览器禁用 loopback，本链不成立。

## 检测与防御

- **CTF 验证**：先确认改 Cookie 能进后台，再确认双凭据能通过复核，最后确认 `target_url` 回显内网 flag。
- **修复**：角色/身份放服务端会话或签名 Cookie；摘要比较用 `hash_equals` 且不要用 `==`；双人复核应比较完整凭据而非摘要；预览器做 URL 白名单、禁 loopback/内网地址、限制协议。
- **检测信号**：Cookie 中出现 `role=admin`/`is_admin=1`；`token_a`/`token_b` 为已知 0e 碰撞值；预览请求目标为 `127.0.0.1`/`localhost`/内网段。
