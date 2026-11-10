---
id: web-generic-auth-rasp-console-login-bruteforce-rate-limit-gap
title: watchbird 控制台密码验证不在自身防 DDoS 覆盖内：可无限爆破，响应长度区分正确口令
type: scenario
domain: web
path: web/generic/auth
technique: rasp-console-auth-bruteforce-rate-limit-gap
tags:
- web
- auth
- bruteforce
- rate-limit
- waf
- rasp
- awd
- watchbird
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:15:40+08:00'
  notes: 已对照原文与图01-03核对：watchbird=ui 登录分支先于防 DDoS、失败响应约1955字节/成功约42789字节/防DDoS logo约312字节、原文口令123456 爆破成功均一致；该卡为进入后台的前置手法，与配置写入 RCE 卡关联。原文未给版本号，affected_versions 留空。未复现
url: /docs/web/generic/auth/web-generic-auth-rasp-console-login-bruteforce-rate-limit-gap/
draft: false
kb_aliases:
- watchbird 后台爆破
- RASP 控制台无限爆破
- WAF 自身登录不限速
- 防 DDoS 不覆盖密码验证
- 响应长度判断爆破成功
---

## 一句话结论

watchbird 的防 DDoS 逻辑只在其保护正常站点请求的路径上生效，而控制台密码验证分支（`?watchbird=ui&passwd=...`）在此之前完成，不经过计数/封锁逻辑；攻击者因此可以对控制台口令做不限次数的爆破，并用响应长度差异（登录成功页约 42KB，登录页约 2KB）判断正确的弱口令。

## 原理

- **RASP/WAF 的防护面与自身管理面不同**：watchbird 作为 PHP 运行时防护，防 DDoS 等检查是在处理被保护站点请求的流程里执行的；控制台初始化、登录、配置等分支是同一入口文件中的独立 `watchbird=` 分支，先做 `session_start()` 和口令哈希比较，未进入防 DDoS 计数。
- **表现出来的差异**：频繁访问普通站点会触发防 DDoS，返回一个 watchbird logo 页面（约 312 字节、ASCII art），不返回正常内容；但对控制台持续发送密码尝试不会出现该页面，也不会被封锁。
- **成功 oracle**：控制台登录页/失败响应长度稳定（原文约 1955 字节）；登录成功后返回完整控制台页面（原文约 42789 字节）。爆破时只需按响应长度排序即可找出正确口令（原文口令为 `123456`，响应长度 42789）。
- **为什么是完整危害链**：拿到后台会话后可继续利用 `watchbird=change` 的任意配置写入实现 RCE（见关联卡）；即使单独看，管理面口令无限爆破也意味着弱口令/默认口令环境下必然失守。
- **根因**：安全产品的“数据面防护”没有覆盖“控制面认证”，认证接口缺少独立的速率限制/账户锁定/验证码，且以可区分的响应长度暴露成功与否。

## 触发条件

- 目标部署 watchbird（原文测试版本在漏洞修复前；控制台路径如 `/watchbird/`），控制台可访问。
- 存在弱口令/可猜口令（原文 123456），或口令空间较小。
- 无外层（Nginx/WAF/网关）对控制台登录的额外限流、封禁或验证码；watchbird 自身的防 DDoS 不作用于该分支。
- 登录成功/失败的响应体长度或内容存在可区分差异。

## 利用步骤

1. 确认控制台入口：访问 `?watchbird=ui`，观察登录页/初始化密码页及正常响应长度。
2. 构造密码参数请求（原文用 Burp Intruder 对 `passwd` 做字典爆破），持续发送；观察不会出现防 DDoS logo 页或封锁。
3. 以响应长度为 oracle：失败约 1955 字节，成功约 42789 字节；按长度排序定位命中项。
4. 用命中口令登录，取得 `PHPSESSID` 会话，进入控制台。
5. 在后台继续利用配置修改接口（`watchbird=change`）写入 Web 根实现 RCE，或做配置篡改。
6. 记录爆破速率、响应长度差异与成功会话。

## PoC

```http
GET /watchbird/?watchbird=ui&passwd=123456 HTTP/1.1
Host: target
```

```text
# 失败尝试：响应约 1955 字节（登录页）
# 正确口令：响应约 42789 字节（控制台页面）
# 防 DDoS 触发时普通站点返回约 312 字节 logo 页；控制台爆破不触发
```

无完整脚本：原文用 Burp Intruder 手工配置字典爆破，未给出请求包全文；上例为按截图还原的请求形态。

## 变体与关联

- 变体：把密码尝试改为 POST、或带上已有 Cookie/会话，观察是否仍不计数；若外层有统一限流则以 IP 轮换/低速爆破应对。
- 变体：除长度外，可用状态码、Set-Cookie、页面标题（登录页 vs 控制台）作为成功 oracle。
- 关联：[[web-php-rce-watchbird-config-change-config-path-overwrite-webshell]]——拿到后台后的任意配置写入/RCE 链。
- 关联：[[web-generic-auth-astrbot-dashboard-weak-password]]、[[web-generic-auth-captcha-ocr-username-enum-bruteforce]]——同类管理面弱口令/无限爆破进入后台的场景。
- 边界：如果目标在 watchbird 前面还有一层 WAF/网关对 `/watchbird/` 登录做限流，或管理员使用强口令，本手法失效；登录成功页大小也随版本/主题变化，需现场校准 oracle。

## 检测与防御

- 检测：短时间内大量 `watchbird=ui` 且 `passwd` 变化的请求；响应长度在 1955/42789 两档间跳变；同一源 IP 高频访问控制台登录。
- 检测：登录成功后立即出现 `watchbird=change` 且 key 为 `config_path` 或含 `<?php` 的请求。
- 防御：在 Web 服务器/网关层对控制台登录做独立限流、账户锁定、验证码与告警，不依赖产品自身的防 DDoS。
- 防御：强制强口令、多因素认证；限制控制台访问来源（内网/白名单）；统一失败响应长度与时间，避免长度 oracle。
- 加固：升级 watchbird 到已修复版本，并审计其认证分支是否纳入统一防护流程。
