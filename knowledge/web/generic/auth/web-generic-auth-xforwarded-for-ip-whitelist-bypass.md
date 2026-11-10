---
id: web-generic-auth-xforwarded-for-ip-whitelist-bypass
title: 服务端信任 X-Forwarded-For 做 IP 白名单校验时伪造请求头绕过登录限制
type: scenario
domain: web
path: web/generic/auth
technique: xff-ip-trust-bypass
aliases:
- XFF 伪造 IP 绕过
- 信任代理头 IP 鉴权绕过
tags:
- xff
- ip-whitelist
- auth-bypass
- header-forgery
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-33
  verified_at: '2026-11-08T17:02:52+08:00'
  notes: 已对照原文核对：源码HTTP_X_FORWARDED_FOR==2.2.2.1白名单判断（img01）、插件伪造XFF登录成功返回flag{9u60w1kemajt}（img02）证据齐全
---

## 一句话结论

后端用 `$_SERVER["HTTP_X_FORWARDED_FOR"]` 与固定 IP 比对实现"仅内网/指定 IP 可登录"时，攻击者用插件或 Burp 直接伪造 X-Forwarded-For 头为白名单值即可通过校验登录并获取 flag。

## 原理

HTTP_X_FORWARDED_FOR 是客户端完全可控的请求头，只有位于可信反向代理之后并由代理覆盖该头时它才可信。代码直接取该头与白名单 IP（如 2.2.2.1）做相等判断，等于把鉴权依据放在攻击者手里；伪造该头即绕过 IP 限制。

## 触发条件

- 服务端以 X-Forwarded-For（或 X-Real-IP、X-Originating-IP 等同类头）作为鉴权/白名单依据；
- 攻击者可直接访问该应用（前置代理未覆盖或未过滤该头）。

## 利用步骤

1. 查看页面源码/报错确认存在 IP 校验逻辑及白名单值；
2. 用浏览器插件（如 Header Editor）或 Burp 添加请求头 `X-Forwarded-For: 2.2.2.1`；
3. 任意输入用户名密码提交登录，返回登录成功与 flag（原文实测 flag{9u60w1kemajt}）。

## PoC

```
POST / HTTP/1.1
Host: target
X-Forwarded-For: 2.2.2.1
Content-Type: application/x-www-form-urlencoded

username=a&password=b
```

## 变体与关联

- 常见同类头：X-Real-IP、X-Originating-IP、X-Remote-Addr、Client-IP，逐个尝试；
- 与限流绕过场景（每次改 XFF 绕过频率限制）共享同一根因：信任伪造头；
- 源码注释/报错中常直接暴露白名单 IP 值。

## 检测与防御

- 检测：同一会话/短时间内 XFF 频繁变化；业务未部署在代理后却出现 XFF 头。
- 防御：鉴权用 TCP 对端地址 `$_SERVER['REMOTE_ADDR']`；必须在代理链上统一覆盖并剥离客户端伪造的 XFF。
