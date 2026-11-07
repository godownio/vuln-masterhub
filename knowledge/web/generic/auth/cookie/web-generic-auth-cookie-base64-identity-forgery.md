---
id: web-generic-auth-cookie-base64-identity-forgery
title: Base64 Cookie 身份伪造导致未授权文件上传
type: scenario
domain: web
path: web/generic/auth/cookie
technique: cookie-identity-forgery
aliases:
- Cookie 身份伪造
- Base64 Cookie 伪造
- 未授权上传
tags:
- web
- auth
- cookie
- session
- file-upload
- identity-forgery
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
---

## 一句话结论

当服务端把 Cookie 里的用户标识只做 Base64 解码、不做签名或服务端比对时，攻击者可以伪造任意用户 ID，冒充管理员进入上传等敏感功能。

## 原理

系统从 Cookie 读取“站点用户标识”，仅做 Base64 解码后写入会话。Base64 是编码不是加密，客户端可以任意解码、篡改、重新编码。服务端随后只用这个 ID 去用户表做“存在且有效”校验，而 ID 本身由攻击者提供；管理员账号通常随系统初始化创建，填 `1` 之类的 ID 必然通过。校验通过后，后续鉴权把请求当成已登录管理员，未登录拦截被跳过。

## 触发条件

- 身份标识放在客户端可读写的 Cookie/Header 中；
- 仅做编码/序列化，没有签名、加密或服务端会话绑定；
- 用户存在性校验以客户端提供的 ID 为准；
- 敏感功能只检查“是否登录”，不校验角色/归属。

## 利用步骤

1. 观察登录后的 Cookie 结构，确认是否为可解码的明文/序列化数据；
2. 解码后定位用户 ID 字段，改成管理员 ID（常见为 1）；
3. 重新编码并替换 Cookie；
4. 访问需要登录的上传/管理接口，确认返回已登录状态；
5. 结合上传等缺陷完成后续利用。

## PoC

```text
Cookie: user=<base64({"uid":1,"name":"admin"})>
# 服务端仅 base64_decode 后写入会话，未验签
```

## 变体与关联

- 变体：明文 Cookie、可预测 Session ID、JWT 未验签/算法混淆；
- 关联：默认口令、未授权文件上传、权限校验缺失。

## 检测与防御

- 检测：Cookie 中可解码的身份字段、异常用户 ID 切换、无登录记录的敏感操作；
- 防御：服务端会话、Cookie 签名/加密、不要信任客户端身份字段、敏感操作二次鉴权。
