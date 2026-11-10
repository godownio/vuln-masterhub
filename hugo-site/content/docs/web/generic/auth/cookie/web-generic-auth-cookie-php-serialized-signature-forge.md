---
id: web-generic-auth-cookie-php-serialized-signature-forge
title: 泄露的签名密钥可离线伪造 PHP 序列化认证 Cookie 越权访问开发者功能
type: scenario
domain: web
path: web/generic/auth/cookie
technique: php-serialize-cookie-signature-forge
tags:
- cookie
- authentication
- serialize
- md5
- signature-forge
- privilege-escalation
- key-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:09:09+08:00'
  notes: 已对照原文核对；图 12 源码注释的 unserialize+base64+md5(username+key) 公式与卡一致，越权访问开发者日志已打通；dedup_review 成立；重点判定：与 web-generic-auth-client-recomputable-signature-forge 分属不同题、不同 sink、不同载荷，互不在对方 dedup 候选内，非同一条利用链，不重复；未验证点：服务端校验细节依原文注释推断
url: /docs/web/generic/auth/cookie/web-generic-auth-cookie-php-serialized-signature-forge/
draft: false
kb_aliases:
- 序列化 cookie 伪造
- auth_token 伪造
- md5 签名绕过
- PHP 反序列化 cookie
---

## 一句话结论

当认证 Cookie 是客户端可见的 `base64(serialize(array))`、而校验只是 `md5(username + 硬编码key)` 时，一旦该 key 从源码注释或备份/隐藏文件中泄露，攻击者即可离线构造任意用户名的合法 Cookie，越权访问「仅限开发者」的功能。

## 原理

- 服务端用 `unserialize(base64_decode($_COOKIE['auth_token']))` 还原数组，再校验 `$data['hash'] === md5($data['username'] . $CONFIG['auth_key'])`。签名只覆盖「用户名 + 一个静态密钥」两个值，不含过期时间、随机数、会话 nonce 或服务端状态。
- 为什么可伪造：生成公式（`serialize` → `base64_encode`、`md5(concat)`）与密钥都能从泄露的源码注释、目录爆破得到的隐藏文件中拿到；两者都不含「只有服务端知道的秘密」，因此 Cookie 完全可以在客户端离线复算。这是「客户端可控结构 + 可复算签名 + 密钥泄露」叠加的身份伪造。
- 与 PHP 反序列化利用的区别：这里没有 POP 链、没有魔术方法、没有 gadget，纯粹是签名校验被绕过；危险来自信任了客户端提交的序列化对象，而非 `unserialize` 触发对象注入。
- 为什么能越权：高权限页面（如系统日志）只判断该 Cookie 是否通过签名校验，不查服务端会话表、不二次核对角色；于是伪造 `username=dev` 即可获得开发者视角。

## 触发条件

- 认证/授权状态以客户端可见的序列化 Cookie 承载；
- 签名密钥硬编码在源码、注释或可读文件里，或可通过目录/文件枚举获取；
- 校验为无服务端秘密的摘要（如 `md5(username+key)`），且不含时间戳/nonce；
- 高权限功能仅依赖该 Cookie 判定，无服务端会话绑定。

## 利用步骤

1. 用弱口令进入低权限账户，观察 Cookie 结构（本例另有 `role`/`username` 明文 Cookie，可直接改，但关键接口另要 `auth_token`）。
2. 目录/文件枚举或源码注释中找到泄露的 `username` 与 `auth_key`（本例为隐藏文本给出）。
3. 按公式生成 `base64_encode(serialize(['username'=>U,'hash'=>md5(U.KEY)]))`。
4. 用 Cookie 编辑工具写入 `auth_token`，请求受限页面，验证可访问。
5. 进入受限功能后再找该功能的输入点做进一步利用。

## PoC

```php
<?php
// 仅在授权环境验证；密钥来自泄露的源码/配置
$username = 'dev';
$auth_key = '<LEAKED_AUTH_KEY>';
$data = ['username' => $username, 'hash' => md5($username . $auth_key)];
echo base64_encode(serialize($data));   // 作为 auth_token Cookie 的值
```

## 变体与关联

- 变体：把 md5 换成 HMAC 但密钥仍随客户端分发；签名不含过期时间/nonce 导致可重放；`hash` 与 `username` 来自不同字段时的类型/比较绕过；明文 `role=admin` Cookie 直接篡改。
- 关联：弱口令、敏感文件/目录枚举、服务端密钥签名 oracle、命令注入（拿到开发者功能后的下一步）。

## 检测与防御

- 防御：Cookie 用不透明的服务端 session id，权限状态存服务端；必须自包含时用 HMAC-SHA256 + 服务端独有密钥 + 过期时间 + nonce，并保证密钥不进入源码/前端可见文件；对不可信数据禁用 `unserialize` 或强制 `allowed_classes => false`。
- 密钥管理：签名密钥从环境变量/密钥管理系统注入，禁止写入注释、备份、`.txt` 隐藏文件；清理仓库历史中的密钥。
- 检测：日志中出现对隐藏文件/敏感路径的枚举请求；同一 `auth_token` 长期重复、跨账户复用；`hash` 与用户名不匹配的成功请求。
