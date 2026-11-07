---
id: web-php-deserialization-session-s-hex-escape-admin-forge
title: PHP Session 反序列化 S 类型十六进制转义：把 admin 藏进 \61\64\6d\69\6e 绕过检测
type: scenario
domain: web
path: web/php/deserialization
technique: php-session-serialization-s-hex-escape
tags:
- php
- session
- deserialization
- s-hex
- serialize
- waf-bypass
- auth-bypass
- cookie
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T02:05:34+08:00'
  notes: 已对照原文「茉莉蜜茶」核对：登录后拿到 cookie，WAF 拦截明文 admin；payload O:12:"Session\User":1:{s:8:"username";S:5:"\61\64\6d\69\6e";} 用大写 S 的十六进制转义表示 admin（长度 5 为解码后字节数），与原文一致。未验证点：S 类型/转义支持与 PHP 版本、session 处理器相关，卡片已标 confidence=medium；未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/web/php/deserialization/web-php-deserialization-session-s-hex-escape-admin-forge/
draft: false
kb_aliases:
- PHP Session S 类型绕过
- session 反序列化十六进制转义
- S:5 十六进制 username
- PHP session 伪造 admin
- session_decode 转义字符串
---

## 一句话结论

当应用把客户端 Cookie 中的 PHP session 序列化串直接反序列化、且只靠 WAF/关键字检查拦截 `admin` 时，可把字符串类型写成 `S:5:"\61\64\6d\69\6e"`：检测器看到的是十六进制转义，PHP session 解码器却还原成 `admin`，从而伪造管理员会话。

## 原理

- PHP session 默认把 `$_SESSION` 序列化成 `key|serialized_value` 形式存入 Cookie/文件；对象形如 `O:12:"Session\User":1:{s:8:"username";s:5:"admin";}`。
- PHP 的 session 反序列化解析器在部分实现/版本中支持 `S` 类型（大写）字符串，并对字符串内容做转义/十六进制还原；`S:5:"\61\64\6d\69\6e"` 的长度 5 指解码后的 `admin`，而不是转义文本的字符数。
- WAF/关键字检测通常只匹配明文 `admin`、`s:5:"admin"` 或对象属性；十六进制转义形式 `\61\64\6d\69\6e` 不含连续 `admin` 字样，容易绕过。
- 反序列化后 `Session\User` 对象的 `username` 属性变为 `admin`，应用按会话身份放行管理员功能。
- 根因是“会话数据由客户端控制 + 无完整性签名 + 反序列化器接受多种等价编码”，而不是单一 WAF 规则缺失。

## 触发条件

- 应用使用 PHP session，且 session 数据存放在客户端 Cookie（或攻击者可篡改的存储）中，未做签名/HMAC。
- 服务端对 Cookie 做 session 反序列化，且 PHP 版本/会话处理器接受 `S` 类型或等价转义形式。
- 存在基于用户名的权限判断（如 `username == "admin"`），且 WAF/黑名单只做字符串匹配。
- 攻击者能拿到一个合法 session Cookie 作为模板（登录普通账号即可）。
- 目标未启用 `session.use_strict_mode`、未绑定 session 到服务端存储或未校验会话完整性。

## 利用步骤

1. 登录普通账号，抓取 Cookie 中的 session 值，确认序列化格式（`O:...`、`s:...`、base64/URL 编码层）。
2. 解码外层编码（URL decode/base64），定位 `username` 属性的字符串类型与长度。
3. 把 `s:5:"admin"` 替换为 `S:5:"\61\64\6d\69\6e"`（`\61\64\6d\69\6e` 即 `admin` 的十六进制转义）；保持对象类名、属性数与外层长度一致。
4. 重新做 URL/base64 编码，替换 Cookie，访问管理员接口/页面。
5. 若被拦截，尝试大小写 `S`/`s`、八进制 `\141\144\155\151\156`、混合转义、双重编码、在值中插入空字节等变体。
6. 成功后读取管理员数据或执行管理员操作。

## PoC

```text
原始 Cookie 片段：
O:12:"Session\User":1:{s:8:"username";s:5:"admin";}

替换为：
O:12:"Session\User":1:{s:8:"username";S:5:"\61\64\6d\69\6e";}
```

```python
from urllib.parse import quote

payload = r'O:12:"Session\User":1:{s:8:"username";S:5:"\61\64\6d\69\6e";}'
print(quote(payload, safe=""))
```

无真实目标 PoC：原文为 CTF 环境，类名/属性名与编码层需按实际 Cookie 调整；`S` 类型支持取决于 PHP 版本/会话处理器，使用前需在目标同版本验证。

## 变体与关联

- **转义形式**：十六进制 `\xNN`/`\NN`、八进制、`\uNNNN`、双重转义；不同解析器支持范围不同。
- **类型混淆**：`s` 与 `S`、长度字段与实际内容不一致、数组/对象嵌套、`__wakeup`/`__destruct` 触发 POP 链。
- **Cookie 层编码**：URL 编码、base64、JSON 包装、多重编码；WAF 只解一层时容易漏。
- **关联**：PHP 对象注入 POP 链、Session 固定/伪造、无签名 Cookie、JWT 未验签、WAF 规范化差异。

## 检测与防御

- **服务端会话**：session 数据只存服务端，Cookie 只放随机 ID；启用 `session.use_strict_mode`，登录后 `session_regenerate_id(true)`。
- **完整性签名**：若必须客户端存储，使用 HMAC/签名覆盖整个会话串，服务端先验签再反序列化。
- **禁止不可信反序列化**：不要对用户可控 Cookie 直接 `unserialize`/`session_decode`；使用 JSON 等无代码执行的数据格式。
- **输入规范化**：WAF/校验层先做 URL/base64/转义归一化，再匹配关键字；拒绝包含反斜杠转义、控制字符、异常长度的序列化串。
- **检测**：监控 Cookie 中出现 `S:`、`\xNN`、`\NNN`、长度与内容不一致的序列化串；对同一 session 的用户名突变告警。

## 可信度与边界

- 原文为 CTF 题，给出的 `S:5:"\61\64\6d\69\6e"` payload 在题目环境成功伪造 admin；思路与 payload 有实测依据。
- `S` 类型/转义解析在不同 PHP 版本与会话处理器中行为可能不同；真实目标需先确认版本与 session 序列化格式。
- 未在真实 PHP 环境复跑；卡内不包含题目 flag。
