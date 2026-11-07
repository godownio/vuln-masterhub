---
id: web-generic-auth-php-md5-loose-comparison-error-code
title: PHP md5 弱比较遇错误码整数：构造 2025 前缀 MD5 绕过登录
type: scenario
domain: web
path: web/generic/auth
technique: php-md5-loose-comparison-integer-bypass
aliases:
- PHP 弱比较登录绕过
- md5 2025 前缀绕过
- 错误码当哈希比较
- VERIFY_FAILED 2025
- PHP 7 字符串数字比较
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
tags:
- php
- auth-bypass
- type-juggling
- md5
- loose-comparison
- error-handling
cve: []
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:19:36+08:00'
  notes: 已对照原文与图片07核对：buildExpectedHash 对长度>=64或含控制字符的 channelKey 抛 LENGTH_ERROR，内层catch转抛 VERIFY_FAILED，getExpectedHash 返回 pickErrorCode=2025；登录处 md5(accessKey)==expected 为弱比较，PHP<8 下 "2025xxx"==2025 成立，爆破脚本要求 md5 以2025开头且第5位非数字，逻辑与原文一致。原文仅展示常量并给出爆破脚本，未截图成功登录；PoC未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

登录逻辑 `md5($accessKey) == $expected` 使用弱比较；当 `channel_key` 过长或非法时，哈希计算抛异常，错误处理把 `VERIFY_FAILED` 常量（整数 2025）当作 `$expected` 返回。攻击者只需找到一个 MD5 十六进制串以 `2025` 开头、第 5 位非数字的 `accessKey`，PHP 7 的“字符串转数字”弱比较就会把它与 2025 判等，从而绕过登录。

## 原理

- 正常路径 `buildExpectedHash()` 返回 `md5('ctfshow:'.$channelKey.':verify'.$secret_salt)`；salt 未知，攻击者无法直接算出。
- 异常路径：`getExpectedHash()` 捕获异常后调用 `pickErrorCode()`，返回 `ERROR_CODES` 中的错误码；其中 `VERIFY_FAILED = 2025`。若让 `channelKey` 触发 `LENGTH_ERROR`（长度 ≥64 或包含控制字符），`buildExpectedHash` 抛 `RuntimeException(..., LENGTH_ERROR)`，但被内层 `catch` 转成 `VERIFY_FAILED`，最终 `$expected` 是整数 2025。
- 比较语句 `md5($accessKey) == $expected`：
  - `md5()` 返回 32 位十六进制字符串；
  - PHP 7 及更早版本在“数字与字符串”弱比较时，会把字符串转换为数字：从左到右解析数字前缀，遇到非数字字符停止。因此 `"2025abc..." == 2025` 为 true。
  - PHP 8 改变了规则：数字与字符串比较时把数字转成字符串做字符串比较，`"2025abc..." == 2025` 为 false，因此该手法仅在 PHP < 8 成立。
- 攻击者只需暴力搜索 `accessKey`，使 `md5(accessKey)` 以 `2025` 开头且第 5 个字符不是数字（确保转数字后正好为 2025，而不是 20250 等）。
- `channel_key` 用任意长度 ≥64 的字符串即可触发异常路径；不要求正确盐值。

## 触发条件

1. 目标 PHP 版本 < 8（弱比较仍做字符串转数字）。
2. 登录接口使用 `==`/`!=` 比较哈希与期望值，而非 `===`/`hash_equals()`。
3. 异常处理会把整数错误码作为期望哈希返回。
4. 攻击者能控制 `channel_key` 使其进入异常分支（长度/控制字符等）。

## 利用步骤

1. 阅读源码，确认比较符为 `==`、`$expected` 可能为整数错误码。
2. 构造 `channel_key` 长度 ≥64（或含控制字符），使 `getExpectedHash` 返回 `VERIFY_FAILED = 2025`。
3. 本地爆破 `accessKey`：`md5(accessKey)` 以 `2025` 开头且第 5 位非数字。
4. 提交登录：`access_key=<爆破值>&channel_key=<长字符串>&csrf=...`。
5. 弱比较成立，`$_SESSION['authed']=true`，读取 flag。

## PoC

爆破脚本：

```python
import hashlib

target = "2025"
i = 0
while True:
    s = str(i)
    h = hashlib.md5(s.encode()).hexdigest()
    if h.startswith(target) and not h[len(target)].isdigit():
        print("access_key =", s)
        print("md5 =", h)
        break
    i += 1
```

登录请求（`channel_key` 用 64 个 `a` 触发长度错误）：

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=login&csrf=<csrf>&access_key=<爆破值>&channel_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

PHP 7 中 `md5('<爆破值>') == 2025` 为 true；PHP 8 中为 false。

## 变体与关联

- 同类“0e”魔法哈希（`md5(...) == "0e..."`）是另一个弱比较分支；本案利用的是整数错误码而非 0e。
- `in_array` 未开启 strict、`strcmp` 返回值、`==` 比较数组/布尔等也存在类似弱比较问题。
- 根因组合：弱比较 + 异常处理把内部错误码泄露为业务值。
- 若代码使用 `hash_equals` 或 `===`，该手法失效；若 `channel_key` 校验更严格，异常分支也不可达。

## 检测与防御

- 哈希/令牌比较一律使用 `hash_equals()` 或 `===`，禁止 `==`。
- 错误处理不要返回可用于比较的内部错误码；异常路径应直接失败，不要返回整数作为“期望值”。
- 升级到 PHP 8+ 可缓解该特定弱比较，但不能替代严格比较。
- 输入校验：`channel_key` 明确长度/字符集，异常分支不可由用户随意触发。
- 代码审计搜索 `md5(`/`sha1(` 与 `==` 组合、`in_array` 未 strict、错误码常量参与业务比较。
