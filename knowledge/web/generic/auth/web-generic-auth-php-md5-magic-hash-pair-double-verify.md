---
id: web-generic-auth-php-md5-magic-hash-pair-double-verify
title: PHP 双人复核绕过：不同输入 240610708/QNKCDZO 的 MD5 同为 0e 前缀，== 判等且 !== 判不等
type: scenario
domain: web
path: web/generic/auth
technique: php-md5-magic-hash-double-input
aliases:
- 0e 魔术哈希
- md5 双输入碰撞
- token_a token_b
- 双人复核绕过
- 240610708 QNKCDZO
- md5($a) == md5($b)
- type juggling md5
tags:
- php
- magic-hash
- type-juggling
- loose-comparison
- md5
- auth-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:15:46+08:00'
  notes: 已对照原文与图02/03核对：admin.php 要求 token_a/token_b 非空、互不相同、md5($a)==md5($b) 且 !==；240610708/QNKCDZO 的 0e 魔术哈希成立，页面提交后回显 flag（图03），与卡片一致。未验证点：PoC 未本机复跑；CTF 环境无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当校验逻辑要求“两份凭据不能相同，但它们的 MD5 必须相等”时，提交 `token_a=240610708`、`token_b=QNKCDZO` 即可：两者的 MD5 都是以 `0e` 开头、后续全为数字的字符串，PHP 的 `==` 会把它们都当作数字 0 而判等，`!==` 又会因原始字符串不同而判不等，于是同时满足“不同输入”和“哈希相等”。

## 原理

- 目标代码通常写成：
  ```php
  $h1 = md5($tokenA);
  $h2 = md5($tokenB);
  if ($h1 == $h2 && $h1 !== $h2) { /* 通过 */ }
  ```
  这里混用了两种比较：`==` 是松散比较，`!==` 是严格比较。
- PHP 的 `==` 在比较两个“数字字符串”时，会先把它们转成数字再比。`0e` 后跟纯数字的字符串是合法的科学计数法，值为 `0 × 10^n = 0`：
  - `md5('240610708') = 0e462097431906509019562988736854`
  - `md5('QNKCDZO') = 0e830400451993494058024219903391`
  两者都被解析为 0，所以 `$h1 == $h2` 为 `true`。
- `!==` 比较的是两个 MD5 结果的原字符串：`0e4620...` 与 `0e8304...` 不同，所以 `$h1 !== $h2` 也为 `true`。两个条件同时成立，校验通过。
- 根因不是 MD5 可碰撞，而是“用松散比较校验安全哈希”；攻击者只需要找到两个不同的输入，使它们的哈希都落在 `0e[0-9]+` 形式，而不需要真正的 MD5 碰撞。
- 同样的逻辑若写成 `md5($a) == md5($b)` 且没有 `!==` 检查，也会被同一对输入绕过；若使用 `hash_equals()` 或 `===`，则不会。

## 触发条件

- 应用要求两个凭据/令牌不同（双人复核、双因子确认、二次确认），但把它们的哈希用 `==`、`!=`、`in_array`（未 strict）等松散比较。
- 被比较的哈希是 `0e` 开头、后续纯数字的字符串，或攻击者能控制两侧输入。
- 目标 PHP 版本仍对“数字字符串之间”的 `==` 使用数值比较；PHP 8 收紧了数字与非数字字符串的比较，但两个数字字符串之间仍受影响。
- 校验通过后能触发敏感操作（进入后台、请求内部诊断接口等）。

## 利用步骤

1. 审计/猜测校验逻辑：找到“两个输入不能相同”但比较哈希的接口，确认是否使用 `==`。
2. 用已知的 0e 魔术哈希输入对测试：`240610708` 与 `QNKCDZO`。
3. 提交 `token_a=240610708&token_b=QNKCDZO`；若返回“校验通过”，说明条件成立。
4. 若接口还有后续参数（如 `target_url`），把完整 URL 作为单个参数值提交；注意 `&` 会被表单/工具拆成新参数，需 URL 编码或直接在页面表单中提交。
5. 继续执行校验后的敏感功能，例如让服务端请求 `http://127.0.0.1/internal/report?view=flag&slot=last`。

## PoC

```http
POST /admin.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

token_a=240610708&token_b=QNKCDZO&target_url=http%3A%2F%2F127.0.0.1%2Finternal%2Freport%3Fview%3Dflag%26slot%3Dlast
```

等价的 PHP 验证：

```php
var_dump(md5('240610708')); // 0e462097431906509019562988736854
var_dump(md5('QNKCDZO'));   // 0e830400451993494058024219903391
var_dump(md5('240610708') == md5('QNKCDZO'));  // bool(true)
var_dump(md5('240610708') !== md5('QNKCDZO')); // bool(true)
```

## 变体与关联

- **输入对变体**：其他 `0e` 前缀 MD5 字典（如 `aabg7XSs`、`aabC9RqS` 等）可与 `240610708` 互换；不同字典项对应不同哈希值，需按目标验证。
- **哈希变体**：SHA-1、SHA-256 也可能出现 `0e` 前缀数字串；`md5(raw_output=true)` 的二进制结果不适用此技巧。
- **比较变体**：`==`/`!=`、`in_array`/`array_search`（未 strict）、`switch` 松散比较；`hash_equals()`/`===` 可防御。
- **关联**：[[web-generic-auth-php-loose-comparison-token-0e-bypass]]（0e 魔术哈希用于 token 校验的另一场景）；[[web-generic-ssrf-preview-panel-target-url-localhost]]（本题校验通过后的 SSRF 利用）。
- **边界**：PHP 8 中 `0 == "foo"` 为 false，但 `"0e1" == "0e2"` 仍为 true；使用严格比较或 `hash_equals()` 时本路径失效。

## 检测与防御

- **检测**：请求参数出现 `0e` 开头数字串、纯 `0`、`240610708`、`QNKCDZO` 等已知魔术哈希输入；同一接口在“双人复核”参数上出现大量不同组合；校验通过后立即访问内部地址。
- **防御**：所有安全哈希/令牌比较使用 `===` 或 `hash_equals()`；`in_array`/`array_search` 加 `true`；不要用哈希值做松散比较；对输入做类型与格式校验（固定长度十六进制）。
- **加固**：双人复核应使用服务端签名的 challenge/response，而不是两个可自由提交的字符串；对校验失败与成功都记录审计日志。
