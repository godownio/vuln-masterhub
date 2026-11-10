---
id: web-php-json-encode-inf-false-jsondecode-null-strict-bypass
title: json_encode(INF) 失败导致内部请求变空包，json_decode(500 错误页) 返回 NULL 绕过 === FALSE 校验
type: scenario
domain: web
path: web/php
technique: php-json-encode-inf-null-strict-compare-bypass
tags:
- php
- json
- inf
- json_encode
- json_decode
- strict-comparison
- bypass
- type-juggling
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:18:29+08:00'
  notes: 已对照原文与图片核对：invite=-3.3e99999999999999 使 json_encode 返回 false、qInternal 空 POST、Flask 500 错误页被 curl 返回、json_decode(错误页)=NULL、NULL===FALSE 不成立从而绕过邀请码校验，均与原文流程与截图一致；卡片说明了错误页为空时绕过失效的边界。未验证点：未在本机复跑；受影响 PHP 版本原文未给，affected_versions 已 --clear。
url: /docs/web/php/web-php-json-encode-inf-false-jsondecode-null-strict-bypass/
draft: false
kb_aliases:
- json_encode INF false
- json_decode 错误页 NULL
- === FALSE 绕过
- 邀请码绕过
- PHP JSON 严格比较
- -3.3e999
---

## 一句话结论

PHP 的 `json_encode()` 遇到 `INF`/`NAN` 会返回 `false`：若业务把该返回值直接当作内部 HTTP 请求的 body，请求会退化为空 POST，内网服务返回 500 错误页；`json_decode(错误页, true)` 得到 `NULL`，而代码用 `if ($result === FALSE)` 做拒绝判断，`NULL !== false`，邀请码/结果校验因此被绕过。

## 原理

- **JSON 数字溢出成 INF**：`json_decode()` 解析 `-3.3e99999999999999` 这类超出浮点范围的指数时，PHP 得到 `float(-INF)`。`json_encode()` 不能编码 INF/NAN，返回 `false` 并产生 `JSON_ERROR_INF_OR_NAN`（未设置 `JSON_PARTIAL_OUTPUT_ON_ERROR` 时）。
- **false 进入 curl 的 payload**：内部请求封装函数形如 `qInternal($endpoint, $payload = null)`，判断 `$payload !== null` 后执行 `curl_setopt($ch, CURLOPT_POSTFIELDS, $payload)`。`false !== null` 成立，于是 POST body 为空。内网 Flask 的 `json.loads(request.data)` 解析空 body 抛异常，返回 500。
- **curl 仍返回错误页**：没有设置 `CURLOPT_FAILONERROR` 时，`curl_exec()` 对 HTTP 500 仍返回响应体（如 Flask 错误页 HTML）。封装函数 `return @$result ? $result : 'false';` 看到非空字符串，原样返回 HTML。
- **json_decode 的失败结果**：`json_decode('<html>...')` 不是合法 JSON，返回 `NULL`。业务接着写 `if ($checkInvite === FALSE) deny();`——严格比较要求类型和值都相同，`NULL === false` 为 false，于是不进入拒绝分支，注册继续。
- **为什么不是普通的类型juggle**：这里不是 `==` 的松散比较，而是“校验方误以为失败一定是 false”，忽略了 `json_decode` 对非法输入返回的是 `NULL`；同时上游 `json_encode` 失败导致请求本身畸形，制造了“非 JSON 的错误页”这一输入。
- **失败条件**：若内部错误页为空，封装函数的 `@$result ? ... : 'false'` 返回字符串 `'false'`，`json_decode('false', true)` 得到布尔 `false`，`=== FALSE` 成立，绕过就失败；只有拿到非空非 JSON 响应体时才能得到 NULL。

## 触发条件

- 后端把用户提供的 JSON 值（或包含该值的数组）再次 `json_encode` 后作为内部请求/外部 HTTP 调用的 body。
- 用户可注入超出浮点范围的数字（如 `-3.3e99999999999999`、`1e9999`）。
- 下游服务解析失败返回非空错误页（HTML/文本），且调用方未设置 `CURLOPT_FAILONERROR` 或错误处理。
- 调用方对下游响应 `json_decode` 后用 `=== FALSE`（或类似的“失败即布尔 false”假设）判断，而没有检查 `json_last_error()`。

## 利用步骤

1. 找到把用户 JSON 字段二次编码并转发到内部服务的接口（本例为注册时邀请码校验）。
2. 在 JSON 中把该字段设成超范围指数：
   ```json
   {"action":"register","d":{"user":"attacker","pass":"attacker123","invite":-3.3e99999999999999}}
   ```
3. 触发接口：`json_encode` 失败 → 空 POST → 下游 500 → 错误页 HTML 被返回 → `json_decode` 得 NULL → 严格比较放行。
4. 观察注册是否成功；成功后用该账户继续登录、操作。
5. 若第一次不成功，检查下游错误页是否为空、封装函数是否吞掉响应，以及代码是否改用 `!$result`/`== false` 等判断。

## PoC

```json
{
  "action": "register",
  "d": {
    "user": "attacker",
    "pass": "attacker123",
    "invite": -3.3e99999999999999
  }
}
```

```php
// 等价的核心逻辑
$v = json_decode('{"invite":-3.3e99999999999999}', true); // invite => -INF
$payload = json_encode(array("invite" => $v['invite']));   // false（JSON_ERROR_INF_OR_NAN）
// $payload 传给 curl CURLOPT_POSTFIELDS，导致空 body + 下游 500
$check = json_decode($errorHtml, true);                    // NULL
var_dump($check === FALSE);                                // false，校验放行
```

说明：payload 与比较逻辑按原文流程整理；未在本机复跑。

## 变体与关联

- **NAN/INF 注入点**：任何用户可控浮点进入 `json_encode` 的路径都可尝试；JSON 本身不支持 NaN/Infinity 字面量，但超范围指数会被解析为 INF。
- **其他“失败值”误判**：`json_decode` 失败返回 NULL、`preg_match` 失败返回 false、`file_get_contents` 失败返回 false，若代码假设“失败一定是某一种布尔值”，都可能被不同失败形态绕过。
- **PHP 版本差异**：`JSON_PARTIAL_OUTPUT_ON_ERROR` 会把 INF 替换成 0，若业务显式设置该 flag，本链失效；`JSON_THROW_ON_ERROR` 会抛异常，也可能阻断。
- **关联**：PHP 松散/严格比较类绕过见 [[web-generic-auth-php-loose-comparison-token-0e-bypass]]、[[web-generic-auth-php-md5-array-strict-comparison-bypass]]。
- **边界**：下游返回空响应、封装函数把 falsey 结果替换成字符串 `'false'`、或用 `json_last_error()`/类型检查时，本链不成立。

## 检测与防御

- **代码**：校验外部响应时先检查 `json_last_error() === JSON_ERROR_NONE`，并验证响应 `Content-Type: application/json`；不要用 `=== FALSE` 作为唯一失败判据，改用 `!is_array($result)` / 显式白名单。
- **上游**：对 `json_encode` 的返回值做检查（`=== false` 时拒绝请求），或使用 `JSON_THROW_ON_ERROR`；对用户提交的数值做范围校验（拒绝 INF/NAN）。
- **网络**：内部调用设置 `CURLOPT_FAILONERROR` 或检查 HTTP 状态码，非 2xx 直接失败而不是把错误页当业务数据。
- **检测**：请求体中出现超大指数数字（`e999...`）、内部接口 500 与注册成功的时间关联、`json_encode` 相关 warning/`JSON_ERROR_INF_OR_NAN` 日志。
