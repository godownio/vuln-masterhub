---
id: web-php-deserialization-wakeup-resource-null-destruct-reentry
title: PHP 反序列化绕过 __wakeup 资源置空：三对象析构 + 构造器重入 + 引用调用 execute
type: scenario
domain: web
path: web/php/deserialization
technique: php-wakeup-resource-null-destruct-reentry
aliases:
- __wakeup 资源置空绕过
- PHP wakeup 绕过
- 三对象析构链
- 构造器重入
- tmpfile 资源反序列化
- 引用调用 execute
- getHandler 反序列化
tags:
- php
- deserialization
- wakeup
- bypass
- destruct
- reference
- anonymous-class
- tmpfile
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V152
  verified_at: '2026-11-06T07:36:07+08:00'
  notes: 已对照原文源码核对：getHandler::__destruct 调用可控 callable、匿名类 __wakeup 将 tmpfile 资源置 null、execute 要求 is_resource、三对象数组（obj1->a=[obj3,'__construct']、obj2->a=[&obj3->p,'execute']、arr=[obj1,obj2,obj3]）保证先重建后执行，逻辑与原文一致。未验证点：未在 PHP 环境复跑，数组析构顺序/引用序列化保留需按目标 PHP 版本确认（卡中已注明）；CTF 题无组件版本，未设 versions；frontmatter 无 sources/source_url。
---

## 一句话结论

当匿名类的 `__wakeup()` 会把 `tmpfile()` 资源置空、`execute()` 又要求资源有效时，可以用三个 `getHandler` 对象组成数组：第一个对象析构时调用第三个对象的 `__construct` 重新创建资源，第二个对象通过**引用**指向第三个对象的 `p` 属性并在析构时调用 `execute()`；数组先进先出的析构顺序保证“先重建、后执行”，从而绕过 `__wakeup` 并执行 `system($_GET['cmd'])`。

## 原理

- 目标类 `getHandler`：
  - `__construct()` 创建一个匿名类实例并赋给 `$this->p`；匿名类构造时 `tmpfile()` 得到有效资源，`execute()` 在资源有效时执行 `system($_GET['cmd'])`，`__wakeup()` 会把 `handle` 置为 `null`。
  - `__destruct()` 要求 `$this->a` 是数组，然后 `$cb = $this->a; $cb();`，即把属性当 callable 调用。
- 直接反序列化 `getHandler` 时，PHP 会调用匿名类的 `__wakeup()`，`handle` 变成 `null`；随后析构调用 `execute()` 会命中 `!is_resource($handle)` 而 `die`，无法利用。
- 绕过思路是“在 wakeup 之后重新构造一个未被置空的对象”，并用引用把“执行者”指向这个新对象：
  1. `obj1->a = [obj3, '__construct']`：obj1 析构时调用 obj3 的构造器；构造器内部 `new class { tmpfile(); }` 创建新的匿名类实例并赋给 `obj3->p`，这个新对象的 `handle` 是有效资源（它的 `__wakeup` 在构造时不会执行，只有反序列化时才会）。
  2. `obj2->a = [&obj3->p, 'execute']`：数组第一个元素是对 `obj3->p` 的**引用**，而不是构造时的旧对象；当 obj2 析构调用该 callable 时，引用已指向 obj1 步骤中新构造的匿名类实例，因此 `execute()` 看到有效 handle 并执行命令。
  3. `$arr = [obj1, obj2, obj3]`：PHP 数组析构按元素顺序进行（先进先出），保证 obj1 先于 obj2 析构；obj3 被数组持有，直到最后才销毁，因此它的 `p` 在 obj1/obj2 执行期间一直存活。
- 为什么 `__wakeup` 不再阻碍：被 `__wakeup` 置空的是反序列化时创建的旧匿名对象；obj1 的 `__construct` 重新创建了一个新的匿名对象并覆盖 `obj3->p`，执行时使用的是新对象，旧对象的 `handle=null` 无关紧要。
- 引用是关键：如果 `obj2->a` 在序列化时直接写 `[$obj3->p, 'execute']`（值拷贝），它保存的是旧对象句柄，仍会被 `handle=null` 挡住；用 `&$obj3->p` 让 callable 在调用时解引用当前属性值。

## 触发条件

- 存在 `unserialize($_GET['p'])` 等用户可控反序列化入口。
- 可反序列化的类在 `__destruct()` 中把属性当 callable 调用（`$cb()`/`call_user_func`），且属性可控。
- 目标匿名类/普通类有 `__wakeup()` 把资源或关键状态置空，同时 `__construct()` 会重新初始化该状态。
- 攻击者能把多个对象放进同一个数组，并利用引用（`&`）让 callable 指向运行时属性。
- 数组析构顺序为先进先出（PHP 常见行为），且对象在数组销毁前保持存活。

## 利用步骤

1. 审计类：找 `__destruct` 中的 `$this->a` 调用、`__wakeup` 中的资源/状态置空、`__construct` 中的资源重建、`execute` 中的危险 sink。
2. 构造 `obj1`：`a = [obj3, '__construct']`，用于在析构时重建 obj3 的资源。
3. 构造 `obj2`：`a = [&obj3->p, 'execute']`，用引用指向 obj3 的属性，确保调用时取到新对象。
4. 构造 `obj3`：作为被重建/被调用的载体，放入数组。
5. `$arr = [obj1, obj2, obj3]`，`serialize($arr)` 后 URL 编码，作为 `p` 参数提交；设置 `cmd` 参数为要执行的命令。
6. 观察命令输出；若失败，检查数组析构顺序、引用是否被序列化保留、匿名类名/方法名是否正确。

## PoC

```php
<?php
class getHandler {
    public $p;
    public $a;
}

$obj1 = new getHandler(); // 创造者：析构时重建 obj3 的资源
$obj2 = new getHandler(); // 执行者：析构时调用 execute
$obj3 = new getHandler(); // 工具人：持有 p

$obj1->a = array($obj3, '__construct');
$obj2->a = array(&$obj3->p, 'execute');

$arr = array($obj1, $obj2, $obj3);
echo urlencode(serialize($arr));
```

```text
GET /?p=<urlencoded_serialized_array>&cmd=id
```

说明：目标源码中的 `getHandler::__construct()` 会创建带 `tmpfile()` 的匿名类；`__wakeup()` 把 `handle` 置 null。上述 payload 通过 obj1 的析构重新调用构造器，绕过了置空。

## 变体与关联

- 变体：`__wakeup` 置空的是普通属性而非资源时，同样可用“析构调用构造器/初始化方法”重新赋值。
- 变体：用 `__destruct` 调用 `call_user_func`/`array_map`/`usort` 等间接 callable，引用属性作为回调。
- 变体：对象数组析构顺序在某些 PHP 版本/结构中可能不同；可用嵌套数组/引用调整顺序，先本地验证。
- 关联：[[web-php-deserialization-multi-destruct-anonymous-class-global-function-chain]]（多对象析构顺序 + 匿名类 + 全局函数链）；[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（`__wakeup` 绕过的其他手法）；[[web-php-deserialization-destruct-session-balance-forge]]（析构链利用）。
- 关联：类 C 的 `__wakeup` 只在反序列化时触发，`__construct` 在 `new` 时触发；利用“构造器重入”可绕过只针对反序列化路径的初始化/清零逻辑。

## 检测与防御

- 修复：不要对用户输入使用 `unserialize`；改用 `json_decode` 等无代码执行的格式。
- 防御：必须反序列化时使用 `unserialize($data, ['allowed_classes' => [...]])` 严格限制类；不要让 `__destruct`/`__wakeup` 执行动态 callable。
- 防御：避免在 `__wakeup` 中只做“置空”而不阻止后续构造器重入；对资源/句柄类状态使用不可伪造的令牌或直接拒绝反序列化。
- 检测：请求参数中出现 `O:`/`a:`/`s:` 序列化结构、`__construct`/`execute`/`system` 等字符串，或 Base64 解码后出现 `serialize` 特征；监控 `unserialize` 入口的异常类名与引用结构。
- 响应：禁用危险函数、清理 webshell、审计命令执行与文件访问；轮换应用密钥与凭据。
