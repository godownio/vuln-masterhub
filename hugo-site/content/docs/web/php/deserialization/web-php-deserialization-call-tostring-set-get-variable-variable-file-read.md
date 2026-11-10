---
id: web-php-deserialization-call-tostring-set-get-variable-variable-file-read
title: 四层魔术方法接力 POP：__call 里 echo 属性触发 __toString，__toString 写属性触发 __set，__set 读属性触发 __get，最终 $$key 变量变量 + file_get_contents 任意文件读取
type: scenario
domain: web
path: web/php/deserialization
technique: call-tostring-set-get-chain-variable-variable-file-read
tags:
- php
- deserialization
- pop-chain
- magic-method
- variable-variable
- file-read
- ctf
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:21:45+08:00'
  notes: 本次核对未读取图片，仅依据正文与卡片正文。四跳魔术方法接力（Kl::__call echo apple → Als::__toString 写 text 属性 → Glb::__set 读 boy->name → Kl::__get）与原文 tcClassLoad.php 源码一致。但 sink 不可达：原文 __get 内 if ($_GET == Hack) 是数组与字符串比较恒假，且内层 if ($arr[] = 1) 赋值表达式恒为 1 恒真直接 die，file_get_contents 分支是死代码；卡片 step4 的「把 $_GET 改写成字符串绕过」只会让外层比较变假从而跳过整个块，并不能到达读文件，最终危害（任意文件读取）在原文源码下未被证明，需按实际源码修正链路或把卡片降级
url: /docs/web/php/deserialization/web-php-deserialization-call-tostring-set-get-variable-variable-file-read/
draft: false
kb_aliases:
- tcClassLoad POP 链
- __call → __toString → __set → __get 接力
- $$key 变量变量 配合 file_get_contents
- 魔术方法四跳读文件
- Als Kl Glb 反序列化
---

## 一句话结论

入口只有 `unserialize($_POST['cmd'])->init()`，看起来只能调用一个方法；但类里分别存在 `__call`、`__toString`、`__set`、`__get` 四个魔术方法，把它们首尾相连就能串成四跳：`init()` 未定义 → `__call` 执行 `echo $this->apple` → `apple` 是对象触发 `__toString` → `__toString` 给 `$this->text->undefinedProperty` 赋值触发 `__set` → `__set` 读取 `$this->boy->name` 触发 `__get` → `__get` 里 `foreach ($_GET as $k => $v) $$k = $$v;` 把 GET 参数做成变量变量，再用 `file_get_contents($this->phone)` 读出任意文件。

## 原理

- `unserialize` 本身只负责还原对象，真正的执行依赖魔术方法在**对象生命周期中被动触发**；而 `->init()` 这种「方法名固定」的入口可以借 `__call` 把「方法不存在」转成一次可控的属性访问。
- 第一跳：目标类（`Kl`）没有 `init` 方法、但有 `__call($name,$args)`，于是 `$obj->init()` 进入 `__call`；其实现是 `echo $this->apple`——`echo` 一个对象会强制调用该对象的 `__toString`。
- 第二跳：`apple` 属性设为另一个类（`Als`）的实例，其 `__toString` 内部执行 `$this->text->undefinedProperty = 'New Value'`；对不存在的属性赋值会调用目标对象的 `__set`。
- 第三跳：`text` 属性设为（`Glb`）实例，`__set` 内 `return $this->boy->name;`——读取未定义属性触发 `__get`。
- 第四跳：`__get` 是全链的 sink：`foreach ($_GET as $key => $value) { $$key = $$value; }` 把「GET 的键」当变量名、「GET 的值」再当变量名，从而实现变量变量赋值（可覆盖 `$this` 之外的同名局部/全局变量）；紧随其后的 `file_get_contents($this->phone)` 用攻击者可控的属性名做路径，读任意文件并 `echo`。
- 之所以可复用：很多 PHP 题的入口只给「一个方法调用」，看似无害；只要类集合里凑齐 `__call`/`__toString`/`__set`/`__get`/`__destruct` 中的若干，就能用「属性指向下一个对象」把调用链拼长，这是 PHP POP 链构造的通用手法。

## 触发条件

- 存在 `unserialize()` 且攻击者能控制整段序列化数据（本例经 POST `cmd`）。
- 类集合里同时存在至少两三个可用的魔术方法，且它们的实现里有「echo 对象」「给对象属性赋值」「读对象属性」这类会级联触发的操作。
- 链尾 sink 的路径参数来自对象属性（而不是写死），使攻击者可指向 `/flag` 之类目标。
- 需要知道类名与属性名（源码泄露、`highlight_file` 自曝、常见命名）。

## 利用步骤

1. 读全部类，标出每个魔术方法的触发条件与内部动作，画成有向图：`__call`→`__toString`→`__set`→`__get`→sink。
2. 从 sink 反推：`__get` 里的 `file_get_contents($this->phone)` 需要 `phone` 可控 → 该对象即 `Glb`，其 `boy` 指向下一跳对象。
3. 中间层 `Kl` 的 `phone` 设为 `/flag`；`var` 属性存在与否决定走 `die("Hack!!")` 还是读文件分支，注意避开 `die`。
4. `__get` 里的 `$_GET` 循环是变量变量赋值：构造 GET 参数让被覆盖的变量恰好是分支判断用的那个（`$_GET == "Hack"` 这类恒假比较可借变量变量把 `$_GET` 自身改写成字符串绕过）。
5. 顶层 `Kl`：`apple` = `Als` 实例，`Als` 的 `text` = 下一层 `Kl`，`Als` 的 `dict` 需满足 `text == "helloworld"` 才进 `__wakeup` 分支，按源码取舍。
6. 生成序列化串 POST 到入口，观察 flag 回显。

## PoC

结构示意（属性名按源码）：

```php
<?php
class Als { public $text; public $dict; }
class Kl  { public $apple; public $phone; public $var; }
class Glb { public $boy; public $gay; }

$a = new Als();
$a->text = "helloworld";        // 影响 __wakeup 分支
$a->dict = new Glb();

$k2 = new Kl();                 // __get 层，phone = 目标文件
$k2->phone = "/flag";
$k2->var   = "x";               // 影响 isset 分支

$g = new Glb();
$g->boy = $k2;                  // __set 读 $boy->name 跳到 __get

$k1 = new Kl();                 // 顶层，init() 走 __call
$k1->apple = $a;                // echo 触发 __toString

$a->text = $k1;                 // __toString 里给 text 赋属性 → $k1 的 __set? 按源码取向
echo serialize($k1);
```

发送：

```http
POST /tcClassLoad.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

cmd=<上一步的序列化串>
```

## 变体与关联

- 变体：`__destruct` 也可以当入口（脚本结束自动调用），比 `__call` 更常见；把入口换成 `__destruct` 后其余跳数不变。
- 变体：sink 换成 `include`/`eval`/`call_user_func` 即从任意读升为任意代码执行；换成 `unlink`/`file_put_contents` 则是删除/写马。
- 变体：`$$key = $$value` 若无法满足，可用 `$this->{$name}` 动态属性或 `$obj->$prop` 达到同样的「属性名可控」效果。
- 关联：[[web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read]]（同为 `__toString`→`__get` 读文件，但走 `is_callable`/`__invoke`，且入口是 `__wakeup`）。
- 关联：[[web-php-deserialization-destruct-tostring-htmlspecialchars-file-read]]（`__destruct`→`__toString`→`file_get_contents`，跳数更少）。
- 关联：[[web-generic-auth-php-variable-variable-config-array-bypass]]（`$$key` 变量变量覆盖的通用形态）。

## 检测与防御

- 防御：禁止对不可信输入 `unserialize`；用 JSON + 显式字段白名单，或 `allowed_classes` 严格限制可实例化类。
- 防御：不要给魔术方法写「对属性做 echo/赋值/读取」这类隐式级联动作；sink 类操作（读文件、执行命令）不要出现在魔术方法内。
- 防御：`file_get_contents` 的路径必须白名单校验，禁用 `..` 与绝对路径。
- 检测：请求体出现 `O:` 开头的序列化串且长度异常；魔术方法链导致单次请求内出现 `file_get_contents` 于非常规路径（`/flag`、`/etc/passwd`）；`$_GET` 被以变量变量方式改写时 PHP 报 undefined variable 的日志。
- 响应：下线入口、审计同工程其它 `unserialize` 点、检查是否已写入 webshell。
