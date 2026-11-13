---
id: web-php-deserialization-class-case-regex-wakeup-property-bypass
title: PHP 序列化正则类名大小写绕过 + 属性数绕过 __wakeup：小写类名躲过 [BA] 校验后经 __destruct/__call eval
type: scenario
domain: web
path: web/php/deserialization
technique: php-serialize-class-case-regex-wakeup-property-bypass
aliases:
- 类名大小写绕过序列化正则
- O:1:"b" 绕过 "[BA]"
- PHP 类名大小写不敏感
- 属性数绕过 wakeup
- easy_eval
- 天翼杯 easy_eval
tags:
- php
- deserialization
- wakeup-bypass
- regex-bypass
- class-name
- property-count
- ctf
cve:
- CVE-2016-7124
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V647
  verified_at: '2026-11-13T03:48:06+08:00'
  notes: 已对照原文与39张截图核对：例题源码 preg_match_all('/"[BA]":(.*?):/s')+intval!==1、PoC O:1:"B":1:{s:1:"a";O:1:"a":2:{s:4:"code";s:16:"eval($_POST[0]);";}}、__destruct→__call→eval 链与图28-39（phpinfo open_basedir、config.php.swp、REDIS_PASS、MODULE LOAD 提权）一致，类名小写+属性数绕过描述成立；原文未标注 PHP 受影响版本，affected_versions 留空正确；CVE-2016-7124 版本区间文字沿引既有卡未独立复核。未复跑 PoC。
---

# 一句话结论

当服务端用区分大小写的正则（如 `preg_match_all('/"[BA]":(.*?):/s')`）检查序列化串里的类名/属性数，以防止 `__wakeup` 绕过时，可以把类名写成小写（`O:1:"b"`/`O:1:"a"`）：PHP 反序列化时类名不区分大小写、仍实例化 `B`/`A`，但正则匹配不到小写类名从而跳过校验；随后把带 `__wakeup` 的类的声明属性数改成大于实际值，即可跳过 `__wakeup` 的重置，由 `__destruct → __call → eval` 执行代码。

# 原理

- **PHP 类名大小写不敏感**：`unserialize('O:1:"a":1:{...}')` 与 `O:1:"A":...` 都会实例化类 `A`；序列化串中的类名只是查找键，PHP 在类表中按大小写不敏感匹配。
- **正则默认区分大小写**：`preg_match_all('/"[BA]":(.*?):/s', $poc, $ret)` 只匹配大写 `"A":`/`"B":`；把类名写成小写 `"a"`/`"b"` 后该正则完全看不到它们，也无法对它们后面的属性数做 `intval($i)!==1` 检查。
- **属性数绕过 `__wakeup`**：在受 CVE-2016-7124 影响或行为相同的 PHP 实现中，序列化串声明的属性个数大于对象实际属性个数时，`unserialize()` 会跳过 `__wakeup()`，但已解析出的属性保留；因此把 `A` 的 `O:1:"a":1:` 改成 `O:1:"a":2:`，`__wakeup()` 中 `$this->code = ""` 不执行，`code` 仍是攻击者写入的 `eval($_POST[0]);`。
- **触发链**：`B::__destruct()` 执行 `echo $this->a->a();`，`A` 没有 `a()` 方法，触发 `A::__call('a', [])`，其方法体 `eval($this->code)` 执行攻击者代码。外层 `B` 用大写（正则只看到 `"B":1:{s`，`intval` 为 1 通过），内层 `A` 用小写躲过正则并改属性数。
- **为什么能同时满足过滤与执行**：过滤器和 PHP 解析器对同一个序列化串使用了不同的“类名视图”——过滤器按字节区分大小写，解析器按类表不区分大小写；这是典型的“校验点与执行点解析不一致”。
- **版本边界**：属性数绕过依赖 PHP 版本/实现（CVE-2016-7124 影响 PHP 5.5 及更早、5.6.0–5.6.25、7.0.0–7.0.10；更高版本多数已修复）。类名大小写绕过本身与版本无关；若属性数绕过失效，可改用引用别名、`C:` 前缀、`__wakeup` 抛异常等其他绕过（见关联卡）。

# 触发条件

- 目标对用户可控数据调用 `unserialize()`，且存在可串联的魔术方法（`__wakeup` 重置、`__destruct`/`__call` 等 sink）。
- 过滤逻辑是在原始序列化字符串上跑区分大小写的正则，按类名/属性数字段做校验（而不是用 `allowed_classes` 或反序列化后对象检查）。
- 目标 PHP 版本仍受属性数绕过影响（或存在其他可用的 `__wakeup` 绕过）。
- 攻击者能控制序列化串中的类名大小写与属性计数（直接 POST 序列化串即可）。

# 利用步骤

1. 审计目标类，确认 `__wakeup` 重置哪些属性、`__destruct`/`__call` 如何到达 eval/命令执行。
2. 在本地按正常属性数构造对象并 `serialize()`，确认类名与属性计数位置。
3. 把带 `__wakeup` 的类名改成小写（如 `A` → `a`），使区分大小写的正则匹配不到；外层类保持正则期望的大小写与属性数（如 `O:1:"B":1:{...}`）。
4. 把小写类的属性计数从真实值 N 改为 N+1（如 `O:1:"a":1:` → `O:1:"a":2:`），跳过 `__wakeup`。
5. 提交 payload，确认 `__destruct → __call → eval` 执行；若目标禁用大量函数，再用蚁剑等工具连接或结合 `open_basedir`/`disable_functions` 绕过。
6. 注意不同 PHP 版本的属性数绕过行为，必要时换用其他 `__wakeup` 绕过链。

# PoC

```php
<?php
class A {
    public $code = "";
    function __call($method, $args) { eval($this->code); }
    function __wakeup() { $this->code = ""; }
}
class B {
    public $a;
    function __destruct() { echo $this->a->a(); }
}
// 正常序列化（属性数 1）
// O:1:"B":1:{s:1:"a";O:1:"A":1:{s:4:"code";s:16:"eval($_POST[0]);";}}
// 绕过：内层类名小写躲过 /"[BA]":/，属性数改为 2 跳过 __wakeup
// O:1:"B":1:{s:1:"a";O:1:"a":2:{s:4:"code";s:16:"eval($_POST[0]);";}}
```

```http
POST /?poc=O:1:"B":1:{s:1:"a";O:1:"a":2:{s:4:"code";s:16:"eval($_POST[0]);";}} HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

0=phpinfo();
```

# 变体与关联

- 与 [[web-php-deserialization-wakeup-property-count-bypass]]：该卡覆盖纯属性数绕过及其影响版本；本卡补充“正则按大写类名校验、用小写类名让过滤失效”的前置绕过，两者组合使用。
- 与 [[web-php-deserialization-capital-s-hex-escape-regex-filter-bypass]]：同属序列化正则过滤绕过，但该卡用 `S` 十六进制转义隐藏敏感字符串，本卡利用类名大小写不敏感。
- 其他 `__wakeup` 绕过：引用别名（[[web-php-deserialization-wakeup-reference-alias-bypass]]）、`C:` 前缀（[[web-php-deserialization-c-prefix-arrayobject-bypass]]）、`__wakeup` 抛异常仍析构（[[web-php-deserialization-wakeup-throw-still-destruct]]）。
- 后利用：该 CTF 题在 get shell 后通过 `.swp` 泄露 `config.php` 中的 Redis 密码，再用 Redis 主从复制/`MODULE LOAD` 加载 `exp.so` 提权（见 [[pentest-initial-access-redis-master-slave-rogue-server-rce]]、[[pentest-privilege-escalation-redis-module-load-root-exec]]）。

# 检测与防御

- 检测：请求体中出现 `O:`/`C:` 序列化串且类名大小写与源码不一致、属性计数与类定义不符；同一参数先做正则检查后又 `unserialize()` 的代码模式；`__wakeup` 未执行导致敏感属性保留的异常行为。
- 防御：不要用正则检查序列化字符串，改用 `unserialize($data, ['allowed_classes' => [...]])` 白名单并在反序列化后校验对象；升级 PHP 修复 CVE-2016-7124；避免在 `__destruct`/`__call` 中执行 `eval`/命令；对用户输入做签名/HMAC 或改用 JSON。
