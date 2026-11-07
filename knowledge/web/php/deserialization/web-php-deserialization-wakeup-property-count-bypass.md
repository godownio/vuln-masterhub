---
id: web-php-deserialization-wakeup-property-count-bypass
title: PHP __wakeup 属性数绕过（CVE-2016-7124）：序列化声明属性数大于实际即跳过重置
type: scenario
domain: web
path: web/php/deserialization
technique: php-wakeup-property-count-bypass
aliases:
- __wakeup 绕过
- 属性数绕过
- 序列化属性数量大于实际
- CVE-2016-7124
- 极客大挑战 2019 PHP
- Name username password
tags:
- php
- deserialization
- wakeup-bypass
- property-count
- cve-2016-7124
- ctf
cve:
- CVE-2016-7124
severity: high
confidence: high
status: verified
affected_versions: PHP 5.5 及更早分支；PHP 5.6.0–5.6.25；PHP 7.0.0–7.0.10（原文标记）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T17:01:29+08:00'
  notes: 已对照原文0x02与图03-06核对：O:4:"Name":2→3跳过__wakeup、private属性%00Name%00格式、CVE-2016-7124版本区间5.6.0-5.6.25/7.0.0-7.0.10与原文一致；无sources/source_url；未在本机复跑
---

## 一句话结论

在受影响的 PHP 版本上，`unserialize()` 遇到序列化串声明的属性个数大于对象真实属性个数时会跳过 `__wakeup()`，攻击者因此可以保留在 payload 中设置的敏感属性值（如 `username=admin`），绕过 `__wakeup` 的安全重置后由 `__destruct` 等后续逻辑触发危害。

## 原理

- PHP 对象序列化格式为 `O:<类名长度>:"<类名>":<属性个数>:{...属性...}`；反序列化时引擎按声明的属性个数读取属性表。
- 正常情况下 `unserialize()` 完成属性恢复后立即调用 `__wakeup()`，很多题目/业务会在其中把关键属性重置为安全值（例：`$this->username = 'guest';`）。
- 受影响版本中，若声明的属性个数**大于**实际提供的属性个数，`unserialize()` 会认为对象结构不完整/进入异常路径，从而不调用 `__wakeup()`，但已解析出的属性仍然保留，随后对象析构时 `__destruct()` 照常执行。
- 因此只要把 `O:4:"Name":2:` 改成 `O:4:"Name":3:`（其余属性不变），`__wakeup()` 中的 `username=guest` 不会执行，攻击者设置的 `username=admin` 与 `password=100` 就能进入 `__destruct()` 的判断分支。
- 私有/受保护属性的属性名在序列化串中以 `%00类名%00属性名` / `%00*%00属性名` 表示（原始字节为 NUL），构造时长度按字节数计算；URL 传递时 NUL 需写成 `%00`。

## 触发条件

- 目标使用 `unserialize()` 处理用户可控数据，且允许实例化目标类（无 `allowed_classes` 白名单或白名单包含该类）。
- 入口类定义了 `__wakeup()`，其中会重置攻击者需要保留的属性。
- 目标 PHP 版本落在受影响区间：PHP 5.5 及更早、PHP 5.6.0–5.6.25、PHP 7.0.0–7.0.10；PHP 5.6.26 / 7.0.11 起修复。
- 存在后续自动触发点（通常 `__destruct()`）使用被保留的属性完成敏感操作。

## 利用步骤

1. 审计目标类，确认 `__wakeup()` 重置了哪个属性、`__destruct()`/其他魔术方法如何使用该属性。
2. 按目标类定义在本地构造对象并 `serialize()`，得到属性个数为真实值 N 的序列化串。
3. 把类名后的属性计数从 N 改为 N+1（或更大），保持属性内容不变。
4. 若属性为 private/protected，把属性名改写为 `%00类名%00属性名` / `%00*%00属性名`，长度按改写后的字节数计算并 URL 编码。
5. 提交 payload，确认 `__wakeup()` 未执行、目标属性值在 `__destruct()` 中生效。

## PoC

题目类（极客大挑战 2019 PHP 简化）：

```php
class Name {
    private $username = 'nonono';
    private $password = 'yesyes';
    public function __wakeup() { $this->username = 'guest'; }
    public function __destruct() {
        if ($this->password != 100) { die('NO!!!hacker!!!'); }
        if ($this->username === 'admin') { global $flag; echo $flag; }
    }
}
```

正常序列化结果为 2 个属性；把计数改为 3，并保留 private 属性名格式：

```text
O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}
```

URL 编码后作为 `?select=` 参数提交；`__wakeup()` 被跳过，`__destruct()` 中 `username==='admin'` 成立并输出 flag。原文未在本机复跑。

## 变体与关联

- 引用别名绕过：不用改属性计数，而用 `$a =& $b` 的 `R:` 引用让 `__wakeup()` 的重置在 `__destruct()` 写回时失效，见 [[web-php-deserialization-wakeup-reference-alias-bypass]]。
- 计数不匹配还可用于让解析器提前结束对象、把剩余字节解释为后续结构（与字符逃逸配合）。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（把该绕过作为 POP 链入口）、[[web-php-deserialization-str-replace-length-lengthening-pop-eval]]（长度/结构错位类技巧）。
- 版本边界：修复后的 PHP 会正常调用 `__wakeup()`，需改用不经 `__wakeup` 的链或其他入口。

## 检测与防御

- 检测：请求参数中出现 `O:` 序列化结构且声明属性数与实际属性数不一致（如 `":3:{` 后只有两组属性）；同一请求包含 `%00类名%00` 形式的私有属性名；反序列化入口附近存在 `__wakeup`/`__destruct` 敏感逻辑。
- 修复：升级 PHP 到 5.6.26 / 7.0.11 及以上；不要对不可信输入使用 `unserialize()`，改用 JSON；必须使用时设置 `allowed_classes` 白名单并校验对象结构。
- 加固：不要在 `__wakeup` 中依赖“重置即安全”，对属性做类型/取值白名单校验；移除魔术方法中的敏感 sink。
