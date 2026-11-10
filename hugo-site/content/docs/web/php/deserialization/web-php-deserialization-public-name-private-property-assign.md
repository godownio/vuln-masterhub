---
id: web-php-deserialization-public-name-private-property-assign
title: PHP 7.1+ 反序列化公有字段名直接赋值 private/protected 属性：免 \x00 前缀构造对象
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-public-name-private-property
tags:
- php
- deserialization
- unserialize
- private-property
- protected-property
- payload-construction
- visibility
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: PHP >= 7.1
verification:
  verified_by: verifier-V372
  verified_at: '2026-11-09T06:03:38+08:00'
  notes: 已对照原文'非公有字段绕过'节：原文明确 PHP7.1+ 公有名写法可忽略 private/protected 访问性并赋值；本地 PHP 7.3.4 复跑 worker 测试 t1/t4，裸名 x/y 分别写入 protected/private 槽（var_dump 显示 private），不存在的 new 生成动态公有属性，与卡一致；versions 按原文标记设为 PHP >= 7.1；原文无图片、无 sources/source_url；dedup recommendation=new(最高 related 0.89 反射改私有属性，机制不同)；dup-scan(11-08)早于建卡；未在 8.x 复测（worker 记录 8.2.9 通过）
url: /docs/web/php/deserialization/web-php-deserialization-public-name-private-property-assign/
draft: false
kb_aliases:
- 非公有字段绕过
- 公有字段名赋值私有属性
- 私有属性绕过
- protected 属性绕过
- 空字节前缀绕过
- visibility bypass
---

## 一句话结论

PHP 7.1+ 的 `unserialize()` 在属性名以“公有字段”格式出现时，会忽略类中同名 `private`/`protected` 字段的访问性，直接把值写入这些字段；因此构造 payload 时不必写出含 NUL 的 `\x00类名\x00字段名` 或 `\x00*\x00字段名`，可绕过禁止空字节/`%00`/`\0` 的过滤，或在无法用 `serialize()` 生成私有字段时手工拼装对象。

## 原理

- **正常序列化命名**：`private` 属性名是 `\x00类名\x00字段名`，`protected` 是 `\x00*\x00字段名`；字符串按字节计长度，NUL 必须原样存在，因此 payload 中通常会出现不可见字节，传输/过滤时容易被拦截或破坏。
- **反序列化的可见性语义**：PHP 7.1 起，`unserialize()` 按属性名匹配对象已声明的属性槽；当传入的名字与声明的 private/protected 属性同名（不带 NUL 前缀）时，会直接写进该属性，而不是创建同名动态公有属性。访问性检查在反序列化路径上不生效。
- **为什么是“绕过”**：很多过滤器只拦 NUL 字节、`%00`、`\0` 转义，或要求 JSON 传输（NUL 会破坏 JSON）；用公有名写法可以完全避开这些字符，同时仍控制私有字段。
- **同名判定**：只有类中确实存在同名声明属性时才会命中私有槽；不存在的属性名会变成普通动态公有属性（原文“其余情况会被强转成字符串”一节的同类行为）。
- **版本边界**：PHP 7.1+；老版本对公有名写法可能只创建动态属性。该语义在 PHP 7.2.9、7.3.4、8.2.9 的最小本地测试中一致成立；PHP 8 未改变该行为。

## 触发条件

- 应用存在用户可控的 `unserialize()` 入口（或 Phar metadata 等触发点），且目标类可被实例化（无 `allowed_classes=false` 或包含该类）。
- 目标类的 private/protected 字段参与危险逻辑（`__destruct`/`__wakeup`/`__toString` 的开关、文件路径、命令等）。
- 入口过滤禁止 NUL 字节、`%00`、`\0` 转义，或 payload 需经 JSON/表单传输，无法携带原始 NUL。
- 目标 PHP ≥ 7.1（按目标版本验证；不同小版本可用 `var_dump` 复核字段归属）。

## 利用步骤

1. 审源码确认目标类名、私有/保护字段名，以及这些字段在魔术方法中控制的分支。
2. 按公有属性格式拼 payload：`O:<类名长度>:"<类名>":<属性数>:{s:<字段名长度>:"<字段名>";<值>;...}`，字段名写裸名，长度按裸名计算。
3. 不再使用 `\x00类名\x00字段名` 形式；若需要同时设置多个字段，逐个写裸名即可。
4. 用同版本 PHP 本地 `var_dump(unserialize($payload))` 确认字段显示为 `private`/`protected` 而不是动态公有属性。
5. 把该对象嵌入 POP 链，触发依赖私有字段的危险分支；若过滤只拦 `O:` 开头，再结合数组嵌套/`C:` 格式等入口绕过。

## PoC

最小语义验证（PHP 7.2.9/7.3.4/8.2.9 均通过）：

```php
<?php
class P {
    protected $x;
    private $y;
    public function dump(){ var_dump($this->x, $this->y); }
}
$o = unserialize('O:1:"P":2:{s:1:"x";s:3:"abc";s:1:"y";s:3:"def";}');
$o->dump();   // string(3) "abc"  string(3) "def"（protected/private 均被赋值）
```

对照：不存在的属性名 `new` 会生成动态公有属性：

```text
O:1:"P":3:{s:1:"x";s:3:"abc";s:1:"y";s:3:"def";s:3:"new";s:3:"dyn";}
```

## 变体与关联

- 变体：属性名同时写裸名与 NUL 前缀（后者用于老版本或强制匹配）；把 private 字段名改成 `protected` 的 `\x00*\x00` 形式；结合属性数绕过（CVE-2016-7124）与提前析构。
- 关联：[[web-php-deserialization-reflection-private-property-payload]]（生成端用反射改私有属性）、[[web-php-deserialization-wakeup-property-count-bypass]]（属性数绕过）、[[web-php-deserialization-premature-destruct-bypass]]（提前析构）。
- 边界：若目标 PHP < 7.1，裸名不会写入私有槽；若类使用了 `__unserialize()`/`Serializable` 自定义解析，属性名语义由自定义代码决定。

## 检测与防御

- **检测**：序列化 payload 中出现“类中私有字段的裸名”而不是 `\x00` 形式；同一入口同时出现 `O:` 结构与私有字段名。
- **防御**：不要用属性可见性作为安全边界；`unserialize()` 使用 `allowed_classes` 白名单，或在入口处强制 JSON/结构校验；对敏感类禁用反序列化（`__serialize`/`__unserialize` 白名单）。
- **注意**：仅过滤 NUL 字节不能阻止本手法；需要按目标类字段名校验整个对象图。
