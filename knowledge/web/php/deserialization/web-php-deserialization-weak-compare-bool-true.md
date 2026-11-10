---
id: web-php-deserialization-weak-compare-bool-true
title: unserialize 后用 == 弱比较判断键值：布尔 true 与任意非空字符串相等绕过校验
type: scenario
domain: web
path: web/php/deserialization
technique: php-unserialize-loose-comparison-bool-true
aliases:
- PHP 反序列化弱比较绕过
- == 松散比较 true 绕过
- b:1 布尔值绕过 == 判断
- unserialize 数组键值比较
tags:
- php
- deserialization
- loose-comparison
- type-juggling
- weak-typing
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-5
  verified_at: '2026-11-08T01:19:31+08:00'
  notes: 已对照原文核对：shop.php 用 == 弱比较、反序列化数组 b:1 布尔 true 绕过两处字符串比较，与图09 得 flag1 一致；dedup 的 merge 为自命中，其余候选结论不同；CTF 题无受影响版本标记；PoC 未独立执行
---

## 一句话结论

应用把 `unserialize($_GET['buy'])` 的结果当数组，并用 `==` 将其键值与两个目标字符串比较；由于 PHP 松散比较中布尔 `true` 与任意非空字符串相等，构造反序列化数组把两个键都设为 `b:1`（布尔 true），即可让 `$un_buy['onething']==$gift1 && $un_buy['twothing']==$gift2` 同时成立，通过校验输出敏感信息。

## 原理

- PHP 的 `==` 在比较不同类型时会先做类型转换：布尔与其它类型比较时，双方都被转为布尔。任意非空字符串（且非字符串 `"0"`）转为布尔都是 `true`，因此 `true == "xiaomisu7"`、`true == "redmiK60"` 均成立。
- `unserialize()` 支持布尔类型字面量 `b:1;`；序列化数组 `a:2:{s:8:"onething";b:1;s:8:"twothing";b:1;}` 反序列化后得到 `['onething'=>true,'twothing'=>true]`。
- 校验只检查"值是否相等"，没有检查类型是否一致，也没有限定值必须是字符串；攻击者用布尔值即可让两个条件同时为真。
- 若目标变量是未定义/空值（如 include 文件里的变量未赋值得到 null），`true == null` 为 false，此时应改用与目标实际类型匹配的值；但典型题目里目标是普通非空字符串，布尔 true 即通杀。

## 触发条件

- 存在 `unserialize(用户输入)`，反序列化结果被当作数组/对象取值；
- 判断使用 `==`（或 `!=`）而非 `===`，且两侧类型不受约束；
- 目标比较值为非空字符串（或可转换为 true 的值）；
- 通过校验后可获得敏感输出/后续权限。

## 利用步骤

1. 审计源码，确认比较用 `==`、需要满足的键名与目标值类型。
2. 构造数组，把每个待比较键的值设为布尔 `true`。
3. `serialize()` 得到 `a:N:{...;b:1;...}`，URL 编码后传入 `unserialize` 参数。
4. 观察是否通过校验并输出敏感信息。

## PoC

```php
$payload = array("onething" => true, "twothing" => true);
echo urlencode(serialize($payload));
```

```text
?buy=a%3A2%3A%7Bs%3A8%3A%22onething%22%3Bb%3A1%3Bs%3A8%3A%22twothing%22%3Bb%3A1%3B%7D
```

说明：结构复现的通用 payload，键名/数量按目标源码调整；不访问、不执行。

## 变体与关联

- 变体：PHP 8 以前 `0 == "非数字字符串"` 成立（"Magic Hash"/类型杂耍）；`0e` 科学计数法字符串 md5 碰撞（`0e... == 0e...`）；数组与非数组比较等。
- 变体：若目标是数字 0，可用 `false`/空数组/`"0"`；若用 `===`，需改用类/对象注入或调整反序列化结构。
- 关联：[[web-php-deserialization-pop-wakeup-tostring-system-rce]]（反序列化入口）；[[web-php-deserialization-filter-str-replace-length-escape]]（反序列化改属性）。

## 检测与防御

- 检测：代码审计搜索 `unserialize(` 结果参与 `==`/`!=` 比较；请求参数中出现 `b:1;`、`a:` 开头的序列化数组。
- 防御：所有安全判断用 `===`（同时比较类型与值）；对反序列化结果做显式类型校验（如 `is_string`）；优先用 JSON 传递结构化数据。
- 防御：避免对用户输入调用 `unserialize`；必须使用时限制 `allowed_classes` 并对结果做白名单键/类型检查。
