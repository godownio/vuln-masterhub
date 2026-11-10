---
id: web-php-deserialization-pop-wakeup-tostring-system-rce
title: PHP 反序列化 POP 链：__wakeup→get_flag→对象字符串拼接触发 __toString→system 命令执行
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-chain-wakeup-tostring-system
tags:
- php
- deserialization
- pop-chain
- wakeup
- tostring
- magic-method
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-5
  verified_at: '2026-11-08T01:19:28+08:00'
  notes: 已对照原文核对：A1.__wakeup→A2.get_flag→字符串拼接→A3.__toString→A4.fun→system 链与 payload 中 2025=admin 条件、图01 得 flag 一致；dedup rec=new，related 候选为不同魔术方法链，非同一条利用链；CTF 题无受影响版本标记；PoC 未独立执行
url: /docs/web/php/deserialization/web-php-deserialization-pop-wakeup-tostring-system-rce/
draft: false
kb_aliases:
- PHP 反序列化 POP 链
- __wakeup 触发 get_flag
- 对象拼接字符串触发 __toString
- __toString 转调 fun 执行命令
---

## 一句话结论

当应用对用户可控输入调用 `unserialize()`、且类定义里存在一条由魔术方法串起的调用链时，可构造 `A1→A2→A3→A4` 对象图：反序列化自动触发 `A1::__wakeup()` 调用 `A2::get_flag()`，后者把对象与字符串拼接触发 `A3::__toString()`，进而调用 `A4::fun()`，在额外条件满足时执行 `system("cat ./flag.php")` 读取敏感文件。

## 原理

- `unserialize()` 还原对象时会自动调用该类的 `__wakeup()`（若定义）；把 `A1::$a1` 指向 `A2` 实例，则 `__wakeup()` 内的 `$this->a1->get_flag()` 会调用 `A2::get_flag()`。
- `A2::get_flag()` 中执行 `"flag{" . $this->a2 . "}"`：PHP 把对象当作字符串拼接时会调用其 `__toString()`；把 `$a2` 指向 `A3` 实例即进入 `A3::__toString()`。
- `A3::__toString()` 内 `$this->a3->fun()`；把 `$a3` 指向 `A4` 实例即调用 `A4::fun()`。
- `A4::fun()` 在 `GET` 参数满足 `=== "admin"` 时执行 `system("cat ./flag.php")` 并回显 flag 变量，形成从反序列化入口到命令执行/文件读取的完整链。
- 根因：反序列化会自动调用魔术方法，且应用把用户输入直接交给 `unserialize()`；攻击者通过控制对象属性把若干类的魔术方法按调用关系连成一条链（POP 链），链尾落在危险方法。

## 触发条件

- 存在 `unserialize(用户输入)` 入口，且相关类均已定义/可自动加载；
- 类中存在可被串联的魔术方法（`__wakeup`/`__destruct` 起点、`__toString`/`__call`/`__get` 等中间跳板）；
- 链尾存在命令执行/文件读取等危险方法，其附加条件（如某个 GET 参数取特定值）可满足；
- 未对反序列化数据做类型/类白名单校验。

## 利用步骤

1. 阅读源码，找出 `unserialize` 入口与所有类的魔术方法，倒推一条从入口到危险方法的调用链。
2. 按链反向构造对象：链尾对象 → 中间跳板对象 → 起点对象，逐级把属性指向下一环。
3. 用 PHP `serialize()` 生成序列化串并 URL 编码。
4. 传入 `unserialize` 参数，同时满足链尾附加条件（如 `?2025=admin`）。
5. 从响应/源码注释中取得命令输出或 flag。

## PoC

```php
class A1 { public $a1; }
class A2 { public $a2; }
class A3 { public $a3; }
class A4 { public $a4; }
$a4 = new A4();
$a3 = new A3(); $a3->a3 = $a4;
$a2 = new A2(); $a2->a2 = $a3;
$a1 = new A1(); $a1->a1 = $a2;
echo urlencode(serialize($a1));
```

```text
GET ?wlaq=<urlencode(serialize($a1))>&2025=admin
```

说明：结构复现的通用 POP 链构造，具体类名/条件需按目标源码调整；不访问、不执行。

## 变体与关联

- 起点可换成 `__destruct()`；跳板可换成 `__call`（调用不存在方法）、`__get`（访问不存在属性）、`__invoke` 等。
- 链尾可换成 `file_get_contents`、`include`、写 webshell、`eval` 等任意危险调用；条件判断可用弱比较/其它 GET 参数绕过。
- 关联：[[web-php-deserialization-filter-str-replace-length-escape]]（反序列化字符串逃逸改属性）；PHP 反序列化其它 POP 链卡片。

## 检测与防御

- 检测：代码审计定位 `unserialize(` 接收用户输入；反序列化流量中出现自定义类名与嵌套 `O:` 对象；`__wakeup`/`__toString` 被异常调用、出现 `system`/`cat` 子进程。
- 防御：不要对用户可控数据调用 `unserialize`（改用 JSON）；必须使用时加 `allowed_classes => false` 或严格类白名单。
- 防御：危险方法不放在可被魔术方法间接调用的路径上；对命令执行参数做白名单；部署 PHP 反序列化 RASP/监控。
