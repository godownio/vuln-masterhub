---
id: web-php-deserialization-wakeup-throw-still-destruct
title: __wakeup 里抛异常也拦不住反序列化：异常展开后对象析构仍执行 __destruct，静态标志位绕过第一轮分支直接进 sink
type: scenario
domain: web
path: web/php/deserialization
technique: php-wakeup-throw-destruct-still-runs
tags:
- php
- deserialization
- magic-method
- wakeup
- destruct
- pop-chain
- ctf
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:51:32+08:00'
  notes: 已对照原文核对；本次核对未读取图片；__wakeup 直接 throw、__destruct 两轮循环里 aaa[1](aaa[2]) 变量函数 sink、入口 code 参数 base64(serialize) 均与正文一致，但「静态属性 bbb 出现在 serialize 串里、可被反序列化赋成 true」不成立（PHP serialize 不包含 static 属性）；正文 exp 同时塞了 aaa['object']='phpinfo'，真实链条是第一轮 call_user_func(phpinfo) 返回 true 赋给 bbb、第二轮才执行 system，卡内标题/原理/步骤基于「静态标志位可控」需据此更正
url: /docs/web/php/deserialization/web-php-deserialization-wakeup-throw-still-destruct/
draft: false
kb_aliases:
- __wakeup 抛异常绕过
- wakeup throw 仍触发 destruct
- 反序列化异常后析构
- static 标志位控制 destruct 分支
- aaa[1]($aaa[2]) 变量函数
---

## 一句话结论

入口是 `unserialize(base64_decode($_GET['code']))`，而类里 `__wakeup()` 直接 `throw new Exception("You're banned to serialize pop!")`，看似把反序列化堵死；但 PHP 在 `unserialize` 抛异常时会**销毁已创建的对象**，`__destruct()` 照样执行——只要把 `__destruct` 的分支条件（本例 `static $bbb`）在序列化数据里设成期望值，析构就会走到 `$this->aaa[1]($this->aaa[2])` 这个变量函数调用，直接把数组里塞的 `system`/命令执行掉。

## 原理

- `__wakeup()` 在 `unserialize()` 完成对象图重建后触发，`throw` 只会中断 `unserialize()` 的返回，并不会撤销已经构造好的对象；对象引用计数归零后 PHP 仍走正常析构流程，因此 `__destruct()` 必然执行。
- 于是「在 `__wakeup` 里阻止反序列化」是**无效防护**：它既没有拒绝对象创建，也没有阻止属性赋值；攻击者要做的只是让 `__destruct` 本身可用。
- 本例 `__destruct` 有个两轮循环：第一轮 `if (self::$bbb)` 为假时执行 `self::$bbb = call_user_func($this->aaa["object"]);`（把 `phpinfo` 之类当“无害”默认路径），第二轮 `$bbb` 为真才执行 `$this->aaa[1]($this->aaa[2])`。攻击者把 `PopClass::$bbb` 反序列化成 `true`（静态属性同样出现在序列化串里，PHP 会直接赋值），第一轮就跳过“安全分支”，立刻走到真正 sink。
- `$this->aaa[1]($this->aaa[2])` 是 PHP 的「数组元素当函数名」语法：`aaa[1] = "system"`、`aaa[2] = "cat /*"` 即 `system("cat /*")`，属于无需 `eval` 的直接命令执行原语。

## 触发条件

- 存在 `unserialize()` 且输入可控（本例 GET 参数 base64 解码后直接反序列化）。
- 目标类有 `__destruct()`（或其它自动触发魔术方法），其内部存在可控变量函数/回调 sink。
- `__wakeup()` 通过 `throw`/`exit` 之外的软手段“防护”，或虽有 `throw` 但未在析构链路上做校验。
- 静态属性可被序列化数据赋值（`static` 属性在 `serialize()` 输出中正常出现）。

## 利用步骤

1. 读源码，确认 `__wakeup` 只是 `throw`、`__destruct` 里有变量函数 sink，且分支条件由静态/实例属性控制。
2. 本地定义同名类，把静态标志位设为让析构走 sink 的那一支（本例 `static $bbb = true`）。
3. 把 sink 的函数名与参数塞进对应数组下标（`aaa[1]`、`aaa[2]`）。
4. `serialize` 后 base64 编码，作为 `code` 参数提交；异常导致的 500/报错不影响析构已执行。
5. 把命令从 `cat /*` 换成读 flag 的实际路径，或先 `system('id')` 确认。

## PoC

```php
<?php
class pop
{
    public $aaa;
    public static $bbb = true;      // 关键：让 __destruct 第一轮就走 $this->aaa[1]($this->aaa[2])
}

$p = new pop();
$p->aaa[1] = "system";              // 变量函数名
$p->aaa[2] = "cat /flag";           // 参数
echo base64_encode(serialize($p));
```

```text
GET /index.php?code=<base64(上面的 serialize 输出)>
```

（`__wakeup` 抛出的异常只会让响应 500，对象析构依旧执行 `system("cat /flag")`；base64 串需用上面的 PHP 片段在本地生成，勿照抄他处。）

## 变体与关联

- 对照：本卡与「提前析构（fast destruct）」类技巧的关键差别在于——本卡不需要畸形串、重复键或私有属性名长度错位，序列化数据完全合法，`__wakeup` 也正常被调用，只是它的 `throw` 拦不住随后必然发生的析构；真正决定成败的是 `__destruct` 内部的分支条件（`static $bbb`）是否被数据改成「直接走 sink」。
- 变体：`__wakeup` 里用 `exit`/`die` 才能真阻断（但仍可在 `__destruct` 前被 `register_shutdown_function` 之类利用）。
- 变体：属性个数不匹配（`O:3:"pop":2:` 改为 3）可让 `__wakeup` 压根不被调用（PHP < 7.4.23 的 CVE-2016-7124 行为），是另一种“绕过 wakeup”的路径。
- 关联：[[web-php-deserialization-premature-destruct-bypass]]（用畸形串/重复键把 `__destruct` 提到 `__wakeup` 与 `exit`/`throw` 之前，与本卡「合法串 + throw 后仍析构」互为对照）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（属性个数绕过 `__wakeup` 后串魔术方法链）、[[ctf-pwn-cpp-exception-catch-hidden-shell]]（同为「异常路径带出隐藏执行」的跨语言对照）。
- 边界：`unserialize` 使用 `allowed_classes` 白名单、或 `__destruct` 中做了属性类型校验时，链不成立；PHP 8 对静态属性序列化行为一致，但若类被 `final` 且 sink 被移除则失效。

## 检测与防御

- 检测：同时出现 `unserialize(` 与 `__destruct` 内的 `$var()`/`call_user_func`；把 `throw` 当作反序列化防护的写法应视为缺陷。
- 修复：`unserialize($s, ['allowed_classes' => false|[...]])` 白名单；改用 JSON；`__destruct` 内不要执行任何依赖属性的动态调用。
- 加固：`disable_functions` 拦截 `system/exec/passthru/shell_exec`；对反序列化入口加签名校验（HMAC）后再反序列化。
