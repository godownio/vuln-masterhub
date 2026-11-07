---
id: web-php-deserialization-magic-chain-eval-wakeup-bypass
title: PHP 反序列化魔术方法链：__destruct 起步经 __toString/__get/__call 到 eval，并用属性数绕过 __wakeup
type: scenario
domain: web
path: web/php/deserialization
technique: php-magic-method-pop-chain
aliases:
- 魔术方法 POP 链
- __destruct __toString __get __call 链
- __wakeup 属性数绕过
- Amiya Sakiko Doctor 反序列化
- PHP 序列化对象属性数大于实际
tags:
- php
- deserialization
- pop-chain
- magic-methods
- wakeup-bypass
- eval
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:47:00+08:00'
  notes: 已对照原文源码与图13/14核对：两条链（Amiya::__destruct -> Texas::__toString -> Lappland::__call -> Kaltsit::__invoke 读 /password；Amiya::__destruct -> Sakiko::__toString -> Doctor::__get -> W::__set 校验 md5 后 eval）与卡片一致；md5 原像 Pr0_dont_W@nt_y2u_to_u3e_th1s 与原文一致；Amiya 属性数 3 改 4 的 __wakeup 绕过与原文 exp 一致，卡片注明依赖 PHP 版本。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

当目标把 `unserialize()` 的结果直接暴露，且代码里存在 `__destruct` / `__toString` / `__get` / `__call` / `__invoke` 等魔术方法时，可把对象属性按调用顺序串成链，从一个自动触发的析构函数一路走到 `eval()` 或 `file_get_contents()`；若入口类定义了会覆盖属性的 `__wakeup()`，把序列化串中的属性数写得大于实际属性数即可跳过它。

## 原理

- `__destruct()` 在对象销毁时自动执行，是链的起点；它读取一个不存在的属性或把属性当字符串使用，就会触发 `__get()` 或 `__toString()`。
- `__toString()` 在对象被字符串化时执行；其中访问 `$this->x->y` 可在 `$x` 不存在该属性时触发 `__get()`，调用不存在的方法时触发 `__call()`。
- `__call()` 收到方法名后可取出一个属性作为可调用对象执行 `$func()`，若该属性是实现了 `__invoke()` 的对象，就触发 `__invoke()`；`__invoke()` / `__get()` / `__set()` 中若存在 `eval()`、`file_get_contents()`，链即到达敏感操作。
- 这些方法由 PHP 引擎在语言层自动调用，攻击者只需控制反序列化后的属性指向，不需要目标显式调用任何业务方法。
- `__wakeup()` 会在 `unserialize()` 时自动执行，常被用来把属性重置为安全值。部分 PHP 版本在序列化串声明的属性数量大于实际属性数量时不会调用 `__wakeup()`（CVE-2016-7124 类行为），于是 payload 中把 `O:5:"Amiya":3:` 改成 `O:5:"Amiya":4:`，让声明的属性数比实际多一个，即可保留攻击者设置的属性。是否生效取决于 PHP 版本。

## 触发条件

- 应用存在 `unserialize($_POST[...])` 等直接反序列化用户输入的入口；
- 可用类中至少有一个自动触发的起点（`__destruct` 最常见），并能通过属性引用串联到 `eval`/文件读取等 sink；
- 入口类没有对属性类型/类名做白名单限制，或限制可被上述链绕过；
- 目标 PHP 版本对属性数不匹配时的 `__wakeup` 行为符合上述缺陷（若已修复，则需另找不依赖 `__wakeup` 的起点）。

## 利用步骤

1. 审计源码，列出所有魔术方法及其中的属性访问、方法调用和 sink（`eval`、`include`、`file_get_contents`、命令函数）。
2. 从自动触发点倒推：`__destruct` 读取的属性 → 该属性对象的 `__toString` → 其内部访问触发的 `__get`/`__call` → 最终 sink。
3. 在本地按目标类定义构造对象图，设置属性指向，序列化后检查字符串；
4. 若入口类 `__wakeup()` 会覆盖关键属性，修改序列化串中该类声明的属性计数（+1），使 `__wakeup` 不被调用。
5. 将序列化串作为参数提交，观察 sink 的回显（密码文件、命令输出、flag）。

## PoC

以下为按文章类名构造的链（读文件链）：

```php
$a = new Amiya();
$a->name = new Texas();                       // __destruct 读取 $name，触发 Texas::__toString
$a->name->partner = new Lappland();           // __toString 调 partner->dirve()，触发 __call
$a->name->partner->target = new Kaltsit();    // __call 执行 target()，触发 __invoke
$a->name->partner->target->mon3tr = "Mon3tr is A Cute Cat!";
$tmp = serialize($a);
echo str_replace('Amiya":3:', 'Amiya":4:', $tmp); // 属性数 +1，绕过 __wakeup
```

RCE 链的核心对象图：`Amiya->name = Sakiko`；`Sakiko->mutsumi = Doctor`；`Doctor->sanity = W`；`W->bomb` 设为满足 `md5($bomb) === "50e25b..."` 的原像，`W->wisadel` 设为要执行的 PHP 代码（如 `system('cat /flag');`）。`Amiya::__destruct` 输出 `$name` 触发 `Sakiko::__toString`，其访问 `mutsumi->uika` 触发 `Doctor::__get`，`__get` 的 else 分支写 `sanity->mutsumi` 触发 `W::__set`，`__set` 校验 md5 后执行 `eval($wisadel)`。

## 变体与关联

- 起点变体：`__destruct`、`__wakeup`、`__toString`、`__invoke` 都可作为链头；没有 `__destruct` 时也可利用 `__wakeup` 或反序列化后立即被字符串化的位置。
- sink 变体：`eval`、`assert`、`include`、`call_user_func`、`file_get_contents`、`system`。
- `__wakeup` 绕过依赖版本；在已修复版本上应寻找不经过 `__wakeup` 的链，或利用 `__unserialize`/其他入口。
- 关联：[[web-php-deserialization-compressed-phar-include-bypass]]（Phar 触发反序列化）；[[web-php-rce-seacms-search-template-code-execution]]（PHP 代码执行 sink）。
- 影响边界：本例最终执行任意 PHP 代码并读取 `/password`、`/flag`；在真实目标中可写 WebShell 或回连。

## 检测与防御

- 检测：请求体中出现 `O:`、`s:` 等序列化结构，尤其是属性数与类定义不符（如 `":4:{` 后只有 3 个属性）、类名与业务无关；`unserialize` 调用点附近出现 `eval`/文件读取；Web 进程读取 `/password`、`/flag` 等敏感路径。
- 修复：禁止对用户输入使用 `unserialize`，改用 JSON/显式字段；必须反序列化时使用 `allowed_classes` 白名单并校验属性；删除或收紧魔术方法中的动态调用与 `eval`。
- 缓解：升级 PHP 修复 `__wakeup` 绕过；`disable_functions` 禁用命令执行；Web 进程降权并限制敏感文件权限。
