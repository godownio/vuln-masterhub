---
id: web-php-rce-preg-replace-e-modifier-case-insensitive-blacklist-bypass
title: preg_replace /e 修饰符把替换串当 PHP 执行，配合不区分大小写的自过滤绕过
type: scenario
domain: web
path: web/php/rce
technique: preg-replace-e-modifier-subject-pattern-case-bypass-code-exec
aliases:
- preg_replace /e 代码执行
- e 修饰符 RCE
- please_give_me_flag
- 正则忽略大小写绕过关键字过滤
- 替换串当代码执行
- print(file_get_contents()) 读文件
tags:
- php
- preg-replace
- e-modifier
- code-execution
- rce
- filter-bypass
- case-insensitive
- ctf
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:50:35+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。问题：利用步骤称 shell_exec 不在本题黑名单内属错误——task 黑名单含 exec 且 preg_match 带 /i，shell_exec 会被拦。其余（strlen==19、subject 检查无 i 而执行正则带 i、print(file_get_contents("\x2f...")) 绕 flag/echo/空格/点号）与正文一致。
---

## 一句话结论

`preg_replace("/pattern/ei", $用户输入, $用户输入)` 里 `/e` 会让替换串 `replacement` 先被 `eval` 成 PHP 代码，而匹配串 `subject` 由攻击者控制；如果前面的黑名单是用**不带 `i`** 的 `preg_match` 拦关键字、正则却带了 `i`，那只要把关键字写成大小写混合（`please_give_me_flaG`）就能同时满足「正则命中」和「黑名单不命中」，从而执行任意 PHP。

## 原理

- **`/e` 修饰符的语义**：PHP 5.x 的 `preg_replace` 支持 `e`（PREG_REPLACE_EVAL），它把 `replacement` 字符串当作 PHP 代码求值，用求值结果替换匹配到的内容。代码执行发生在**替换阶段**，前提是 `pattern` 在 `subject` 里找到了匹配——没有匹配就没有求值。
- **两个用户输入各司其职**：本题 `pattern` 固定为 `"/please_give_me_flag/ei"`，`replacement = $_POST['task']`（要执行的代码），`subject = $_POST['flag']`（触发匹配的文本）。因此 `subject` 必须包含 `please_give_me_flag` 的大小写任意组合。
- **过滤逻辑的不对称**：入口用 `preg_match('/please_give_me_flag/', $str2)`（**无 `i`**）检查 subject，否则直接 `die('hacker!')`。但 `pattern` 带 `i`，`please_give_me_flaG` 对黑名单不匹配（有一个大写 `G`），对 `/please_give_me_flag/i` 却匹配成功——过滤器与执行器对同一字符串给出相反判定，这是整个绕过的核心。
- **`strlen` 锁长度**：subject 长度被限制为 19，恰好等于 `please_give_me_flag` 的长度，所以只能在大小写上做文章，不能追加字符。
- **task 侧黑名单**：`system|eval|assert|call|create|preg|sort|{|}|filter|exec|passthru|proc|open|echo|`| 空格|`.`|include|require|flag` 被拦。因此不能用 `system()`、不能有空格和点号、不能出现 `flag`。`print(file_get_contents(...))` 绕开 `echo`（`print` 不在黑名单）与 `system`，路径用十六进制转义 `\x2f\x66\x6c\x61\x67` 表达 `/flag`，从而避开 `flag` 关键字与引号内可见路径。
- **为什么用 `print` 而不是别的**：`print` 是语言结构而非函数，不在黑名单；`file_get_contents` 读文件直接输出内容，构成完整回显链。
- **版本前提**：`/e` 修饰符在 PHP 7.0 起被移除并发出 `Deprecated`，PHP 7 之后该写法直接报错，属于 PHP 5.x 时代漏洞。

## 触发条件

- 目标使用 PHP 5.x（`/e` 修饰符仍可用），代码中出现 `preg_replace` 且 `pattern` 带 `e`。
- `replacement`（或被替换的变量）来自用户输入；同时 `subject` 也可控，或至少包含能命中 `pattern` 的内容。
- 前置黑名单与 `pattern` 的大小写敏感性不一致（一处有 `i`、一处没有），或黑名单本身可被等价写法绕过。
- 存在读取目标文件/执行命令所需函数未被过滤（本题 `file_get_contents`、`print` 均可用）。

## 利用步骤

1. 读源码确认三点：`preg_replace` 的 `pattern` 带 `e`；`replacement` 与 `subject` 都是用户输入；入口检查与执行用的正则大小写敏感性是否一致。
2. 让 `subject` 命中带 `i` 的正则、又躲开不带 `i` 的黑名单：把关键字最后一个字母改成大写，长度保持不变（19）。
3. 构造 `replacement`：避开 `system/eval/exec/echo/空格/点号/flag` 等黑名单词，用 `print(file_get_contents(...))` 这类不在名单里的组合。
4. 路径中的关键字与分隔符用十六进制转义写出，避免明文命中黑名单。
5. POST 提交，若页面回显文件内容则链打通；命令执行场景可换成 `print(shell_exec(...))` 等等价写法（注意 `shell_exec` 不在本题黑名单内）。
6. 若 `subject` 长度被固定，先用 `strlen` 反推允许的构造空间，只在大小写/等价字符上变形。

## PoC

```http
GET /?moran=flag HTTP/1.1

POST /?moran=flag HTTP/1.1
Content-Type: application/x-www-form-urlencoded

flag=please_give_me_flaG&task=print(file_get_contents("\x2f\x66\x6c\x61\x67"));
```

```text
预期：subject（please_give_me_flaG）不命中无 i 的黑名单、命中 /please_give_me_flag/i，
replacement 被 eval 后执行 print(file_get_contents("/flag"))，页面直接输出 flag 内容。
```

## 变体与关联

- 变体（大小写绕过）：任何「过滤用 `preg_match` 无 `i`、执行用带 `i` 的正则」或反之的组合都能这样打；同理可用 `%00` 截断、双重写关键字等手法绕过自身黑名单。
- 变体（replacement 侧）：`assert`、`create_function`、`call_user_func`、`preg_replace_callback` 回调等被点名拦截时，改用 `print`/`printf`/`var_dump`/`include` 的等价读文件或回显组合；无空格时用 `\x20`、`${IFS}`、`$IFS` 等替代（限命令拼接场景）。
- 变体（subject 侧）：`subject` 不可控时，可以把 `replacement` 里塞入能被 `pattern` 匹配的内容，或用 `\0` 让替换在空串上发生（取决于实现）。
- 关联：[[web-php-rce-eval-expression-closing-paren-injection]]（同为「用户输入进入 eval 语义」的表达式注入）、[[web-php-rce-create-function-callback-gadget]]（被禁函数后的等价回显函数选择）。
- 边界：PHP 7+ 无 `/e`，该原语失效；若 `pattern` 不带 `e`，即使 `subject` 可控也只是普通替换，不构成代码执行。

## 检测与防御

- 代码修复：删除 `e` 修饰符，改用 `preg_replace_callback` 并在回调中显式调用允许的函数；不要对 `replacement` 做「过滤黑名单」式修补。
- 输入校验：黑名单与执行正则必须使用同一套规范化（统一大小写、统一编码），更好的是白名单字符集；任何允许「用户输入即代码」的参数都应视为设计缺陷。
- 运行时缓解：升级到 PHP 7+ 并禁用 `create_function`；`disable_functions` 收敛 `system/exec/shell_exec/passthru/popen/proc_open`；`open_basedir` 限制可读路径。
- 检测：日志中出现 `please_give_me_` 类关键字的异常大小写变体、`\x2f`/`\x66` 十六进制转义路径、`print(file_get_contents` 等特征串；同一 IP 先 GET 探路再 POST 提交大小写混合关键字的行为。
