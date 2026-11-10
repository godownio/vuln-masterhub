---
id: ctf-web-eval-char-permutation-post-param-rce
title: eval 前的字符集排列校验被「少一个字母」绕过：用剩余标识符拼出变量函数调用执行 POST 参数
type: scenario
domain: web
path: web/php/rce
technique: eval-charset-permutation-whitelist-identifier-gadget
aliases:
- checkRequiredChars 绕过
- 字符集排列校验
- prohibited.txt 黑名单少一项
- $_POST 变量函数
- eval 参数拼接
tags:
- php
- rce
- eval
- whitelist-bypass
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:53:28+08:00'
  notes: 已对照原文核对；本次核对未读取图片；本篇正文给出 HelloHacker 完整源码（incompetent 校验、checkRequiredChars 九个必需字符、prohibited.txt 逐行 stripos 与「空行且无空格才 continue」）、缺一排列 oxzverapn 与 passthru(hex2bin(...)) payload，卡内字符集/黑名单缺口/无空格三点一致；卡内给出的 $_POST[a]($_POST[b]) 形态出自同赛事另一篇 WriteUp，与本篇 passthru(hex2bin) 是同一绕过的两种写法
---

## 一句话结论

题目用 `checkRequiredChars($WuCup, ['p','e','v','a','n','x','r','o','z'])` 校验输入「包含这些字符」，再用 `prohibited.txt` 做子串黑名单；但黑名单只枚举了这 9 个字母的**排列**而漏掉一个顺序，且没了空格检查之后，`oxzverapn;$_POST["a"]($_POST["b"]);` 既满足字符集又不在黑名单里，`eval` 后就是 `$_POST['a']($_POST['b'])` 任意函数调用。

## 原理

- `checkRequiredChars` 只判断「是否包含每个必需字符」，不限制长度、顺序与其它字符，等价于「必须出现这 9 个字母」的弱约束。
- `prohibited.txt` 是子串黑名单：把危险函数名（`system`、`passthru`…）的字母重排后逐行 `stripos` 比对。黑名单枚举了 `p,e,v,a,n,x,r,o,z` 的大部分排列，却漏掉 `oxzverapn` 这一种，于是这串本身不含任何黑名单子串，还能当合法 PHP 标识符拼接。
- 关键细节：黑名单循环里有一行 `if ($line === '' && strpos($WuCup, ' ') === false) continue;` —— 只有「空行且输入无空格」才跳过；一旦 payload 含空格，空行不再跳过，但 `stripos($WuCup, '')` 对空串恒为 0（`!== false` 成立）会直接 die，所以 payload 必须**不含空格**，用 `;` 分隔语句、用 POST 参数传命令，从而完全避开空格。
- 最终 `eval('oxzverapn;$_POST["a"]($_POST["b"]);')`：`oxzverapn` 是未定义常量（PHP 8 会抛 Error，PHP 7 及以下当字符串 `"oxzverapn"` 并告警但不中断），随后执行变量函数 `$_POST['a']($_POST['b'])`，即 `system('cat /flag')`。

## 触发条件

- 存在 `eval($input)` 且前面只有「字符包含 + 子串黑名单」两类弱校验。
- 黑名单枚举不完整（漏一种排列），且不拦截 `$`、`_`、`;`、`(`、`)`、`[`、`]`、`"`。
- PHP 7.x（`oxzverapn` 作为未定义常量只告警），或 PHP 8 下改用 `('oxzverapn'==0);` 之类可忽略的表达式。

## 利用步骤

1. 访问被禁字符串清单（本例 `prohibited.txt` 可直读），统计它枚举了哪些字母排列、缺哪一种。
2. 用缺失的排列作为开头标识符，`;` 后接 `$_POST['a']($_POST['b'])`，全程不带空格。
3. POST 提交：`incompetent=HelloHacker&WuCup=oxzverapn;$_POST["a"]($_POST["b"]);&a=system&b=cat /flag`。
4. `eval` 执行变量函数，命令回显在响应里。

## PoC

```bash
# 无空格、满足 9 个必需字符、不在黑名单中
curl -s http://target/ -d 'incompetent=HelloHacker' \
     --data-urlencode 'WuCup=oxzverapn;$_POST["a"]($_POST["b"]);' \
     --data-urlencode 'a=system' --data-urlencode 'b=cat /flag'
```

PHP 8 下把开头换成不报错的等价写法（如 `0;` 会缺字符，因此仍用该排列，但改为 `("oxzverapn"=="x");`）：

```text
WuCup=oxzverapn;$_POST["a"]($_POST["b"]);
```

## 变体与关联

- 变体：黑名单换成 `preg_match` 关键字过滤时，可用 `hex2bin`/`base64_decode`/`chr` 拼接绕过函数名；本例另一解法 `passthru(hex2bin("636174202f666c6167"))` 同样不出现 `cat /flag` 明文。
- 变体：字符集校验若要求「恰好包含」可用排列穷举；若要求「只允许这些字符」则改用 `$_POST` 索引拼接、不加引号（PHP 会把裸字符串当常量键）。
- 关联：[[web-php-rce-eval-var-dump-superglobal-variable-function]]（`$_GET` 变量函数型 eval）、[[web-php-rce-blacklist-no-slash-no-redirect-tee-write-webshell]]（黑名单缺口 + 无重定向符写马）。
- 边界：黑名单若完整枚举全部排列、或额外过滤 `$`/`;`，该绕过失效；`disable_functions` 会拦住最终 sink。

## 检测与防御

- 检测：源码里出现 `eval($_POST[...])`/`call_user_func($_GET[...])`；`checkRequiredChars` 这类「含字符」校验；把 `prohibited.txt` 放在 Web 目录可直读。
- 修复：禁止 `eval` 处理用户输入；若必须，用白名单函数表（`in_array($fn, ['strlen',...])`）而非黑名单；把配置文件移出 Web 根目录。
- 加固：`disable_functions` 覆盖 `system/exec/passthru/shell_exec/proc_open/popen`，开启 `open_basedir`。
