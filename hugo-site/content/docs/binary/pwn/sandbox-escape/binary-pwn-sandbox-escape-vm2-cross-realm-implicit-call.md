---
id: binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call
title: vm2 跨 Realm 隐式调用逃逸：Error.stack、Proxy、util.inspect 与 Promise 链
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: vm2-cross-realm-implicit-call-escape
tags:
- javascript
- nodejs
- vm2
- sandbox-escape
- cross-realm
- proxy
- error-stack
- promise
- rce
cve:
- CVE-2019-10761
- CVE-2023-29017
- CVE-2023-29199
- CVE-2023-30547
- CVE-2023-32313
- CVE-2023-32314
- CVE-2023-37466
affected_versions: vm2：CVE-2019-10761 <3.6.11；CVE-2023-29017 <3.9.15；CVE-2023-29199 <3.9.16；CVE-2023-30547 <3.9.17；CVE-2023-32313/32314 <3.9.18；CVE-2023-37466 <=3.9.19（3.10.0 修复）；SuppressedError <=3.10.4（3.11.0 修复）
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V25
  verified_at: '2026-11-05T02:56:52+08:00'
  notes: 已对照原文核对：跨 Realm 模型、五要素（Realm/bridge/trap 侧/this与参数/返回值）、Error.stack/prepareStackTrace/CallSite、Proxy、util.inspect、Promise then/catch/finally、constructor.constructor 能力放大，以及 CVE-2019-10761/2023-29017/29199/30547/32313/32314/37466 的抽象机制与版本区间均与原文一致。未验证点：原文为综述性分析，未给出完整可执行逃逸载荷，卡内已明确标注'无完整 PoC'、confidence medium；2026 年 SuppressedError/Error.cause 等仅一句带过，未独立核实；process.mainModule.require 属通用能力放大描述，原文未展开。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call/
draft: false
kb_aliases:
- vm2 沙箱逃逸
- 跨 Realm 对象泄漏
- Error.stack 逃逸
- Error.prepareStackTrace
- util.inspect 逃逸
- Promise handler sanitization bypass
- constructor.constructor 能力放大
- NodeVM builtin 逃逸
---

## 一句话结论

vm2 的进程内沙箱边界不是被某个危险 API 直接打破的，而是被“Guest 控制的对象在 Host 侧被隐式调用”打破的：`toString`/`valueOf`、`Symbol.*`、`Error.stack`/`Error.prepareStackTrace`、`util.inspect`、Promise 的 `then/catch/finally` 会在 Host Realm 中触发 Guest 提供的代码，若 trap 参数、返回值或异常对象没有再次正确 bridge/sanitize，Guest 就能拿到 Host Realm 对象，再用 `constructor.constructor` 等能力放大器逃逸到 `process`/`child_process`。

## 原理

- vm2 建立在 Node.js `vm` 模块之上，用跨边界包装和 Proxy 限制 Guest 访问 Host 对象。安全与否不取决于对象“看起来像什么”，而取决于五件事：对象由哪个 Realm 创建、是否经过 bridge、Proxy Trap 在哪一侧执行、Trap 的 `this`/参数属于哪个 Realm、返回值是否再次经过包装。
- JavaScript 的隐式执行路径极多。`String(obj)` 会走 `ToPrimitive → Symbol.toPrimitive → valueOf/toString → Proxy Trap`；`err.stack` 会进入 V8 的 stack formatting、`Error.prepareStackTrace`、`name`/`message` 转换、CallSite 对象创建。开发者以为只是“读一个字符串”，实际可能在 Host 侧执行 Guest 可控的代码。
- 异常不是普通数据。一个 Error 对象携带原型链、自定义属性、`cause`、`stack`、内部 CallSite 和 Host Realm 对象引用；只把 `Error` 换成 `VMError`、或只清洗 `message`，不代表整张对象图里的 Host 引用都被处理。
- 一旦 Guest 拿到任意 Host Realm 对象，`obj.constructor.constructor` 就得到 Host 的 `Function` 构造器，可执行任意代码；随后通过 `process.mainModule.require('child_process')` 等方式取得宿主能力。因此 `constructor.constructor` 是边界突破后的能力放大器，而不是根因。
- Promise 把攻击面扩展到异步路径：`then/catch/finally` 的 callback、rejection reason、`species`、thenable 都可能绕过只保护同步调用的 sanitizer；即使同步路径修好，异步 reaction 仍可能把 Host 对象带回 Guest。
- `util.inspect`/`console.log` 不是只读操作：对象 inspection 会遍历属性、访问原型、触发自定义 `inspect` 和 Proxy Trap；若 inspection 过程中允许 Guest 影响内部引用或配置对象，就可能破坏隔离假设。

## 触发条件

- 应用使用受影响版本的 vm2/NodeVM 执行不可信 JavaScript。
- Host 代码会隐式处理 Guest 提供的对象：字符串化、日志打印、`util.inspect`、错误格式化/堆栈访问、Promise 回调或异常传递。
- vm2 的 bridge/sanitizer 在某一环存在缺口：trap 参数未包装、返回值未重新 bridge、异常对象清洗不完整、Promise 异步回调未处理。
- 若使用 NodeVM，配置了过宽权限（如 `builtin: ['*']`、`nesting: true`，或开放 `child_process`、`cluster`、`worker_threads`、`vm`、`inspector`、网络/文件系统模块），会直接放大逃逸后果。

## 利用步骤

1. 确认 vm2 版本、Node.js 运行时和 VM/NodeVM 配置（`builtin`、`nesting`、`sandbox`、`compiler` 等）。
2. 找到 Host 会隐式处理 Guest 对象的 API：模板渲染、日志、错误上报、`util.inspect`、`JSON.stringify`、Promise 返回值、`Error.stack` 读取等。
3. 判断对象来源与调用侧：对象属于 Guest/Host 哪个 Realm；Proxy Trap 由谁触发；Trap 的 `thisArg` 和 `args` 来自哪一侧；返回值是否再次包装。
4. 构造 Guest 对象，利用 `toString`/`valueOf`/`Symbol.toPrimitive`/Proxy `apply`/`get` 等在 Host 侧执行代码，尝试让 Trap 参数或异常对象携带 Host 引用回到 Guest。
5. 检查异常路径：触发 Host 侧异常（如栈耗尽产生 Host `RangeError`），观察异常对象的 `stack`、`cause`、原型链或自定义属性是否泄漏 Host 对象。
6. 检查异步路径：通过 Promise 的 `then/catch/finally`、rejection reason、`species`、thenable 触发回调，观察 sanitizer 是否只覆盖同步调用。
7. 拿到 Host 对象后，用 `constructor.constructor` 取得 Host `Function`，再加载 `process`/`child_process` 等模块完成命令执行。

## PoC

原文只给出简化的触发结构，未给出完整的逃逸载荷：

```javascript
const err = new Error();

err.name = {
  toString: new Proxy(() => "", {
    apply(target, thisArg, args) {
      // 研究重点：
      // 谁触发了这个函数？
      // args 来自哪个 Realm？
      // thisArg 属于哪一侧？
    }
  })
};

err.stack;
```

这段代码说明 `err.stack` 的读取会进入 Host 侧 stack formatting，并可能调用 Guest 提供的 `toString`（Proxy `apply` Trap）。实际利用需要在 Trap 中观察/截获 Host 参数或返回值，并把它带回 Guest；原文未提供可直接执行的完整链，故不在此编造。

无完整 PoC（原文未给出）；confidence 标 medium。

## 变体与关联

- 历史演进（同一攻击面的不同阶段）：
  - CVE-2019-10761（<3.6.11）：Guest 递归/栈耗尽产生 Host `RangeError`，异常处理路径泄漏未充分隔离的对象。
  - CVE-2023-29017（<3.9.15）：Host 对象传入 `Error.prepareStackTrace` 后跨边界处理不充分。
  - CVE-2023-29199（<3.9.16）：异常处理与代码转换路径的 sanitization 不完整。
  - CVE-2023-30547（<3.9.17）：异常清洗路径继续暴露边界。
  - CVE-2023-32313（<3.9.18）：`util.inspect` 的 inspection 路径被 Guest 影响。
  - CVE-2023-32314（<3.9.18）：Proxy 与 `Error.stack` 组合，Host 侧格式化触发 Guest Trap。
  - CVE-2023-37466（<=3.9.19，3.10.0 修复）：Promise handler sanitization bypass，攻击面进入异步 reaction。
  - 2026：`SuppressedError`（<=3.10.4，3.11.0 修复）、`Error.cause` 清洗不完整、Promise `.finally()` species、`util.getCallSites()`、Host prototype mutator、NodeVM dangerous builtins。
- 变体：`Symbol.for`/跨 Realm Symbol、`AggregateError.errors`、`Error.cause` 等新增错误语义，都是“异常对象图未深度清洗”的新入口。
- 关联：[[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]、[[binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce]]（同属语言/运行时沙箱逃逸，均利用“安全抽象之外的能力入口”）。
- 关联：[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]（同样利用异常/回溯对象泄漏宿主对象）。
- 边界：vm2 已停止维护，新版本/新运行时仍不断出现新入口；具体 CVE 的可用载荷依赖版本与配置，不能跨版本套用。

## 检测与防御

- 根本防御：不要把进程内 JavaScript 沙箱当作强安全边界。对真正不可信的任意代码，使用独立进程/Worker + 容器或 microVM，并叠加 CPU/内存限额、文件系统权限、网络策略、seccomp/namespace。
- 升级：使用 vm2 3.11.0+ 并持续跟踪官方 Security Advisories；但升级不等于永久安全，新运行时语义会带来新入口。
- 配置：NodeVM 遵循最小权限，禁止 `builtin: ['*']`，按需开放模块；谨慎使用 `nesting: true`；默认禁用 `child_process`、`cluster`、`worker_threads`、`vm`、`inspector`、网络与文件系统模块。
- 异常处理：对 Error 做深度清洗，覆盖 `name`、`message`、`stack`、`cause`、`errors[]`、`suppressed`、自定义属性、原型/构造器；不要只替换错误类型或消息。
- 边界处理：对所有跨边界返回值、Trap 参数、Promise reaction、`util.inspect` 结果再次走 bridge/sanitize；禁止 Host 直接对 Guest 对象做字符串化、日志打印或 inspection。
- 检测：审计代码中的 `err.stack`、`Error.prepareStackTrace`、`util.inspect`、`console.log` 处理 Guest 对象的位置；监控高频 `RangeError`、异常对象异常属性、Promise rejection 中的宿主对象引用；用安全公告版本比对。
