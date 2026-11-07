---
id: binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor
title: Node.js 原生 vm 沙箱逃逸：this.constructor.constructor 取宿主 process 执行命令
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: nodejs-native-vm-constructor-constructor-escape
tags:
- javascript
- nodejs
- vm
- sandbox-escape
- constructor-constructor
- process-mainmodule
- child-process
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:30:12+08:00'
  notes: 已对照原文与截图核对：vm.createContext + new vm.Script().runInContext 执行用户脚本、this.constructor.constructor 取宿主 Function、Function("return process")() 取 process、process.mainModule.require("child_process").execSync 执行命令的机制与卡片一致；原文在 YApi after_script 中实测 whoami/id/cat 成功。卡片已注明 process.mainModule 在 ESM/新版本可能不可用的边界。未在本机复现。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor/
draft: false
kb_aliases:
- Node.js vm 沙箱逃逸
- vm.createContext 逃逸
- this.constructor.constructor
- process.mainModule.require
- vm.Script 逃逸
- Node.js 内置 vm 不是安全沙箱
---

## 一句话结论

Node.js 内置 `vm` 模块不是安全沙箱：当应用用 `vm.createContext()` + `new vm.Script(userScript).runInContext()` 执行用户可控脚本时，脚本顶层 `this` 指向宿主创建的上下文对象，`this.constructor.constructor` 即宿主的 `Function` 构造器；据此执行 `Function("return process")()` 取回宿主 `process`，再经 `process.mainModule.require("child_process")` 即可执行任意系统命令，并以 Node 进程权限运行。

## 原理

- Node.js 官方文档明确写明 `vm` 模块不是安全机制，不应用于执行不可信代码。`vm` 的目标是提供独立的 JavaScript 上下文用于测试/求值，而不是隔离宿主能力。
- `vm.createContext(contextObject)` 把传入的宿主对象 contextify 为沙箱的全局对象。脚本顶层 `this` 指向该对象；而这个对象本身由宿主 Realm 创建，其 `constructor` 是宿主的 `Object`，`Object.constructor` 是宿主的 `Function`。因此沙箱脚本可以顺着 `this.constructor.constructor` 拿到宿主 Realm 的 `Function` 构造器，而不是沙箱 Realm 的构造器。
- 用宿主 `Function` 构造出的函数在宿主 Realm 求值，`Function("return process")()` 因而返回宿主进程的 `process` 对象。沙箱默认不注入 `process`/`require`，但这一步绕过了“沙箱全局没有 process”的限制。
- `process.mainModule` 指向 CommonJS 主模块，其 `require` 等价于 `Module._load`，可加载 `child_process`、`fs`、`net` 等内置模块。`child_process.execSync(cmd)` 同步执行系统命令并返回 stdout，攻击者因此能直接读取命令输出；若应用会把脚本结果写回响应/日志，就形成稳定的回显通道。
- 关键点不是某个具体 payload，而是“宿主对象跨边界进入沙箱”这一结构：只要沙箱脚本能触达任一宿主创建的对象的 `constructor`，就能回到宿主构造器。原生 `vm` 不提供对 `constructor`/`Function`/原型链的拦截，这与 vm2 等包装层试图做的边界强化不同。

## 触发条件

- 应用对用户可控脚本调用 `vm.runInContext`、`vm.runInNewContext`、`vm.runInThisContext` 或 `new vm.Script(...).runInContext/runInNewContext`，且脚本内容可由低权限用户/攻击者控制。
- 上下文对象由宿主通过 `vm.createContext({...})` 等方式创建（常见写法 `let context = {}; context.request = ...; vm.createContext(context)`），导致宿主对象进入沙箱。
- 应用没有在脚本外做服务端 AST/字符白名单拦截（原生 `vm` 本身不提供），或拦截可被绕过。
- 脚本执行结果可回显（响应体、日志、测试结果）时，命令输出可直接读取；即使不回显，也可通过外连等方式外带。
- `process.mainModule` 可用性取决于入口为 CommonJS 且未被移除；原文环境为 Node 12，验证成功。

## 利用步骤

1. 定位执行用户脚本的 sink：搜索 `vm.createContext`、`new vm.Script`、`runInContext`、`runInNewContext`，确认脚本来源可由低权限用户写入。
2. 确认脚本是否在宿主创建的上下文对象上执行（顶层 `this` 可访问宿主对象属性）。
3. 注入逃逸载荷，先用 `whoami`/`id` 验证命令执行。
4. 将结果写入应用会回显的字段（如脚本上下文的 `responseData`、日志字段），或改用外连通道外带。
5. 替换命令进行读文件、探测内网、反弹 Shell 等后续操作。

## PoC

最小载荷（作为用户脚本的顶层代码执行）：

```javascript
var p = this.constructor.constructor("return process")();
var r = p.mainModule.require("child_process").execSync("id").toString();
```

带回显的版本（适用于把脚本结果写回响应的场景）：

```javascript
try {
  var p = this.constructor.constructor("return process")();
  var r = p.mainModule.require("child_process").execSync("id").toString();
  responseData = { output: r };
} catch (e) {
  responseData = { error: e.message };
}
```

原文在 YApi v1.10.2 的 `after_script` 中实测该载荷，返回 `uid=0(root) gid=0(root) groups=0(root)`，并进一步用 `id && uname -a` 与 `cat /etc/passwd` 验证任意命令执行与输出读取。

## 变体与关联

- 变体（能力放大）：拿到宿主 `Function` 后可执行任意宿主表达式，不限于 `process`；也可直接访问宿主全局对象、模块系统或其他宿主引用。具体可用方式取决于上下文对象暴露了哪些宿主引用。
- 变体（输出通道）：有回显时写 `responseData`/返回值/日志；无回显时用 `child_process` 派生进程或 `net` 模块外连，或写入 Web 可访问路径。
- 边界：`process.mainModule` 在 ESM 入口或部分新版本 Node 中可能不可用；此时需寻找其他宿主能力放大路径，不能假设同一 payload 无条件通用。
- 关联：[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]]（vm2 建立在 `vm` 之上，但逃逸根因是跨 Realm 包装/隐式调用缺口；本卡是原生 `vm` 直接泄漏宿主构造器）。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（vm2 场景，同样以 `process.mainModule.require` 作为能力放大器）。
- 关联：[[web-nodejs-yapi-project-copy-script-vm-unauth-rce]]（本原语在 YApi 中的完整利用链）。
- 关联：[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]、[[binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce]]（同属语言运行时沙箱逃逸，均利用“看似隔离、实则可达宿主能力”的结构）。

## 检测与防御

- 根本防御：不要把进程内 JavaScript 沙箱当作安全边界。对真正不可信的代码，使用独立进程/Worker + 容器或 microVM，并叠加 CPU/内存限额、文件系统权限、网络策略、seccomp/namespace。
- 若必须在进程内执行，使用经过安全审计的隔离方案（如 `isolated-vm`）；vm2 自身也有历史逃逸，需持续升级并跟踪公告。
- 移除或默认关闭用户自定义脚本功能；YApi v1.11.0 加入 `scriptEnable` 并默认 `false` 即是此类收敛。
- 在脚本入口做 AST 白名单只是纵深防御，不能替代进程/容器隔离；不要依赖正则黑名单拦截 `constructor`/`Function`/`process`。
- 以非 root 用户运行 Node.js 进程，限制容器出网、挂载与可写路径，降低逃逸后的影响面。
- 检测：审计代码中的 `vm.createContext`/`new vm.Script`/`runInContext` 及脚本来源；检索用户脚本中的 `constructor.constructor`、`mainModule.require`、`child_process`、`execSync`、`spawn`、`net.Socket` 特征；监控 Node 进程异常派生子进程、测试/表达式接口返回体中的 `uid=`、`root:` 等命令输出特征。
