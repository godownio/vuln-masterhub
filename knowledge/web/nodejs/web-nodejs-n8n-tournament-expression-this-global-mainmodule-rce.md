---
id: web-nodejs-n8n-tournament-expression-this-global-mainmodule-rce
title: n8n 1.116 tournament 表达式沙箱逃逸：this 绑定全局 + 属性黑名单不全导致 process.mainModule RCE
type: scenario
domain: web
path: web/nodejs
technique: n8n-tournament-expression-this-global-mainmodule-rce
aliases:
- n8n 1.116 表达式注入
- tournament 沙箱逃逸
- FunctionThisSanitizer 绕过
- isSafeObjectProperty 黑名单
- this.process.mainModule
- n8n 表达式 RCE
- '@n8n/tournament'
tags:
- n8n
- nodejs
- tournament
- sandbox-escape
- expression-injection
- rce
- function-constructor
- process-mainmodule
- ast-sanitizer
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: n8n 1.116.0（原文测试版本；对应修复 commit 08f332015153decdda3c37ad4fcb9f7ba13a7c79）
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:07:04+08:00'
  notes: 已对照原文与14图核对：1.116.0环境、this指向全局（图09）、unsafeObjectProperties仅4属性（图12）、补丁FunctionThisSanitizer+mainModule/binding/_load（图10-11）、IIFE执行calc（图14）均一致；已修正isSafeObjectProperty定义在utils.ts而非expression-sandboxing.ts的位置表述。未本机复跑
---

## 一句话结论

n8n 1.116.0 的表达式由 `@n8n/tournament` 编译成函数后调用，表达式里的 `this` 在 n8n 环境下指向全局对象而不是传入的 data；由于 `isSafeObjectProperty` 只把 `__proto__`、`prototype`、`constructor`、`getPrototypeOf` 四个属性列为不安全，`this.process.mainModule` 未被拦截，攻击者用 `this.process.mainModule.require('child_process').exec('calc.exe')` 或立即执行函数即可在 n8n 进程内执行系统命令。

## 原理

- **n8n 表达式编译链**：表达式字段（`{{ ... }}`/`={{ ... }}`）由 tournament 的 `FunctionEvaluator` 处理。`execute()` 调用 `evaluator.evaluate(expr, data)`，`evaluate()` 先 `getFunction(expr)`：`getExpressionCode(expr)` 做 AST 转换与安全检查，得到代码后用 `new Function('E', code + ';')` 编译；最后 `fn.call(data, this.instance.errorHandler)` 执行。
- **this 指向错误**：按设计 `fn.call(data, ...)` 应把 `this` 绑定为传入的 data，表达式里的 `this` 应是工作流数据/上下文。但在 n8n 1.116 的实际运行中，`={{this}}` 显示 `this` 指向 Node 全局对象（含 `process`、`global`、`clearImmediate` 等），而不是 data 代理；原因与 tournament 生成的函数形态/调用方式有关（生成的是箭头函数或不以 `this` 接收 data 的函数，`fn.call` 的 this 绑定没有落到表达式内部的 `this` 上）。这直接把宿主全局暴露给表达式。
- **AST 属性黑名单不全**：n8n 在 `expression-sandboxing.ts` 的 AST 检查里调用 `utils.ts` 的 `isSafeObjectProperty` 检查属性名，`unsafeObjectProperties` 是一个 `Set`，只含 `__proto__`、`prototype`、`constructor`、`getPrototypeOf`。`process`、`mainModule`、`require`、`binding`、`_load` 都不在名单里，因此 `this.process.mainModule` 可以通过检查。
- **process.mainModule 是 CommonJS 后门**：`process.mainModule` 指向 Node 主模块，其 `require` 等价于 `Module._load`，可以加载 `child_process`、`fs`、`net` 等内置模块；`child_process.exec('calc.exe')` 直接在 n8n 进程权限下执行系统命令。即使 `require` 在表达式作用域内不可见，也能从宿主 `process` 上取到。
- **立即执行函数绕过 try/catch 包裹**：tournament 会把表达式放进 `try { ... } catch (e) { E(e, this); }`，直接写语句会作为表达式求值的一部分。用 IIFE 把命令执行包在函数体内：
  `={{(function(){ return this.process.mainModule.require('child_process').exec('calc.exe') })();}}`
  函数被调用时立即执行命令，返回值再交给 tournament 拼接。
- **修复方向**：补丁 commit `08f332015...` 增加了 `FunctionThisSanitizer` 作为 `before` 钩子，并把 `mainModule`、`binding`、`_load` 加入不安全属性；这说明根因是“this 绑定到了全局”加上“黑名单不完整”。黑名单式防御仍可能被新的属性/原型路径绕过（例如 `process.binding`、`module.constructor._load` 等变体）。
- **与旧版 vm2 逃逸的区别**：旧版 n8n（0.211–1.65）表达式在 vm2 中执行，vm2 拦截 `constructor.constructor` 但未移除 `process.mainModule`；本条的 1.116 使用 tournament + AST 属性检查，问题变成 `this` 指向全局与属性黑名单遗漏。两者最终都落到 `process.mainModule.require`，但沙箱实现、版本与修复点不同。

## 触发条件

- 目标为 n8n 1.116.0（或未包含 `FunctionThisSanitizer` + 扩展黑名单的同一版本线）；版本区间需以官方公告/补丁为准。
- 攻击者能创建工作流或编辑节点表达式（拥有工作流创建/修改权限的账号，或已劫持管理员会话）。
- 表达式字段会被求值（Set 节点 Value、Code 节点的表达式参数等），且工作流可被触发执行。
- n8n 以 CommonJS 方式运行，`process.mainModule` 存在；若运行在 ESM/被裁剪的环境，该路径可能不可用。
- 未部署能拦截 `process.mainModule`/`child_process` 的额外运行时防护（如 Node.js permission model、seccomp、EDR）。

## 利用步骤

1. **确认版本**：读取 n8n 版本（登录页/`/rest/settings`/包信息），确认是否为 1.116.0 一类未修复版本。
2. **验证 this 绑定**：在可编辑的表达式字段填 `={{this}}`，观察返回是否包含 `process`、`global` 等全局属性；若 `this` 是 data 代理则此路径不成立。
3. **验证属性检查**：尝试 `={{this.process.mainModule}}`，若返回 Module 对象说明 `mainModule` 未被黑名单拦截。
4. **执行命令**：在表达式字段填入 IIFE：
   ```text
   ={{(function(){ return this.process.mainModule.require('child_process').exec('calc.exe') })();}}
   ```
   保存并执行工作流；Windows 弹出计算器即证明 RCE，Linux 可换成 `id`/`whoami`/`touch /tmp/pwned`。
5. **回显与后续**：`exec` 是异步回调，若需要命令输出可改用 `execSync(...).toString()` 并让表达式返回字符串；随后读取环境变量/配置文件中的数据库与第三方凭据、内网探测、写入持久化或反弹 shell。
6. **修复核对**：对照 commit 08f3320，确认目标是否包含 `FunctionThisSanitizer` 与 `mainModule`/`binding`/`_load` 黑名单；若已包含，尝试其他未列入黑名单的宿主属性/原型链路径验证是否仍有绕过。

## PoC

原文验证的两个表达式（未在本机复跑）：

```text
={{this}}
```

```text
={{(function(){ return this.process.mainModule.require('child_process').exec('calc.exe') })();}}
```

手动验证模块加载：

```text
{{this.process.mainModule.require('child_process').exec('calc.exe');}}
```

原文截图显示：`={{this}}` 返回全局对象（含 `process`、`global`），`isSafeObjectProperty` 的 unsafe 集合只有 4 个属性，最终表达式弹出计算器。

## 变体与关联

- 变体：`execSync` 取回显；用 `process.binding('spawn_sync')` 或 `module.constructor._load('child_process')` 绕过只黑名单 `mainModule` 的修复；用 `this.constructor.constructor('return process')()` 走 Function 构造器；把 payload 拆成多段字符串拼接绕过 AST 字符串匹配。
- 关联：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（旧版 vm2 + CVE-2025-68613，同样落到 `process.mainModule.require`）、[[web-nodejs-n8n-expression-destructuring-constructor-rce-cve-2026-25049]]（解构赋值绕过 AST，影响 <1.123.17/2.x<2.5.2）、[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node.js vm 沙箱逃逸的通用原理）。
- 同平台：[[web-nodejs-n8n-authenticated-execute-command-workflow-rce]]、[[web-nodejs-n8n-object-destructuring-computed-key-ast-bypass]]。

## 检测与防御

- **版本与补丁**：升级到包含 `FunctionThisSanitizer` 与 `mainModule`/`binding`/`_load` 黑名单的 n8n 版本；以官方安全公告的修复版本为准，不要只依赖本文测试版本。
- **运行时隔离**：n8n 进程使用低权限用户运行，容器只挂载必要目录；启用 Node.js permission model（限制 `child_process`/`fs`/网络）或 seccomp/AppArmor；把工作流执行放到独立沙箱/worker。
- **表达式审计**：记录表达式原文与执行结果，对包含 `process`、`mainModule`、`require`、`child_process`、`constructor`、`this` 全局访问的表达式告警；限制可创建工作流的账号。
- **修复思路**：不要只扩充属性黑名单；应修正 `this` 绑定（确保表达式 `this` 指向 data 代理/冻结上下文），并在运行时移除/代理 `process`、`require`、`module` 等宿主能力。
- **检测**：监控 n8n 进程启动 `cmd.exe`/`calc.exe`/`sh`/`bash`、访问 `/etc/passwd`、读取环境变量中的密钥、异常出站连接；结合工作流创建/修改审计定位恶意节点。
