---
id: code-analysis-reverse-obfuscation-javascript-obfuscator-debug-protection-recursive-debugger
title: JavaScript Obfuscator Debug Protection：递归 debugger + setInterval 的识别与绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: javascript-obfuscator-debug-protection-bypass
tags:
- obfuscation
- javascript
- deobfuscation
- anti-debug
- debug-protection
- javascript-obfuscator
- devtools
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:59:42+08:00'
  notes: 已对照原文（无图片）核对：递归 debugger 模板、counter 字符串陷阱、counter % 20、setInterval 4000ms、High 级 RC4 隐藏关键字均一致；绕过建议（不附加调试器、停用断点、不要改 counter）合理，未执行样本
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-javascript-obfuscator-debug-protection-recursive-debugger/
draft: false
kb_aliases:
- Debug Protection
- 递归 debugger 反调试
- Function constructor debugger
- setInterval 反调试
- JS 混淆调试保护
- counter while true 陷阱
---

## 一句话结论

`javascript-obfuscator` 的 Debug Protection 通过 `Function.constructor` 动态生成 `debugger` 语句并递归调用自己，同时用 `setInterval` 每 4 秒重复触发；若分析者把计数器改成字符串，代码会进入 `while (true) {}` 死循环。绕过方式是忽略断点或在不附加调试器的运行时执行（Node、jsdom），而不是去修改 counter。

## 原理

- **递归 debugger 注入**：模板把 `Function` 构造函数当执行器：
  ```javascript
  if (typeof counter === 'string') {
      return (function (arg) {}.constructor('while (true) {}').apply('counter'));
  } else {
      if (('' + counter / counter)['length'] !== 1 || counter % 20 === 0) {
          (function () { return true; }.constructor('debu' + 'gger').call('action'));
      } else {
          (function () { return false; }.constructor('debu' + 'gger').apply('stateObject'));
      }
  }
  ```
  `counter` 每次递归递增，`counter % 20 === 0` 周期性触发 `debugger`；`counter / counter` 的字符串长度用于判断 counter 是否被篡改为非数字。若 `typeof counter === 'string'`，立即执行 `while (true) {}`，标签页卡死。
- **为什么用 `Function` 构造器**：`debugger` 关键字被拆成 `'debu' + 'gger'` 再交给 `Function` 动态编译，静态搜索 `debugger` 可能漏掉；同时 `Function` 构造的代码运行在全局作用域，难以通过局部变量检查定位。
- **定时器持续触发**：`DebugProtectionFunctionIntervalTemplate` 通过 `setInterval(debugProtectionFunctionName, 4000)` 每 4 秒调用一次保护函数；即使某次绕过断点，过几秒又被拉回。
- **High 级别叠加隐藏**：`debugger`、`setInterval` 等关键字本身也会被 RC4 加密进字符串数组，源码中看不到明文；需要先还原字符串表。
- **绕过思路**：`debugger` 语句只有在附加调试器时才会中断，Node 默认不附加 inspector，执行时是空操作；浏览器可在 DevTools 中停用断点（Deactivate breakpoints，Ctrl+F8），或用 `--inspect` 之外的独立运行时执行。不要修改 counter 的类型，否则触发死循环。

## 触发条件

- 混淆选项启用 `debugProtection`（High 预设默认启用，或手动开启）；可配合 `debugProtectionInterval` 定时触发。
- 分析者在浏览器 DevTools 中打开调试器、设置断点或单步执行。
- 代码未做字符串数组还原时，`debugger` 可能以密文形式存在，但运行到保护逻辑仍会生效。
- 运行环境支持 `Function` 构造器与 `setInterval`（浏览器/Node 均可）。

## 利用步骤

1. **静态识别**：搜索 `debugProtection`、`setInterval`、`debu` + `gger`、`while (true) {}`、`counter % 20` 等特征；若字符串数组未还原，先按 [[code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction]] 还原，再定位保护函数。
2. **优先用不附加调试器的运行时**：Node 默认忽略 `debugger`，可用 `timeout 10 node obfuscated.js` 执行并收集行为；浏览器侧用 DevTools 的 Deactivate breakpoints，避免单步进入保护函数。
3. **拦 setInterval**：在加载样本前替换 `setInterval` 为返回假 ID 的空实现（或只允许业务需要的定时器），防止保护函数周期性重入；注意这会影响样本自身的定时逻辑，需在隔离副本中做。
4. **拦截 Function 构造器（可选）**：在沙箱中包装 `Function` 构造器，对包含 `debugger`/`while (true)` 的动态代码返回空函数；仅在确认样本不使用 `Function` 做正常业务时使用。
5. **不要修改 counter**：避免把 counter 改成字符串或对象，否则会走 `while (true) {}` 分支；如必须 patch，直接把 `debugger` 调用替换为 `void 0`，保留 counter 数值逻辑。
6. **验证**：在隔离环境对比 patch 前后的输出/网络请求，确认绕过没有改变业务行为；记录所有 patch 点。

## PoC

```javascript
// 隔离沙箱：屏蔽 setInterval 与动态 debugger 代码（仅用于分析副本）
const vm = require('vm');
const fs = require('fs');
const src = fs.readFileSync('obfuscated.js', 'utf8');

const RealFunction = Function;
function SafeFunction(...args) {
  const body = String(args[args.length - 1] || '');
  if (body.includes('debugger') || body.includes('while (true)')) {
    return function () {};
  }
  return RealFunction(...args);
}

const sandbox = {
  console,
  setInterval: () => 0,
  setTimeout,
  clearInterval: () => {},
  Function: SafeFunction
};
vm.createContext(sandbox);
vm.runInContext(src, sandbox, { timeout: 5000 });
```

```text
浏览器侧：
1. DevTools → Sources → 点击 Deactivate breakpoints（Ctrl+F8），忽略所有 debugger 语句；
2. 不要对保护函数单步/设置断点；
3. 如需阅读源码，先保存副本，在 Node/沙箱中还原字符串表后再静态分析。
```

## 变体与关联

- `debugProtectionInterval` 可调整定时器周期；有的样本会叠加多个保护函数，需逐个识别。
- 字符串表可能被 RC4 加密，先还原字符串才能看到 `debugger`/`setInterval` 明文。
- 通用“定时 debugger”的 DevTools 绕过（Never pause here、条件断点 false、Local Overrides）见 [[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]；动态 `eval`/`Function`/定时器 debugger 的 Hook 拦截见 [[code-analysis-reverse-anti-debug-js-dynamic-debugger-hook]]。本卡补充的是 `javascript-obfuscator` Debug Protection 的具体模板、`counter` 字符串陷阱与 4 秒 `setInterval` 重入特征。
- 与 Self Defending 的格式化陷阱不同：本机制针对“调试”，Self Defending 针对“格式化”，二者可同时启用，见 [[code-analysis-reverse-obfuscation-javascript-obfuscator-self-defending-format-trap]]。
- 通用 JS 解混淆流程见 [[code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation]]；字符串数组提取见 [[code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction]]。

## 检测与防御

- 分析侧：任何不可信 JS 都在无调试器、带超时和资源限制的沙箱中运行；先识别保护再决定是否 patch。
- 保护侧：Debug Protection 只能提高动态调试成本，无法阻止静态读取与 AST 分析；不要把核心算法或密钥仅放在客户端 JS。
- 运行侧：生产环境不需要 `debugger`/反调试逻辑，可在构建时移除；对第三方混淆脚本做完整性校验，防止被替换为恶意版本。
