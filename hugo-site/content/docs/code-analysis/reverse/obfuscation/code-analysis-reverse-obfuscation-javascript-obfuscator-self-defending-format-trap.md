---
id: code-analysis-reverse-obfuscation-javascript-obfuscator-self-defending-format-trap
title: JavaScript Obfuscator Self Defending 的格式化陷阱：compact 绑定 + ReDoS 正则与安全分析方式
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: javascript-obfuscator-self-defending-format-trap
tags:
- obfuscation
- javascript
- deobfuscation
- self-defending
- redos
- anti-analysis
- javascript-obfuscator
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:59:39+08:00'
  notes: 已对照原文（无图片）核对：SelfDefendingRule 强制 compact、(((.+)+)+)+$ 对自身源码 search、格式化后 ReDoS、CallsController 一次性门控及 High 级 StatesClass 第二层保护均与原文一致；卡为分析/规避指南，未执行样本
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-javascript-obfuscator-self-defending-format-trap/
draft: false
kb_aliases:
- Self Defending
- 自我保护 格式化死循环
- (((.+)+)+)+$ ReDoS
- javascript-obfuscator 美化卡死
- compact 单行保护
- 冰蝎式 JS 自我保护
---

## 一句话结论

`javascript-obfuscator` 的 Self Defending 会把输出强制为单行 compact，并注入一段用 `(((.+)+)+)+$` 对**自身函数源码**做 `search` 的代码；代码一旦被美化插入换行，`.` 无法跨越换行，嵌套量词触发灾难性回溯，标签页/进程会被长时间占满。分析这类样本时不要直接格式化，应在隔离沙箱中用 AST 工具处理，或先定位并中和该自保护片段。

## 原理

- **强制 compact**：`SelfDefendingRule` 在 `selfDefending: true` 时同时设置 `compact: true`，保证输出是单行；这是自保护生效的前提。
- **自引用检测**：注入的模板形如
  ```javascript
  return _0xSelf.toString().search('(((.+)+)+)+$')
      .toString().constructor(_0xSelf)
      .search('(((.+)+)+)+$');
  ```
  其中 `_0xSelf.toString()` 取得函数自身源码，再对源码做正则搜索。正则 `(((.+)+)+)+$` 有三层嵌套量词；匹配失败时回溯次数随字符串长度指数增长。
- **单行为什么快、美化为什么慢**：单行代码中 `.`（不匹配换行）可以一直匹配到行尾，正则在到达 `$` 时快速成功/失败；美化后源码包含大量换行，`.` 在第一个换行处中断，`(((.+)+)+)+` 会对每个可能的分段反复尝试，产生灾难性回溯，CPU 被打满，表现为“格式化后浏览器卡死/IDE 无响应”。
- **一次性门控**：该片段外层通常由 CallsController 包裹，用闭包布尔值确保只执行一次；因此卡死发生在首次执行，后续不会重复。
- **High 级别的第二层自我保护**：字符串数组取值函数还注入 StatesClass，用 `new RegExp` 对某个函数源码做格式化检测，再根据状态数组与按位取反 `~` 的结果决定是否进入 `push` 驱动的死循环；同样以“代码是否被格式化”为触发条件。即使绕过第一层，格式化仍可能在数组取值阶段再次触发保护。

## 触发条件

- 混淆选项启用 `selfDefending`（Low/Medium/High 预设默认开启或可手动开启）。
- 分析者对代码执行了格式化/美化（Prettier、IDE 自动格式化、DevTools Pretty Print、在线 beautifier）后运行或让工具对格式化结果求值。
- 注入的自保护片段未被删除或替换。
- 分析环境未设置执行超时/资源限制，卡死会持续较长时间。

## 利用步骤

1. **先判断是否存在自保护**：在源码中搜索字符串 `(((.+)+)+)+$`、`selfDefending`、`\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*` 等特征；若存在，禁止格式化。
2. **保持单行处理**：用 `node --check` 做语法检查；用 acorn/esprima/Babel 等 AST 工具直接解析单行源码，避免任何 pretty-print 后再执行。
3. **隔离执行**：在容器/虚拟机中运行，设置 CPU 时间与内存上限（如 `timeout`、cgroup、Node `vm` 的 `timeout`），避免自保护或死循环影响主机。
4. **中和自保护（如确需格式化）**：用 AST 定位包含该正则的 `CallExpression`，把 `search('(((.+)+)+)+$')` 的结果替换为固定常量（保持其后续 `.toString().constructor(...)` 逻辑可运行），或在沙箱中把 `String.prototype.search` 对该正则的调用短路；修改后再格式化。
5. **处理 High 级 StatesClass**：定位 `StateClass` 构造与 `prototype` 上的检测/判断/破坏方法，替换 `new RegExp(...).test(...)` 为固定 `true`（保持正常分支），并移除 `push` 死循环，之后再提取字符串数组。
6. **验证**：格式化后的代码在隔离环境执行，确认行为与原单行样本一致（输出、网络请求、关键常量），记录所有补丁点。

## PoC

```javascript
// 仅做特征检测，不执行有风险的 search
const fs = require('fs');
const src = fs.readFileSync('obfuscated.js', 'utf8');
const markers = [
  '(((.+)+)+)+$',
  '\\x5cw+\\x20*\\x5c(\\x5c)\\x20*{\\x5cw+\\x20*',
  'selfDefending'
];
for (const m of markers) {
  if (src.includes(m)) console.log('[!] self-defending marker:', m);
}
console.log('单行长度:', src.split('\n').length === 1 ? 'compact（保持单行）' : '已包含换行');
```

```javascript
// 安全解析：用 AST 而不是格式化后执行
const acorn = require('acorn');
const ast = acorn.parse(src, { ecmaVersion: 2022, sourceType: 'script' });
// 在 AST 上定位 search/RegExp 调用并打补丁；不要先 pretty-print
```

## 变体与关联

- 仅启用 Disable Console Output 时不会触发本陷阱，但 `console.log/warn/info/error/exception/table/trace` 会被替换为空函数且 `toString` 伪装成原函数，动态调试时不要依赖控制台输出。
- High 级别字符串数组自保护（StatesClass + `~` + 无限 `push`）与本卡同属“格式化触发破坏”，需在数组取值前处理，见 [[code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction]]。
- 调试保护（递归 `debugger` + `setInterval`）是另一种反分析机制，见 [[code-analysis-reverse-obfuscation-javascript-obfuscator-debug-protection-recursive-debugger]]。
- 对未知 JS 样本，通用流程仍是先静态识别保护、再沙箱执行、最后 AST 重构；AI IDE 流程见 [[code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation]]。

## 检测与防御

- 分析侧：把“是否 compact”“是否含 ReDoS 特征正则”作为样本预处理的第一步；任何自动化 beautify 之前先做保护检测。
- 保护侧：Self Defending 只能提高格式化/动态分析成本，无法阻止 AST 解析与运行时插桩；不要把密钥或核心算法只藏在 JS 字符串数组里。
- 运行侧：对不可信 JS 一律使用带超时和资源限制的沙箱，避免自保护/死循环拖垮分析机。
