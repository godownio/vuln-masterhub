---
id: code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction
title: JavaScript Obfuscator v5.3.0 字符串数组提取：底部数组定义、取值函数偏移与洗牌后数组还原
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: javascript-obfuscator-v530-string-array-extraction
tags:
- obfuscation
- javascript
- deobfuscation
- string-array
- javascript-obfuscator
- ast
- reverse-engineering
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T09:59:37+08:00'
  notes: 已对照原文（无图片）核对：v5.3.0 结构顺序、取值函数简化、数组函数自重赋值缓存、洗牌 12 项 parseInt、默认阈值 0.75 均一致；还原思路与原文示例数组（第2项 extend）相符。卡内已提示沙箱执行不可信代码风险，未执行样本
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction/
draft: false
kb_aliases:
- JavaScript Obfuscator v5.3.0
- javascript-obfuscator 字符串数组
- _0x 取值函数还原
- 数组洗牌 IIFE
- 字符串数组阈值 0.75
- JS 混淆版本指纹
---

## 一句话结论

`javascript-obfuscator` v5.3.0 的默认输出把字符串数组定义函数移到了文件底部（依靠函数声明提升仍可调用），取值函数简化为“索引减固定基址后查数组”，并且数组会先经过洗牌 IIFE 重排；在隔离环境执行数组函数与洗牌 IIFE 取得最终数组，再按取值函数的偏移批量替换，即可还原大部分明文字符串。

## 原理

- **结构指纹**：v5.3.0 默认级别的核心结构顺序变为“取值函数 → 洗牌 IIFE → 主体业务代码 → 字符串数组定义函数”。`function` 声明会提升到作用域顶部，所以底部的数组定义函数在顶部取值函数中仍可调用；这种布局打乱了自上而下的阅读顺序，但不改变执行逻辑。
- **取值函数**：v2.9.0 用闭包自重赋值缓存数组；v5.3.0 简化为每次调用都执行 `index = index - <base>; var arr = <arrayFn>(); return arr[index];`。数组函数自身仍保留自重赋值缓存，因此性能影响不大。`<base>` 是每个样本随机生成的十六进制常量（如 `0x142`），必须先读出。
- **洗牌 IIFE**：加载时立即执行，用一组 `parseInt(...)` 运算结果作为停止条件，对数组做旋转/交换；v5.3.0 的默认停止条件从 10 项 `parseInt` 增加到 12 项，使位移量更难手算。因此**不能直接读数组字面量**，必须以运行时最终数组为准。
- **String Array Threshold**：默认值从 0.8 降到 0.75，约 75% 的字符串进入数组，剩余约 25% 保留明文；因此输出中会同时存在 `_0xabc(0x143)` 和直接字符串，不是提取失败。
- **还原方法**：把“数组定义函数 + 洗牌 IIFE + 取值函数”抽到同一个 Node 沙箱里执行（或直接在浏览器控制台执行），打印数组；再把所有 `_0xabc(0xNNN)` 调用按 `index - base` 映射为数组元素。Medium/High 级别的数组元素是 Base64/RC4 密文，还需先调用取值函数内嵌的解码/解密逻辑。

## 触发条件

- 目标为 `javascript-obfuscator` 生成的 JS，关闭或未启用 Debug Protection/Self Defending（否则执行/格式化会卡死，需先处理保护）。
- 样本可在隔离环境运行（Node 或浏览器沙箱），且初始化 IIFE 不依赖浏览器专有对象。
- 能识别取值函数、数组定义函数和洗牌 IIFE 的边界；若被进一步合并/重命名，需要 AST 辅助定位。
- 数组元素为明文或可逆编码（Base64/RC4 密钥可取得）。

## 利用步骤

1. 搜索形如 `function _0xXXXX(_0x..., _0x...){ _0x... = _0x... - 0xNNN; var ... = _0xYYYY(); ... }` 的取值函数，记录其中的固定基址 `0xNNN`。
2. 搜索文件底部 `function _0xYYYY(){ var _0x... = [...]; _0xYYYY = function(){...}; return _0xYYYY(); }` 形式的数组定义函数。
3. 找到紧随其后的洗牌 IIFE（通常是对数组做 `push`/`shift` 的 `(function(a,b){...}(arrayFn, 0x...))`）。
4. 在隔离的 Node 沙箱中按原顺序执行“数组函数 + 洗牌 IIFE + 取值函数”，打印最终数组；不要在未隔离环境直接 `eval` 不可信代码。
5. 用正则枚举源码中的 `_0xXXXX(0xNNN)` 调用，按 `index - base` 取数组元素替换；对无法命中或越界的调用单独记录。
6. 对替换后的代码做语法检查（如 `node --check`），再人工确认控制流与关键常量。

## PoC

```javascript
// 在隔离沙箱中执行：将样本中的三个片段按原顺序拼在一起
const vm = require('vm');
const fs = require('fs');
const src = fs.readFileSync('obfuscated.js', 'utf8');

// 仅示意：实际用 AST 或人工截取 accessorSrc / arrayFnSrc / shuffleSrc
const harness = accessorSrc + '\n' + arrayFnSrc + '\n' + shuffleSrc + '\n' + 'this.__table = _0x427e();';
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(harness, sandbox, { timeout: 3000 });
console.log(sandbox.__table);   // 洗牌后的最终字符串数组

// 批量替换：_0x517b(0x143) -> table[0x143 - 0x142]
const base = 0x142;
const table = sandbox.__table;
const out = src.replace(/\b(_0x[0-9a-f]+)\((0x[0-9a-f]+)\)/gi, (m, fn, hex) => {
  const idx = parseInt(hex, 16) - base;
  return table[idx] !== undefined ? JSON.stringify(table[idx]) : m;
});
fs.writeFileSync('deobf-preview.js', out);
```

```text
v5.3.0 默认输出结构示例：
function _0x517b(i, k) { i = i - 0x142; var a = _0x427e(); return a[i]; }
(function (a, b) { ... }(_0x427e, 0xa7660),
function (x) { ... }(Math));
function _0x427e() { var arr = ['lib','extend',...]; _0x427e = function(){ return arr; }; return _0x427e(); }
```

## 变体与关联

- Low 级别增加 Disable Console Output 与 Self Defending：执行/格式化前先看 [[code-analysis-reverse-obfuscation-javascript-obfuscator-self-defending-format-trap]]。
- Medium 级别数组改为 Base64（自定义字母表），取值函数内含逐字符解码；High 级别改为 RC4，需要从包装器参数中取密钥。
- Medium/High 还引入字符串数组包装器（多参数、只用其中两个）、字符串分割、对象键变换、数字转表达式、控制流平坦化与死代码注入；字符串还原只是第一步，后续还需 AST 重构。
- 已有 AI IDE 辅助解混淆流程见 [[code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation]]；本卡侧重 v5.3.0 默认结构的数组提取与版本指纹。

## 检测与防御

- 防守方（代码保护方）：仅靠字符串数组混淆不足以阻止自动化还原，敏感逻辑应放到服务端或使用 VM/WebAssembly 方案；可开启 Self Defending/Debug Protection 提高动态分析成本，但不能替代服务端校验。
- 分析方：所有样本操作在隔离沙箱进行，限制网络与文件权限；不要直接 `eval` 不可信代码，优先用 AST 截取必要函数。
- 检测混淆器指纹：底部数组定义函数、`_0x` 取值函数、12 项 `parseInt` 洗牌表达式、默认 0.75 阈值可作为版本/级别判断依据。
