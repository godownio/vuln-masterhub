---
id: web-generic-xss-dom-hash-settimeout-debug-construction
title: DOM-XSS 无回显时的构造：观察法、JS 断点与故意语法错误三路调试定位字符串拼接 sink
type: scenario
domain: web
path: web/generic/xss
technique: dom-xss-hash-settimeout-debug
aliases:
- DOM-XSS 调试
- location.hash setTimeout XSS
- 观察法 XSS
- JS 断点调试 XSS
- 语法错误调试 XSS
- 无输出点 XSS
tags:
- xss
- dom-xss
- javascript
- debugging
- settimeout
- location-hash
- devtools
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V443-fix
  verified_at: '2026-11-09T23:15:53+08:00'
  notes: 'V443 核对指出观察法 PoC 引号方向写反：原文源码为 setTimeout("aa(''"+x+"'')",100)，URL 实测 #'',alert(1),''（单引号），卡内原写双引号 #",alert(1)," 与 aa("",alert(1),"") 无法执行。已把一句话结论/观察法/步骤1-2/PoC 全部改为单引号版本。断点法与语法错误法核对不变。'
---

## 一句话结论

当页面把 `location.hash` 拼进 `setTimeout("aa('"+x+"')",100)` 这类字符串执行 sink 时，传统的"输入字符看输出点"完全看不到回显；必须按运行时 JS 语法分析，用观察法、DevTools 断点或故意制造语法错误三种方式还原拼接后的代码，才能构造出 `',alert(1),'` 这类闭合 payload。

## 原理

- **为什么会"没有输出点"**：source（`location.hash`）读入后只存在于 JS 变量，最终进入 `setTimeout` 的字符串参数被当作代码执行；页面 HTML 里不会出现输入内容，反射型测试方法自然失效。
- **观察法**：直接读源码里的拼接表达式。示例 `setTimeout("aa('"+x+"')",100)`：若 `x = ',alert(1),'`，拼出的字符串是 `aa('',alert(1),'')`，`alert(1)` 作为 `aa` 的第二个实参先被求值，脚本执行；URL 只需 `#',alert(1),'`。
- **断点法**：F12 Sources 在 sink 所在行下断，输入任意字符串后单步执行，观察变量在拼接前后的值、最终传给 `setTimeout` 的完整代码；鼠标悬停变量即可看值。适合代码被压缩/混淆、逻辑复杂的情况，构造时只需保证最终 JS 语法正确。
- **故意语法错误法**：输入特殊字符让页面 JS 解析失败，Console 抛 `SyntaxError`；点击错误堆栈会跳到解析失败的关键函数位置，从而看到自己的输入落在什么语法结构中。示例构造 `#xx');alert(1)//` 让报错暴露上下文，再据此闭合。
- **本质**：DOM-XSS 的 source 可控不代表有回显；必须在浏览器运行时观察"字符串→代码"的拼接点，围绕该点的语法（引号、括号、逗号、注释）构造。

## 触发条件

- 存在 DOM source（`location.hash`/`search`、`document.referrer`、`postMessage` 等）流入字符串执行 sink（`setTimeout`/`setInterval` 字符串参数、`eval`、`Function`、`innerHTML` 等）。
- 无服务端回显，或输入仅存在于 JS 运行时。
- 浏览器可开 DevTools（攻击者本地分析用，不需要目标权限）。

## 利用步骤

1. 查看页面源码/前端 JS，定位 source 到 sink 的拼接表达式（如 `setTimeout("aa('"+x+"')",100)`）。
2. 方法一（观察法）：按表达式手工推导闭合方式，令输入成为合法 JS 表达式的一部分；示例 `',alert(1),'`。
3. 方法二（断点）：在 sink 行下断，输入探测字符串，单步看变量与最终代码，逐步调整至语法正确且含 `alert(1)`。
4. 方法三（语法错误）：输入单引号/括号等破坏语法，读 Console 报错与堆栈定位解析上下文，再按报错位置闭合。
5. 在真实 URL（hash/search）验证执行；若目标有 CSP，确认内联/ eval 是否被限制。

## PoC

```javascript
// 页面源码
var x = location.hash;
function aa(x){}
setTimeout("aa('" + x + "')", 100);

// 观察法 payload（URL）
// http://target/page#',alert(1),'
// 拼接结果：aa('',alert(1),'')  -> alert(1) 先求值

// 语法错误法示例
// http://target/page#xx');alert(1)//
```

## 变体与关联

- 变体：sink 换成 `eval`/`Function`/jQuery `$()`/`innerHTML` 时，同样先还原拼接上下文再构造；`innerHTML` 属 HTML 上下文，需换标签/事件载体。
- 变体：压缩代码可用 Sources 的 Pretty Print 后下断；或用浏览器 Overrides 本地替换 JS 加日志。
- 关联：[[web-generic-xss-double-url-decode-settimeout-sink]]（setTimeout 字符串 sink 的另一条利用路径）；[[web-generic-xss-javascript-context-injection]]（JS 上下文闭合与表达式注入）。

## 检测与防御

- 检测：前端代码审计中搜索 `setTimeout(`/`setInterval(`/`eval(` 的第一个参数为字符串拼接、`location.hash`/`search` 直接参与拼接的模式；CSP 报告 inline/eval 违规。
- 防御：禁止把用户输入拼进字符串执行 sink，改用函数回调 `setTimeout(fn, 100)`；对 hash/search 做白名单校验；启用禁止 `unsafe-eval`/`unsafe-inline` 的 CSP。
