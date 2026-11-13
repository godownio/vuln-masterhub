---
id: web-nodejs-express-object-tostring-md5-equal-bypass
title: Express 对象参数 toString 相同：a[x]=1&b[x]=2 让 a!==b 且 md5(a+flag)===md5(b+flag) 同时成立
type: scenario
domain: web
path: web/nodejs
technique: js-object-tostring-concat-hash-bypass
aliases:
- a[x]=1&b[x]=2
- 对象拼接 md5 相等
- '[object Object] 哈希绕过'
- JS 对象 toString 绕过哈希比较
- 对象 length undefined 绕过
- Express 嵌套参数类型混淆
tags:
- nodejs
- express
- javascript
- type-juggling
- md5
- hash-bypass
- qs
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V632
  verified_at: '2026-11-13T00:44:59+08:00'
  notes: 已对照原文12511全文与13张截图核对：原理（qs嵌套对象→ToPrimitive [object Object]、对象无length导致undefined===undefined、两对象引用不等）与原文代码 a.length===b.length && a!==b && md5(a+flag)===md5(b+flag) 及 payload ?a[x]=1&b[x]=2 一致；本机Node复验对象拼接/长度语义通过。dedup最高候选为PHP Error/Exception __toString哈希绕过(cos 0.846)与PHP magic hash，非同链。原文未标注组件版本，affected_versions保持为空。未在真实Express靶场复现。
---

## 一句话结论

当 Node/Express 应用要求“两个参数不相等、长度相等，但它们与同一秘密拼接后的 md5 相等”时，提交 `a[x]=1&b[x]=2` 把两个参数都变成对象即可：`a!==b` 因引用不同恒真，`a.length===b.length` 因对象没有 length 属性变成 `undefined===undefined`，而 `a+flag` 与 `b+flag` 都会把对象字符串化为 `[object Object]flag`，两次 md5 完全相同，校验整体通过。

## 原理

- **参数被解析成对象**：Express 默认 query parser 为 extended（qs），`a[x]=1` 会被解析为嵌套对象 `{ x: '1' }`，`req.query.a` / `req.query.b` 不再是字符串。
- **对象的 ToPrimitive**：JavaScript 的 `+` 在任一操作数为对象时先做 ToPrimitive（default hint）。普通对象没有自定义 `valueOf`/`toString`，最终调用 `Object.prototype.toString`，结果恒为 `"[object Object]"`。因此 `a+flag` 与 `b+flag` 都是 `"[object Object]" + flag`，与对象内部的 `x` 值无关。
- **长度校验被绕过**：普通对象没有 `length` 属性，`a.length` 与 `b.length` 都是 `undefined`，`undefined === undefined` 为 true。
- **不等比较仍成立**：`a` 与 `b` 是两次解析得到的不同对象引用，`a !== b` 为 true。
- 于是形如 `if (a && b && a.length===b.length && a!==b && md5(a+flag)===md5(b+flag))` 的判断全部满足。注意若用数组 `a[]=1&b[]=2`，数组 toString 是元素 join，两个值不同会导致拼出的字符串不同、哈希不等，因此必须用**对象**而不是数组。

## 触发条件

- 参数解析器支持嵌套对象语法（Express 的 extended query parser、body-parser 的 qs、PHP 风格表单解析等），且未限制参数为标量。
- 业务把两个参数与同一秘密字符串拼接后做哈希/签名比较，同时用 `!==`、`length` 做前置校验。
- 比较前没有强制 `typeof === 'string'` 或 `String()` 归一化。

## 利用步骤

1. 从源码/报错确认校验形态：两个查询参数不相等但其与 flag 拼接结果的 md5 相等。
2. 用嵌套参数分别构造两个不同对象，例如 `a[x]=1&b[x]=2`。
3. 发送请求；两个对象字符串化后同为 `[object Object]flag`，md5 相等，返回 flag。

## PoC

服务端校验示意：

```javascript
var a = req.query.a, b = req.query.b;
if (a && b && a.length === b.length && a !== b && md5(a + flag) === md5(b + flag)) {
    res.end(flag);
}
```

请求：

```
GET /?a[x]=1&b[x]=2 HTTP/1.1
Host: target
```

浏览器/REPL 可验证字符串化行为：

```javascript
console.log({x: 1} + 'flag{xxx}');  // [object Object]flag{xxx}
console.log({x: 2} + 'flag{xxx}');  // [object Object]flag{xxx}
```

## 变体与关联

- 若应用使用 simple/querystring 解析器，`a[x]` 不会被解析为对象，可改用 JSON 请求体或表单嵌套字段，使参数仍是对象。
- 其它可稳定字符串化的内建对象（如 `[object Date]`）也能造成同样效果，但可控性与构造难度不同；普通对象是最稳定的选择。
- 同思想不同语言/机制：PHP 中 `a[]=1&b[]=2` 让 `md5(array)` 返回 null 从而实现严格比较绕过，见 [[web-generic-auth-php-md5-array-strict-comparison-bypass]]。
- 关联 [[web-nodejs-js-keyword-regex-string-construction-bypass]]：同属“源码/运行时类型与字符串语义不一致”类绕过。

## 检测与防御

- 校验前强制类型：`typeof a !== 'string'` 直接拒绝，或先 `String(a)` 归一化并禁止对象/数组。
- 使用参数 schema 校验（zod/joi）限定标量为字符串，关闭不必要的嵌套参数解析。
- 不要把用户参数与秘密直接拼接后比较哈希；改用 HMAC 并对输入做类型与长度白名单校验。
- 检测请求中出现 `a[x]=`/`b[x]=` 等嵌套参数与哈希比较接口组合的情况。
