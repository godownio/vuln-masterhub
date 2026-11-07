---
id: web-nodejs-prototype-pollution-merge-json-parse
title: merge 深合并原型链污染：对象字面量与 JSON.parse 的 __proto__ 差异
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: js-prototype-pollution-merge
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- javascript
- nodejs
- prototype-pollution
- merge
- json-parse
- object-prototype
cve: []
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:35:04+08:00'
  notes: 已对照原文核对 merge 递归、对象字面量 __proto__ 语法设置与 JSON.parse 自有可枚举键差异、o3.b 结果；未验证点：未在本机执行 PoC，原文仅演示 isAdmin/属性继承
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-merge-json-parse/
draft: false
kb_aliases:
- JS 原型链污染
- prototype pollution
- merge 原型链污染
- JSON.parse __proto__
- 深合并污染 Object.prototype
- 原型链继承污染
---

## 一句话结论

当应用把用户可控的 JSON 交给递归深合并函数（merge）时，`__proto__`、`constructor`、`prototype` 这类键会让递归目标从普通对象切换到共享原型，最后一层赋值实际写到 `Object.prototype`；此后创建的所有普通对象都会继承该属性，可用于设置 `isAdmin`、权限标志、配置项等。关键前提是 `__proto__` 必须作为**自有可枚举键**进入 merge，`JSON.parse` 满足这一点，而普通对象字面量不满足。

## 原理

- JavaScript 采用“对象继承对象”的委托式继承：访问属性时先查对象自身，再沿 `__proto__` 指向的原型向上查找，直到 `Object.prototype`，再往上为 `null`。普通对象默认的原型就是 `Object.prototype`，因此对 `Object.prototype` 的写入会影响所有后续对象。
- 典型 merge 实现递归遍历 `source` 的键：值是对象就递归合并到 `target[key]`，否则直接赋值。`key` 完全由输入控制且没有校验。
- 当 `key === "__proto__"` 时，`target["__proto__"]` 返回的是 `target` 的原型对象，而不是一个普通子对象；后续递归和赋值就作用在原型上。类似地，`constructor` 指向构造函数，`prototype` 指向构造函数的原型对象，三者都可作为通向共享原型的路径。
- 关键差异（容易踩坑）：
  - **对象字面量** `{ "__proto__": {b:2} }` 中的 `__proto__` 是**语法级原型设置器**，会把该字面量的原型设为 `{b:2}`，且 `__proto__` 本身不是可枚举自有属性；`for...in` 只看到 `b`，因此 merge 直接写入 `target.b`，不会污染全局原型。
  - **`JSON.parse('{"__proto__":{"b":2}}')`** 把 `__proto__` 当成普通自有可枚举属性创建；`for...in` 能枚举到它，merge 便进入 `target["__proto__"]` 分支，写入共享原型。
- 这正是同一段 merge 代码在“直接传对象”时不生效、在“传 JSON 字符串解析后”时生效的原因：漏洞不在 merge 的语义，而在于它允许用户控制递归路径且不区分普通属性与原型路径。

## 触发条件

- 应用存在递归合并/深拷贝/配置合并逻辑，且合并源可由用户控制（JSON 请求体、配置文件、查询参数解析结果等）。
- 合并源中的 `__proto__`/`constructor`/`prototype` 键未被过滤或未被安全解析器剥离。
- 合并源经过 `JSON.parse`（或等价解析器）生成，使 `__proto__` 成为自有可枚举键。
- 目标属性在后续代码中被读取（权限判断、配置读取、模板渲染、子进程参数等）才会产生实际影响。

## 利用步骤

1. 定位接受 JSON 并做深合并的入口（如 `merge(config, req.body)`、`Object.assign` 的递归封装、配置中心）。
2. 构造含 `__proto__` 的 JSON，使 `for...in` 能枚举到该键。
3. 发送请求触发 merge，污染 `Object.prototype` 上的目标属性。
4. 在后续请求/逻辑中验证该属性是否被所有普通对象继承（如新对象读取到 `isAdmin=true`）。
5. 结合业务读取点提升影响：认证绕过、修改模板/命令参数、覆盖配置开关等。

## PoC

存在漏洞的 merge：

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

对象字面量不触发全局污染：

```javascript
let o1 = {};
let o2 = { a: 1, "__proto__": { b: 2 } };   // __proto__ 是语法级原型设置
merge(o1, o2);
console.log(o1.a, o1.b);   // 1 2
let o3 = {};
console.log(o3.b);         // undefined
```

`JSON.parse` 触发污染：

```javascript
let t = {};
let s = JSON.parse('{"a":1, "__proto__":{"b":2}}');
merge(t, s);
console.log(t.a, t.b);     // 1 2
let o3 = {};
console.log(o3.b);         // 2 —— Object.prototype.b 已被污染
```

实际请求示例：

```json
{"a":1,"__proto__":{"isAdmin":true}}
```

## 变体与关联

- 过滤 `__proto__` 后的绕过（`constructor.prototype`、嵌套键、Unicode 转义、表单参数）见独立卡片。
- 同类 sink 不限于 merge：`Object.assign` 递归封装、lodash `_.merge`/`_.set`、`JSON.parse` + 遍历赋值、查询字符串解析器（qs）都可能成为入口。
- 实际危害取决于被污染属性的读取点：认证标志、模板变量、子进程参数、`env`/`shell` 选项、`NODE_OPTIONS` 等，可进一步链到 RCE。
- 与前端原型链污染（DOM XSS gadget）同源，但本卡聚焦服务端合并逻辑。

## 检测与防御

- 合并前拒绝危险键：对 `__proto__`、`constructor`、`prototype` 做递归键名校验；使用 `Object.create(null)` 或 `Map` 作为容器，避免继承 `Object.prototype`。
- 使用经过修复的库版本；对深合并使用允许键白名单，而不是仅过滤字符串黑名单。
- 解析用户 JSON 后先做规范化，剥离 `__proto__` 自有属性；避免把原始解析结果直接传入通用 merge。
- 代码审计：搜索 `for...in` + 动态 `target[key]` 递归赋值、`_.merge`、`Object.assign` 递归封装等模式。
- 运行时监控：检测请求体中的 `__proto__`/`constructor[prototype]` 键，以及在对象上出现异常继承属性（如 `isAdmin`、`shell`、`env`）的行为。
