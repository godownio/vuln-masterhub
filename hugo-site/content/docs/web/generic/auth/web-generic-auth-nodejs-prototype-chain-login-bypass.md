---
id: web-generic-auth-nodejs-prototype-chain-login-bypass
title: Node.js 原型链继承键登录绕过：users[用户名] 命中 Object.prototype 方法且省略密码
type: scenario
domain: web
path: web/generic/auth
technique: js-prototype-chain-inherited-key-auth-bypass
tags:
- nodejs
- javascript
- prototype-chain
- auth-bypass
- session
- logic-flaw
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:39:24+08:00'
  notes: 已对照原文与图03-06/09核对：users={} 使 users['isPrototypeOf'] 命中 Object.prototype.isPrototypeOf 函数，user 真值成立、user.password 为 undefined；省略 password 字段使 undefined===undefined，图06 显示进入 if 并设置 session。原文为 justCTF Positive Players CTF，无受影响版本；PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-nodejs-prototype-chain-login-bypass/
draft: false
kb_aliases:
- 原型链登录绕过
- users 对象继承属性登录
- isPrototypeOf 登录绕过
- 省略密码 undefined 比较绕过
- prototype chain auth bypass
- 未注册用户获得 session
---

## 一句话结论

当登录逻辑写成 `const user = users[username]; if (user && user.password === password)`，而 `users` 是普通对象字面量时，攻击者可把用户名设为 `isPrototypeOf`、`hasOwnProperty`、`toString`、`constructor` 等 `Object.prototype` 上的继承键，使 `users[username]` 返回一个真值函数对象；该函数没有 `password` 属性，请求中再完全省略 `password` 字段，两边都是 `undefined`，比较成立，服务端便会为一个从未注册的“用户”签发 session。

## 原理

- `users` 由 `const users = {}` 创建，其原型是 `Object.prototype`。用任意字符串取属性 `users[username]` 时，如果 `users` 没有这个自有属性，JavaScript 会沿原型链继续查找，直到 `Object.prototype` 或 `null`。
- `Object.prototype` 上有一批可枚举或不可枚举的内置成员：`isPrototypeOf`、`hasOwnProperty`、`propertyIsEnumerable`、`toString`、`valueOf`、`toLocaleString`、`constructor`、`__proto__`（访问器）等。把用户名设成其中任何一个，`users[username]` 都会返回对应的函数或对象，于是 `user` 判真通过。
- 该函数对象上并没有 `password` 属性，所以 `user.password` 为 `undefined`。如果请求体完全不带 `password` 字段，`req.body.password` 也是 `undefined`；`undefined === undefined` 为真，绕过了密码校验。
- 关键差别在于“缺失字段”和“空字符串字段”：传 `password=` 会得到 `''`，`'' === undefined` 为假，无法通过；必须整个字段省略。
- 服务端随后执行 `req.session.userId = username`，session 中间件为攻击者创建合法会话。原文中 session secret 是随机生成的，无法伪造 Cookie，但本路径完全不依赖伪造，绕开了 secret。
- 单用这条链只能得到一个“幽灵身份”：`isAuthenticated` 只检查 `req.session.userId` 是否存在，因此能进入受保护路由；但业务路由再取 `users[req.session.userId]` 时拿到的仍是那个函数对象，读取业务字段（如 `themeConfig.theme`）会因 `undefined` 抛错。要拿到最终数据，需要与“污染原型既有属性”的技巧组合，见 `web-nodejs-prototype-pollution-inherited-property-subkey`。

## 触发条件

- Node.js/JavaScript 服务端用普通对象（`{}` 或 `Object.create(Object.prototype)`）充当用户表/映射表。
- 登录/查找用户时直接用不可信输入作属性键：`users[username]`、`map[key]`，没有 `Object.prototype.hasOwnProperty.call(...)` 之类的自有属性校验。
- 后续校验只判断对象真值以及某个字段相等，且缺失字段会得到 `undefined`。
- 密码字段可以被完全省略（表单/JSON 绑定不会把缺失字段补成空串）。
- 用户名没有先做格式白名单（如仅字母数字），否则内置键名会被拒绝。

## 利用步骤

1. 先正常注册一个账号，观察登录请求的字段名与响应，确认用户存储是对象映射且登录只做 `user && user.password === password`。
2. 从 `Object.prototype` 成员中挑一个作为用户名，优先 `isPrototypeOf`（普通函数，后续原型属性污染也常用）；`hasOwnProperty`、`toString`、`constructor` 亦可。
3. 发送登录请求时只提交 `username`，**不提交** `password` 字段。
4. 观察是否 302 跳转首页并拿到 session Cookie；访问一个只校验 `req.session.userId` 的受保护路由，确认已通过认证。
5. 若目标是组合利用，再按关联卡片污染该继承键下的子属性，使 `users[继承键].isAdmin` 等字段变为可控值。

## PoC

最小逻辑复现：

```javascript
const users = {};
// 模拟登录路由
function login(username, password) {
  const user = users[username];
  return !!(user && user.password === password);
}

console.log(login('isPrototypeOf', undefined)); // true
console.log(login('hasOwnProperty', undefined)); // true
console.log(login('constructor', undefined));    // true
console.log(login('isPrototypeOf', ''));          // false —— 空串不行
```

实际请求（Express + `express.urlencoded({extended:true})`）：

```http
POST /login HTTP/1.1
Host: target:3000
Content-Type: application/x-www-form-urlencoded

username=isPrototypeOf
```

响应应为 `302 /` 并下发 session Cookie。注意不要带 `password=`，否则值为空串导致比较失败。

## 变体与关联

- 可用的继承键不止 `isPrototypeOf`：`hasOwnProperty`、`propertyIsEnumerable`、`toLocaleString`、`toString`、`valueOf`、`constructor`、`__proto__` 等都可能命中；具体能否用于后续利用取决于目标代码如何解引用该键。
- 同类缺陷也出现在权限映射（`roles[role]`）、配置查找（`config[key]`）、功能开关（`features[name]`）等一切“用户输入作为对象键 + 未校验自有属性”的查找中。
- 若目标对用户名做了 `typeof user === 'object'` 或 `user instanceof User` 等类型校验，继承函数会被挡住，此路径失效。
- 最终提权组合：用继承键登录后，再把 `users[继承键]` 指向的对象上的子属性污染为管理员标志，详见 `web-nodejs-prototype-pollution-inherited-property-subkey`。
- 与经典原型链污染卡的区别：本卡不需要写入任何原型，只利用原型链的**读取**语义；污染卡利用的是**写入**语义。

## 检测与防御

- 用户表使用 `Object.create(null)` 或 `Map`，从根上消除继承键；若必须用普通对象，查找时强制 `Object.prototype.hasOwnProperty.call(users, username)`。
- 登录校验要求用户名/密码字段存在且为字符串，缺失字段直接拒绝，不要依赖 `undefined === undefined`。
- 对用户名做白名单（长度、字符集），禁止 `__proto__`、`constructor`、`prototype` 及 `Object.prototype` 内置成员名。
- 认证中间件不要只判断 `req.session.userId` 真值，还要确认该 ID 在用户表中是自有记录且用户状态有效。
- 代码审计与运行时检测：搜索 `obj[req.*]`、`obj[userInput]` 形式的查找；监控登录请求中缺失密码字段、用户名为内置对象成员名的异常组合。
