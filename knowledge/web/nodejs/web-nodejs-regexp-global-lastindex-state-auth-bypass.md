---
id: web-nodejs-regexp-global-lastindex-state-auth-bypass
title: 全局正则 lastIndex 状态残留 + TypeError 阻断重建绕过封禁（in 运算符误用）
type: scenario
domain: web
path: web/nodejs
technique: js-regexp-global-lastindex-state-auth-bypass
aliases:
- RegExp lastIndex 绕过
- 全局正则鉴权绕过
- 正则 g 标志状态残留
- in 运算符数组误用
- Node.js 封禁绕过
- lastIndex 锚点失效
tags:
- nodejs
- javascript
- regex
- auth-bypass
- lastindex
- type-confusion
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:28:44+08:00'
  notes: 已对照原文代码与解题脚本核对：banned_users 数组、g 正则、try/catch 重建、非字符串 ban_username 触发 TypeError、两次 /api/flag 请求利用 lastIndex=5 使 ^ 锚点失效，逻辑与 PoC 一致；原文正则顺序为 ^hacker$|^admin$，卡内写成 ^admin$|^hacker$ 不影响结论。未在真实 Node 环境复现。
---

## 一句话结论

把禁止用户名构造成带 `g` 标志的正则 `^admin$|^hacker$` 并在每次请求重建时，只要让重建抛异常被 try/catch 吞掉，正则对象与 `lastIndex` 就会跨请求残留：第一次 `test("admin")` 命中后 `lastIndex` 前移到 5，第二次 `test("admin")` 从位置 5 开始、`^` 锚定失效返回 false，被封禁的用户名即可通过校验；再叠加 `in` 运算符检查数组索引而非值的误用，即可用 admin 登录。

## 原理

- ECMAScript 的 `RegExp.prototype.test` 对带 `g`/`y` 标志的正则维护 `lastIndex`：匹配成功时把它设为本次匹配的结束位置，匹配失败时重置为 0。下一次 `test` 从 `lastIndex` 处开始匹配。
- 应用用 `new RegExp(^hacker$|^admin$, "g")` 做封禁判断，并在每个请求的中间件里重建正则，本意是重置状态；但重建代码包在 `try { build_banned_users_regex() } catch (e) {}` 中。
- 攻击者先用合法的 `/api/ban_user` 把**非字符串**（JSON 对象）push 进 `banned_users`：`if (!ban_username)` 对对象为假、`username === ban_username` 与 `for..of` 严格比较均不相等，对象成功入库。
- 之后每个请求的 `build_banned_users_regex()` 在 `escapeRegExp(username)` 上对对象调用 `.replace`，抛 `TypeError` 被 catch 吞掉，**正则没有被重建**，沿用上一次请求留下的对象与 `lastIndex`。
- 第一次用 `username="admin"` 请求受保护接口：`test("admin")` 命中 `^admin$`，请求被拒，但 `lastIndex` 变为 5。
- 第二次请求：重建仍失败，`test("admin")` 从 index 5 开始，`^` 在非 multiline 模式下只匹配字符串开头，**锚点失效**返回 false，第一层检查通过。
- 第二层 `username in banned_users` 对数组检查的是**索引**（"admin" 不是数组下标），恒为 false，形同虚设；随后 `username in users && users[username] === password` 用内置 admin/admin 通过鉴权。

## 触发条件

- Node.js/浏览器 JavaScript 应用，用带 `g`（或 `y`）标志的 RegExp 对象做多次 `test`，且正则对象可能跨请求复用；
- 正则重建逻辑可被攻击者以异常打断（如对数组元素做字符串操作而没有类型校验），且异常被 try/catch 静默吞掉；
- 封禁/黑名单以数组存储，并用 `in` 运算符判断成员；
- 管理员账号在用户表中存在且密码可猜（CTF 环境 admin/admin）或可注册同名以外的绕过。

## 利用步骤

1. 注册普通用户 `aiwin/test`，登录获得可调用 `/api/ban_user` 的会话。
2. 向 `/api/ban_user` 提交 `ban_username` 为 JSON 对象（如 `{"1":"error"}`）：绕过 `!ban_username`、`===` 与 `for..of` 检查后被 push 进 `banned_users`。
3. 以 `username="admin"` 请求受保护接口（如 `/api/flag`）：第一次被正则命中拒绝，但 `lastIndex` 已前移。
4. 立即再发一次同样的请求：`build` 仍因对象元素抛 TypeError 不重建，`test` 从上次结束位置开始，`^admin$` 失效，进入 `in` 检查（恒 false）与密码校验，成功通过。
5. 第二次请求返回 flag/管理员数据。

## PoC

```python
import requests

url = 'http://target/'
s = requests.Session()
s.post(url + 'api/register', json={"username": "aiwin", "password": "test"})
# 把非字符串塞进 banned_users，使后续 build_banned_users_regex() 抛 TypeError
s.post(url + 'api/ban_user', json={"username": "aiwin", "password": "test", "ban_username": {"1": "error"}})
# 第一次：命中 ^admin$，被拒，但 lastIndex 前移到 5
s.post(url + 'api/flag', json={"username": "admin", "password": "admin"})
# 第二次：正则未重建，lastIndex=5 起步，锚点失效 → 通过
r = s.post(url + 'api/flag', json={"username": "admin", "password": "admin"})
print(r.text)
```

## 变体与关联

- 变体：任何跨请求复用的 `g`/`y` 正则（WAF 关键字黑名单、路径白名单）都可能有同类状态残留；`exec()` 同样维护 `lastIndex`。
- 变体：若无法打断重建，可寻找其他让同一正则被连续 `test` 两次的路径（如一个请求内先校验后使用）。
- 关联：未锚定正则鉴权绕过 [[web-generic-auth-unauth-koa-middleware-regex-query-bypass]]（缺失 `^$`）；原型链污染 [[web-nodejs-prototype-pollution]]（同属 JS 语义/类型混淆类）；`in` 运算符对数组的误用是独立代码缺陷，可在审计中单独标注。

## 检测与防御

- 检测：代码审查中搜索 `new RegExp(..., 'g')` 后直接 `.test(` 的用法、`in` 用于数组的写法、以及吞异常的正则重建逻辑。
- 防御：封禁判断用 `Array.prototype.includes`/`Set.has` 而非 `in`；对 `ban_username` 做严格类型与格式校验；不要用带 `g` 的正则执行一次性 `test`（或用 `.match`、去掉 `g`、每次匹配前手动 `lastIndex = 0`）；异常不要静默吞掉，重建失败时应拒绝请求（fail-closed）。
