---
id: web-generic-auth-uppercase-after-filter-dotless-i-admin-bypass
title: 先过滤后 toUpperCase：土耳其无点 ı 大写为 I，注册出 ADMIN 绕过 admin 关键词过滤
type: scenario
domain: web
path: web/generic/auth
technique: filter-before-uppercase-dotless-i-admin-bypass
aliases:
- 土耳其 ı 绕过
- 无点 i 大写绕过
- filter before toUpperCase
- admın 注册 ADMIN
- Unicode 大小写顺序错位
tags:
- unicode
- casefold
- auth-bypass
- filter-bypass
- nodejs
- express
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:18:42+08:00'
  notes: 已对照原文核对：注册处 safeKeyword 用 /(admin)/is 匹配原始值、随后 userid.toUpperCase() 存入 session，admın 大写为 ADMIN 绕过过滤并满足 /action 的 ADMIN 判断，原文图03 Hello,ADMIN 与 /flag 提示一致；原理中 JS 正则 Canonicalize 与 NFKC 说明为补充解释；未实测。
---

## 一句话结论

注册接口先用正则检查原始用户名是否含 `admin`，随后却把 `userid.toUpperCase()` 存入会话/数据库；提交土耳其无点小写 `ı`（U+0131）组成的 `admın`，正则的大小写不敏感匹配不会把非 ASCII 的 `ı` 折叠成 `i`，但 `toUpperCase()` 会把它转换成 `I`，最终保存的值变成 `ADMIN`，从而绕过关键词过滤并满足管理员判断。

## 原理

- 代码里存在两次不同的字符处理：过滤阶段对**原始输入**做关键词匹配（如 `keyword.match(/(admin)/is)`），存储/比较阶段又对同一输入做 `toUpperCase()`。两次处理对 `ı` 的映射结果不同，造成“过滤看到的值”和“实际使用的值”不一致。
- 非 Unicode 模式的 JS 正则大小写不敏感匹配有一个细节：当原字符是非 ASCII 而大写结果是 ASCII 时，Canonicalize 会放弃折叠、保留原字符。因此 `ı`（U+0131）不会被折叠成 `i`，`/admin/i` 不匹配 `admın`；即使用 `/u` 模式，Unicode 简单大小写折叠中 `ı` 也只映射到自身，同样不匹配。
- 但 `String.prototype.toUpperCase()` 使用 Unicode 默认大小写转换（与 locale 无关），`'ı'.toUpperCase()` 的结果就是 `'I'`。于是 `'admın'.toUpperCase() === 'ADMIN'`。
- 如果后续逻辑用大写后的值做权限判断（例如 `if (session.user === 'ADMIN')`、或用大写值写库后再比较），攻击者就得到了一个“过滤时不是 admin、使用时是 ADMIN”的账号。
- 同类字符还有 `ſ`（U+017F，大写为 `S`）等：凡是“过滤字符集/折叠规则”与“后续转换规则”不一致，都可能出现顺序错位绕过。
- 注意：NFKC 归一化不能修复该问题——`ı` 不是 `i` 的兼容变体，归一化后仍是 `ı`；只有 ASCII 白名单或“过滤与使用都基于同一个规范化结果”才能消除差异。

## 触发条件

- 注册/改名/参数校验先用关键词黑名单（正则、includes、startsWith 等）检查原始值，之后又对值做 `toUpperCase()`/`toLowerCase()` 或大小写不敏感比较。
- 两次处理之间没有做 ASCII 白名单、`normalize('NFKC')` 后仍允许非 ASCII 字符，或过滤与使用采用了不同的折叠规则。
- 被转换后的值会用于权限判断、账户名唯一性判断、存储键或下游查询。
- 攻击者能控制输入并进行注册/登录（无需已认证）。

## 利用步骤

1. 读源码/黑盒测试，定位“先过滤、后转换”的链路：过滤函数检查原始值，随后调用 `toUpperCase()` 并用于权限或存储。
2. 确认目标关键词（如 `admin`）和转换方向（大写）。
3. 选取能在大写后变成目标字符、但过滤时不匹配的 Unicode 字符：`ı` → `I`、`ſ` → `S` 等。
4. 构造用户名 `admın`，按表单/JSON 提交；如目标有字符集校验，尝试 UTF-8 原文、`ı` 转义或百分号编码 `%C4%B1`。
5. 注册后登录，访问只有 ADMIN 可访问的接口，确认权限判断使用的是大写值。
6. 若过滤在大写之后也执行一次，或存储前做了 ASCII 白名单，则该路径失效，需要寻找其他顺序错位点。

## PoC

```javascript
// 过滤阶段：非 Unicode 大小写不敏感匹配不会把 ı 折叠成 i
console.log('admın'.match(/admin/is));   // null
// 使用阶段：toUpperCase 使用 Unicode 默认大小写转换
console.log('admın'.toUpperCase());      // 'ADMIN'
```

```http
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

Submit=register&userid=adm%C4%B1n&pwd=<任意口令>
```

```text
# ı 为 U+0131，UTF-8 编码 C4 B1；JSON 等价写法：
{"userid":"admın","pwd":"..."}
```

说明：PoC 依据原文的过滤与 `toUpperCase` 代码路径整理；原文示例中注册后提示 `Hello,ADMIN`，未在本地复跑。

## 变体与关联

- 变体：反向转换（`toLowerCase`）时可用 `İ`（U+0130）等字符；不同语言的大小写规则不同（土耳其语 locale 下 `I` 的小写是 `ı`），需按目标运行时验证。
- 变体：过滤用 `includes`/`startsWith` 而使用阶段用正则 `i` 标志时，同样可能出现两侧折叠规则不一致。
- 关联：[[web-generic-auth-unicode-casefold-login-upper-lower-conflict]]（另一种形态：同一比较里 upper/lower 条件互相制约，用 `ſ` 同时满足）；[[web-java-framework-spring-antpathmatcher-unicode-long-s-case-bypass]]（同一类 Unicode 折叠差异用于路径匹配）；[[web-java-component-h2-cve-2022-23221-forbid-creation-bypass-init-rce]]（`ı`/`ſ` 大写绕过关键字黑名单的组件侧案例）。
- 边界：过滤与使用都在同一规范化结果上执行、强制 ASCII 字符白名单、或权限判断基于用户 ID 而非用户名时失效；`normalize('NFKC')` 不能单独修复 `ı`。

## 检测与防御

- 身份类字段统一做 `normalize('NFKC')` 后，再用 ASCII 白名单正则（如 `^[A-Za-z0-9._-]{1,64}$`）限制；非 ASCII 用户名必须显式拒绝或单独建模。
- 不要用 `toUpperCase()`/`toLowerCase()` 后的值做权限判断或唯一性判断；权限应绑定不可变的用户 ID。
- 过滤逻辑与业务使用必须基于**同一个**规范化后的字符串，避免“过滤原值、使用转换值”。
- 检测：登录/注册请求的 username 含 U+0131、U+017F、U+0130、开尔文符号等折叠异常码点；同一 IP 先用普通用户名失败、再用近似 Unicode 用户名成功；请求中出现 `ı` 等转义序列。
- 审计：记录并告警非 ASCII 用户名，尤其是能大写为 ASCII 关键字的字符组合。
