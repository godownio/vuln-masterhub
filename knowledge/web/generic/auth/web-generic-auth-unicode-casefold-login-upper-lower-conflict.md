---
id: web-generic-auth-unicode-casefold-login-upper-lower-conflict
title: 登录校验同时要求 upper()==大写 且 lower()!=小写：用 Unicode 长 s「ſ」让两个条件同时成立
type: scenario
domain: web
path: web/generic/auth
technique: unicode-casefold-upper-lower-conflict-login-bypass
aliases:
- ſyclover 绕过登录
- 长 s 大小写折叠
- toUpperCase 与 toLowerCase 冲突
- Unicode case folding 认证绕过
- Kelvin sign 绕过
tags:
- unicode
- casefold
- auth-bypass
- javascript
- normalization
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W10
  verified_at: '2026-11-09T04:53:19+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文 escapeSandbox_PLUS 的登录判断为 username.toLowerCase() !== 'syclover' && username.toUpperCase() === 'SYCLOVER' && passwd==='J1rrY'，提交 ſyclover/J1rrY 登录成功，与卡内 U+017F 长 s 折叠分析一致；属 JS/Node 侧 CTF 场景，非某组件版本缺陷，未设受影响版本
---

## 一句话结论

当代码用“用户名转大写必须等于 `SYCLOVER`、且转小写必须不等于 `syclover`”这类**双向大小写比较**来校验时，它假设了“大小写折叠是单射”。Unicode 里存在大小写折叠不闭合的字符——`ſ`（U+017F LATIN SMALL LETTER LONG S）的 `toUpperCase()` 是 `S`，但 `toLowerCase()` 仍是 `ſ`——因此用户名填 `ſyclover` 即可：`toUpperCase()` 得到 `SYCLOVER` 通过第一条件，`toLowerCase()` 得到 `ſyclover` 不等于 `syclover`，绕过第二条件。

## 原理

- **两个条件本意是“排除”**：`if (u.toLowerCase() !== 'syclover' && u.toUpperCase() === 'SYCLOVER' && pass === 'J1rrY')` —— 作者想表达“不是小写的 syclover，但大写后就是 SYCLOVER”，实际是“必须存在非 ASCII 的大小写异常字符”。
- **大小写折叠不是一一映射**：Unicode 里有若干字符的 upper/lower 不对称：`ſ` → `S` → `s`（transitivity 断裂：`'ſ'.toUpperCase()='S'`，`'S'.toLowerCase()='s'`，但 `'ſ'.toLowerCase()='ſ'`）；`K`（开尔文符号 U+212A）`toLowerCase()` 是 `k`；`İ`（U+0130）`toLowerCase()` 是 `i̇`（两码点）；`ẞ`/`ß` 在不同 locale 下不对称。
- **比较的是折叠结果，不是原值**：只要两边的折叠结果满足条件，原字符串可以完全不同；如果没有在折叠前做 `normalize('NFKC')` 或字符白名单，异常字符就直接进入业务。
- **危害取决于后续用途**：本题里它直接构成登录绕过（配合已知口令 `J1rrY`）进入沙箱挑战；在真实系统里，若用户名被用作权限判定、日志审计、下游 SQL/命令拼接，同一技巧可造成“看起来是 A 实际是 B”的账号混淆。

## 触发条件

- 认证/权限判断用 `toUpperCase()`/`toLowerCase()` 比较，且两个方向的条件互相制约（或只用一个方向与白名单比较）。
- 比较前没有 `normalize('NFKC')`、没有正则限制 `^[A-Za-z0-9_]+$`、没有对原值做长度/字符集校验。
- 口令已知或可从其它渠道获得（本卡只解决“身份字符串”绕过）。

## 利用步骤

1. 读源码，定位大小写比较的具体形式（是 `===`、`includes`、还是正则 `i` 标志）。
2. 判断需要满足的条件：本题要求“大写后等于 `SYCLOVER`”且“小写后不等于 `syclover`”。
3. 选一个 upper 折叠到目标大写、但 lower 不回到目标小写的字符：`ſ`(U+017F) → `S`。
4. 提交 `ſyclover` + 正确口令，观察是否登录成功。
5. 若表单/JSON 对非 ASCII 有过滤，尝试 `\u017f` 转义、UTF-8 百分号编码（`%C5%BF`），或换用 `K`(U+212A) 之类其它折叠异常字符。

## PoC

```javascript
// 说明两条件为何同时成立
const u = 'ſyclover';                 // U+017F + yclover
console.log(u.toUpperCase());         // SYCLOVER  -> 第一个条件通过
console.log(u.toLowerCase());         // ſyclover  -> 不等于 'syclover'，第二个条件也通过
```

```http
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=%C5%BFyclover&passwd=J1rrY
```

```text
等价写法（JSON / JS 字符串转义）："username": "\u017fyclover"
```

说明：PoC 依据原文服务端判断语句整理；原文只在浏览器/脚本中验证登录成功，未给出响应原文。

## 变体与关联

- **其它折叠异常字符**：`K`(U+212A)→`k`、`Å`(U+212B)→`å`、`İ`(U+0130)→`i̇`、`ẞ`(U+1E9E)→`ß`；希腊/西里尔字母中也存在同类不对称。
- **比较方式变体**：正则 `/^syclover$/i` 会漏掉 `ſ`（因为 `i` 标志按 Unicode 简单折叠，`ſ` 与 `s` 在多数引擎里其实相等，需实测）；`includes('admin')`、`startsWith` 与折叠组合时同理。
- **其它归一化类绕过**：全角字符（`ａｄｍｉｎ`）在 `NFKC` 后才变成 ASCII、零宽字符（U+200B）绕过子串匹配、土耳其语 `İ/ı` 的 locale 差异（`toLowerCase()` 依赖 locale 时行为不同）。
- **关联**：`web-generic-auth-username-enumeration-timing-lockout`（用户名处理不一致导致的枚举）、`web-golang-golang-idna-ascii-punycode-validation-bypass`（另一语言的 Unicode 归一化校验绕过）。
- **边界**：比较前做 `normalize('NFKC')` + 字符白名单 + 长度校验时失效；如果只比较哈希/数据库里的原值，异常字符会因不匹配而失败（除非数据库排序规则做了折叠）。

## 检测与防御

- **代码层**：身份类字段先 `normalize('NFKC')` 再 `trim()`，并用白名单正则 `^[A-Za-z0-9._-]{1,64}$` 限制；不要用 `toUpperCase()/toLowerCase()` 做权限判定，改用规范化后的**原值全等**比较或 ID。
- **数据层**：用户名/角色在入库时统一小写化并建立唯一约束；数据库中避免使用大小写不敏感的排序规则做权限匹配。
- **审计**：记录并告警包含非 ASCII 字符的用户名，尤其是 `ſ`、`K`、`İ`、全角字母、零宽字符。
- **检测**：登录请求的 username 含 U+017F/U+212A/U+0130 等折叠异常码点，或含 `\u` 转义序列；同一 IP 先用 ASCII 用户名失败、再用近似 Unicode 用户名成功。
