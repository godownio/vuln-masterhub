---
id: ctf-web-ezlog-prototype-inherited-nonce-query-array-traversal
title: 原型链继承 nonce 绕过管理员校验 + Express 同名参数数组/截断路径穿越读文件
type: scenario
domain: ctf
path: ctf/web
technique: prototype-inherited-nonce-query-array-truncation-traversal
tags:
- ctf
- web
- nodejs
- express
- prototype-pollution
- auth-bypass
- type-confusion
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:57+08:00'
  notes: 已对照原文ezlog源码核对：Object.prototype.nonce继承、merge原型污染、Express同名query数组、allowedFile数组lastIndexOf/slice、includes黑名单、length>10截断、path.resolve穿越及9个a+/../../flag+./log脚本均一致。未验证点：PoC未本机复跑；截断行为依赖12个file参数（卡内已说明保留前10个元素）；frontmatter无sources/source_url。
url: /docs/ctf/web/ctf-web-ezlog-prototype-inherited-nonce-query-array-traversal/
draft: false
kb_aliases:
- ezlog
- Object.prototype.nonce
- 原型链继承鉴权绕过
- Express 同名 query 参数
- req.query.file 数组
- 10 字符截断绕过
- path.resolve 穿越
---

## 一句话结论

ezlog 在启动时把随机 nonce 写到 `Object.prototype.nonce`，管理员校验 `isAdmin(name, nonce)` 用 `nonce === Object.prototype.nonce` 比较；攻击者只发送 `{"name":"CTF-ADMIN"}`，`req.body.nonce` 就会沿原型链继承到该值，直接通过认证。随后 `/api/checkfile` 用 `file.includes`/`path.resolve('./'+file)` 处理文件名，利用 Express 对同名 query 参数返回数组的特性：`allowedFile` 看到数组末元素 `.` 与 `log` 通过 `.log` 检查，`file.length>10` 截断去掉 `.`/`log`，`path.resolve` 把数组字符串中的 `/../../flag` 解析成 `/flag`，从而读取任意文件。

## 原理

- **原型链继承鉴权**：Node/Express 的 `req.body` 是普通对象，自身没有 `nonce` 属性时会沿 `__proto__` 查找到 `Object.prototype.nonce`。服务端把 `ADMIN_NONCE` 设为 `Object.prototype.nonce`，本意可能是全局配置，却让所有请求体都“继承”了管理员 nonce；`isAdmin` 只做严格相等比较，不检查属性是否为自有属性/是否来自可信来源。
- **同名 query 参数变数组**：Express 默认 `query parser` 在遇到 `?file=a&file=b` 时把 `req.query.file` 解析为数组，而不是最后一个值。后续代码假定它是字符串，产生类型混淆。
- **`.log` 检查**：`allowedFile(file)` 用 `file.lastIndexOf('.')` 与 `file.slice(lastDot+1)`；数组的 `lastIndexOf('.')` 找到元素 `'.'`，`slice` 得到 `['log']`，`['log'] == 'log'` 通过。
- **黑名单检查**：`file.includes(' ')`/`includes('/')`/`includes('..')` 对数组是“元素严格相等”检查；数组元素 `"/../../flag"` 不等于 `'/'` 或 `'..'`，因此通过。
- **截断**：`file.length > 10` 时 `file.slice(0,10)` 只保留前 10 个元素（9 个 `a` + `"/../../flag"`），丢掉末尾 `'.'`/`'log'`。
- **路径穿越**：`path.resolve('./' + file)` 会把数组 `toString()` 成 `a,a,...,a,/../../flag`；`/..` 作为路径分隔后的段被解析，最终落到 `/flag`，`fs.readFile`/`sendFile` 读出。

## 触发条件

- 应用把敏感配置/权限标志写到 `Object.prototype` 或其它共享原型，且鉴权读取时未检查自有属性。
- 认证接口接受 JSON body，且校验字段可直接从原型继承。
- 文件读取接口对 `req.query.file` 做字符串假设，但 Express 允许多同名参数形成数组。
- 存在扩展名/黑名单/长度截断等字符串检查，可被数组类型混淆绕过。
- 路径拼接使用 `path.resolve('./'+file)` 且未做规范化/白名单。

## 利用步骤

1. 发送 `POST /api/checkfile?file=...`，body `{"name":"CTF-ADMIN"}`（不带 nonce），确认 `isAdmin` 通过（不再返回 403）。
2. 构造 query 参数数组：9 个 `file=a`，再 `file=/../../flag`、`file=.`、`file=log`。
3. 服务端 `allowedFile` 用 `.`/`log` 通过 `.log` 检查，黑名单因数组元素不等于 `'/'`/`'..'` 通过，长度截断丢掉 `.`/`log`。
4. `path.resolve` 把 `/../../flag` 解析到 `/flag`，读取并返回。
5. 若公共靶机已被污染，可用 `/api/pollute` 先污染 `name`/`nonce` 再配合。

## PoC

```python
import requests

r = requests.post(
    "http://target:10010/api/checkfile",
    params=[("file", "a")] * 9 + [("file", "/../../flag"), ("file", "."), ("file", "log")],
    json={"name": "CTF-ADMIN"},
)
print(r.text.strip())
```

可选污染（公共靶机被改时）：

```json
{"constructor": {"prototype": {"nonce": "hacker"}}}
```

## 变体与关联

- `Object.prototype` 上的其他字段（`isAdmin`、`role`、`token`）同样可能被继承；检查 `hasOwnProperty`/`Object.create(null)`。
- Express 的 `qs`/`querystring` 解析器行为不同；`?file[]=...`、重复键、嵌套对象都可能产生数组/对象。
- 截断/扩展名检查可换成 `endsWith`、正则、`path.extname`；数组/对象类型混淆可配合 `toString`/`valueOf`。
- 关联：原型链污染、Express 参数解析、路径穿越、鉴权绕过卡。

## 检测与防御

- 不要把权限/密钥写到 `Object.prototype`；鉴权字段必须来自签名 token/会话，并用 `Object.hasOwn` 校验。
- 对 `req.query` 做类型/形状校验，只接受字符串；使用严格 query parser 或显式数组 schema。
- 文件读取使用规范化后的绝对路径 + 白名单根目录，拒绝 `..`/绝对路径/数组；不要依赖字符串 `includes` 做安全判断。
- 检测：请求体缺少 nonce 却通过管理员校验；同一 query key 重复多次；file 参数为数组；路径解析结果跳出允许目录。
