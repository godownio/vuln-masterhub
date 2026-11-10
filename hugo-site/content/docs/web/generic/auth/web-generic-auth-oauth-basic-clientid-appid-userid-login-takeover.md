---
id: web-generic-auth-oauth-basic-clientid-appid-userid-login-takeover
title: 前端 chunk 泄露 OAuth clientId/appId：Basic btoa(clientId:appId) 换 token 后拼 userId 登录参数实现任意用户登录
type: scenario
domain: web
path: web/generic/auth
technique: oauth-basic-frontend-clientid-appid-userid-login-takeover
tags:
- web
- oauth2
- javascript
- information-disclosure
- basic-auth
- idor
- account-takeover
- authorization
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-8
  verified_at: '2026-11-08T01:57:39+08:00'
  notes: 已对照原文核对：JS chunk 泄露 clientId/appId、Authorization=Basic btoa(clientId:appId)、/auth/oauth/token 换 token、登录 URL 拼 userId 四步与原文截图一致；未验证点：原换取 token 的请求以 client_credentials 提交，卡内以 authorization_code 举例（注明等价参数），token 与登录 URL 的实际后端校验未实测
url: /docs/web/generic/auth/web-generic-auth-oauth-basic-clientid-appid-userid-login-takeover/
draft: false
kb_aliases:
- 前端 JS 泄露 clientId appId
- Basic btoa(clientId:appId)
- /auth/oauth/token 硬编码凭证
- 登录 URL 拼接 userId
- OAuth 任意用户登录
---

## 一句话结论

SPA 打包后的 JS chunk 里把 OAuth 客户端的 `clientId` 与 `appId` 以明文配置写死，前端又用 `'Basic ' + btoa(clientId + ':' + appId)` 直接当 `Authorization` 头去请求 `/auth/oauth/token`；攻击者只要照着这段代码在浏览器控制台复算同一个 Base64，就能自己换取合法 token，再把代码里拼接的登录 URL 中的 `&userId=` 改成任意用户 ID，实现任意用户登录并读取姓名、手机号等 PII。

## 原理

- **前端持有 OAuth 客户端凭证**：OAuth2 的 `client_id`/`client_secret` 本应只在服务端之间使用，但 SPA 为了在浏览器里发起授权请求，常把「客户端标识」打包进 JS。本例泄露的是 `clientId` 与 `appId` 两个字段（分别来自 `webpackJsonp` chunk 中的 `platform` 配置数组），它们在运行时被读入变量后仅用于构造 Basic 头，因此前端代码本身就是一份可直接复用的凭证说明书。
- **Basic 头是纯编码而非加密**：`btoa(''.concat(o, ':').concat(c))` 只是把 `clientId:appId` 做 Base64。任何人拿到这两个值就能自己生成 `Authorization: Basic <base64>`，不需要理解客户端流程、不需要逆向签名算法。这也是「前端可见即可用」的典型特征。
- **token 接口没有绑定浏览器上下文**：`POST /auth/oauth/token` 只校验 Basic 头里的客户端身份，配合 `grant_type` 换取 token；它不校验来源域、不校验 PKCE，也没有一次性 nonce。于是「攻击者用 Burp/curl 直接打」与「正常前端打」在服务端看来完全一致。
- **登录环节信任了 URL 参数**：前端 `forward`/登录跳转逻辑把 token 与 `userId` 拼进登录 URL（`.../login?Authorization=<basic>&userId=<id>&url=<ret>`），后端按 `userId` 决定「以谁的身份建立会话」，没有把 URL 里的 `userId` 与 token 所属主体比对。这属于把「我是谁」交给客户端声明，等价于对象级授权缺失。
- **为什么是任意用户登录而不是越权读**：登录接口用 `userId` 直接查库并签发会话，返回该用户的姓名、手机号等资料；攻击者不需要知道密码、不需要短信验证码，只要枚举或猜到目标 `userId` 就能拿到完整会话。

## 触发条件

- 目标为 SPA + OAuth2 的前后端分离架构，前端 JS 中可搜到 `clientId`、`appId`、`client_id`、`oauth/token` 等字符串。
- `/auth/oauth/token` 接受 `Authorization: Basic base64(clientId:appId)`（或 `clientId:clientSecret`），且不校验 PKCE/来源域。
- 登录/跳转 URL 或登录接口接受 `userId` 参数，并以它决定登录身份，不与 token 主体绑定。
- 目标 `userId` 可枚举（连续自增、页面上暴露、或从其他接口/响应泄露）。

## 利用步骤

1. 打开站点，用代理（Burp）记录全部请求；重点看 JS chunk 响应（`webpackJsonp` 形式），全局搜索 `clientId`、`appId`、`oauth`、`token`。
2. 在命中的 chunk 里定位 token 请求代码，读出 `o`/`c` 两个变量的来源（配置文件里的 `clientId`、`appId`）与 `Authorization = 'Basic ' + btoa(o + ':' + c)` 的构造方式。
3. 在浏览器控制台执行 `btoa('<clientId>:<appId>')` 复算同样的值（或本地用 Python `base64.b64encode` 算），确认与请求头一致。
4. 用该 Basic 头请求 `/auth/oauth/token`（按前端代码补 `grant_type`、`code`、`redirect_uri` 等等价参数），拿到 token。
5. 观察前端 `forward` 逻辑拼出的登录 URL，把其中的 `userId` 替换为目标 ID，带上同一条 Basic 头与 token 访问，确认返回该用户的姓名、手机号等资料。
6. 枚举 `userId`（从 1 开始，或先从自己的 ID 推断相邻值），对高价值目标重复第 5 步；控制速率，避免批量拉取真实 PII。

## PoC

```javascript
// 前端 chunk 中的关键片段（变量名随打包结果变化）
var o = /* clientId */ n;
var c = e.appId;
d.Authorization = 'Basic ' + btoa(''.concat(o, ':').concat(c));
d['content-type'] = 'application/x-www-form-urlencoded';
var l = '/auth/oauth/token';
var u = { code: t, grant_type: 'authorization_code', redirect_uri: i };
```

```bash
# 1) 复算 Basic 头
python -c "import base64;print(base64.b64encode(b'<clientId>:<appId>').decode())"

# 2) 用泄露的客户端凭证换取 token
curl -s -X POST "https://target/auth/oauth/token" \
  -H "Authorization: Basic <base64(clientId:appId)>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "grant_type=authorization_code&code=<code>&redirect_uri=<uri>"
```

```text
# 3) 登录 URL 形态（userId 由客户端决定）
GET /auth/login?Authorization=Basic%20<base64>&userId=<目标ID>&url=<回跳地址> HTTP/1.1
Host: target
# 响应 302 并下发会话 Cookie；随后请求用户信息接口返回目标用户的姓名/手机号
```

## 变体与关联

- **凭证字段变体**：也可能是 `client_id`/`client_secret`（前端注释或 `config.js` 残留，见 [[web-generic-auth-oauth-commented-js-client-secret-register-ownerid-admin]]），或 `appId`/`appKey`（小程序包内加密配置，见 [[web-generic-auth-miniprogram-local-config-signature-forgery]]）。
- **授权模式变体**：`authorization_code`、`password`、`client_credentials` 都可能被前端代码使用；`client_credentials` 换出的 token 通常 scope 受限，往往还需要一个系统内账号，参考上述 client_secret 卡。
- **身份参数变体**：登录接口可能用 `userId`、`userid`、`uid`、`loginName`；也可能把身份放在 `X-User-Id` 之类的头里，机制相同（见 [[web-generic-auth-login-header-userid-token-binding-takeover]]）。
- **接口直签变体**：更极端的情况是提供 `getTokenById?userId=` 这类按 ID 直接签发 token 的接口，见 [[web-generic-auth-gettokenbyid-userid-token-issuance]]。
- **关联**：[[pentest-recon-webpack-apiurlkey-endpoint-extraction]]（从前端 chunk 提取接口与硬编码 key 的通用方法）。
- **边界**：`/auth/oauth/token` 若强制 PKCE、绑定 `redirect_uri` 白名单、或校验客户端来源 IP/域，则仅靠泄露的 Basic 头可能换不出 token；登录环节若把 `userId` 从 token 中解析（而不是读 URL 参数），本链直接失效。

## 检测与防御

- **凭证治理**：不要把 `client_secret`、`appId`+`appKey` 这类可用于换取 token 的组合打包进前端；前端只应持有公开的 `client_id`，凭证交换走 BFF（后端代理）。已泄露的立即轮换。
- **协议加固**：对 `authorization_code` 强制 PKCE 并校验 `redirect_uri` 精确白名单；对 `client_credentials` 限制 scope 与来源；token 绑定客户端类型，禁止浏览器端直接调用 token 端点。
- **身份绑定**：登录/会话签发必须从 token 中解析主体，绝不接受 URL 或请求体里的 `userId` 作为「登录谁」的依据；确需切换用户时走单独的、带二次授权的接口。
- **检测（流量）**：同一 `Authorization: Basic` 值在短时间内被多个源 IP/UA 复用；`/auth/oauth/token` 出现非浏览器来源（无 `Origin`/`Sec-Fetch-*`）或参数组合与前端不一致；登录 URL 中 `userId` 高频变化并伴随 302 下会话。
- **检测（静态/构建）**：CI 中对前端产物扫描 `client_secret`、`appSecret`、`Basic ` + `btoa(` 等模式；对 chunk 做敏感字符串基线比对，新增即阻断发布。
- **审计**：对同一账号短时间内来自不同设备/地理位置的会话创建告警；用户信息接口对 `password` 等字段强制脱敏。
