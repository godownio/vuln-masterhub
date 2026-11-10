---
id: web-generic-auth-unauth-get-create-endpoint-error-param
title: 未授权 GET create 接口：报错“项目名称不能为空”暴露必填字段，补 name 参数即创建业务对象
type: scenario
domain: web
path: web/generic/auth
technique: unauth-create-endpoint-error-param
aliases:
- 未授权创建项目
- create 接口未鉴权
- 报错补参创建对象
- GET create 写接口
- 项目名称不能为空
tags:
- web
- auth
- broken-access-control
- unauth
- api
- create
- error-message
- src
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:44:49+08:00'
  notes: 已对照原文 content.md 与 18 张图片核对：img02 createUser{userId,userName,email}、img03 /web/home/search 返回 userId+phoneNumber、img04/05 logic1/loadUser 返回 communityPhone、img16 /api/user/cert/certs 返回 verifier 邮箱+realName+idCardNum、img14 /api/enterprise/certs 返回 verifier+contactName+contactPhone、img01 JS chunk 内嵌 name/nickname/email；未授权链 img06 GET /project/create 报项目名称不能为空→img15 补 name=test 返回 UUID succ:true→img13 /milestone/projects 列表可见 name=test，均与 PoC 一致。两卡技术原子独立（关联对象过返 PII / 未授权 GET create 写对象），判粒度合格；dedup 除自身外无 duplicate/likely_duplicate（resume 下载脱敏、user/all 未授权、参数枚举身份证等均为不同触发）。未验证点：接口域名/路径原文打码，未在目标复测。
---

## 一句话结论

前端 JS 暴露的 `/project/create` 接口没有服务端鉴权，直接请求返回业务错误“项目名称不能为空”；按错误提示补上 `name` 参数（甚至用 GET）后返回新对象 UUID 且 `succ:true`，随后在项目列表接口中能看到刚创建的项目——攻击者未登录即可在系统内创建业务对象。

## 原理

- **create 接口默认“只有登录用户会调”**：开发把创建入口放在登录后的前端页面，后端没有对 `/project/create` 做认证/授权检查，导致直接请求即可到达业务逻辑。
- **错误消息泄露必填字段**：空请求返回 `{"code":"1002","succ":false,"message":"项目名称不能为空"}`，直接告诉攻击者需要“项目名称”；按中文语义猜英文参数名 `name`，补上后成功。
- **GET 被用于状态变更**：接口接受 GET 查询串传参（`/project/create?name=test`），没有限制为 POST，也没有 CSRF Token/来源校验；这使浏览器地址栏、爬虫、图片标签等都能触发创建，扩大了攻击面（与 CSRF 同源风险）。
- **写操作有可见副作用**：响应返回新项目 UUID（`6ac36cea-...`），随后 `/milestone/projects` 列表中出现 `{"name":"test","milestones":[],"errors":["缺少进度信息"]}`，证明对象真实落库，不是空响应。
- **危害边界**：单次创建本身危害较低（原文厂商评为低危），但可用于污染数据、占用配额/项目名、探测内部业务逻辑，或结合后续 update/delete 接口扩大影响；如果 create 接口还接受 `ownerId`、`role` 等批量赋值字段，可能进一步提权。

## 触发条件

- 目标前端 JS 暴露 create/新增类接口路径，且服务端未做认证/授权。
- 接口对缺少参数返回具体业务错误（中文/英文字段名），可据此推断必填参数。
- 接口接受 GET 或未校验 CSRF/来源；参数名可猜（“项目名称”→`name`）。
- 存在可读取的列表/详情接口验证对象是否创建成功。

## 利用步骤

1. 从前端 JS/网络请求中提取 create 类接口路径（`/project/create`、`/xxx/add`、`/xxx/save`）。
2. 直接请求（不带 Cookie 或带低权限 Cookie），观察响应：若返回“XX不能为空”等业务错误，说明请求已进入业务层。
3. 按错误语义猜参数名并补参（`name=test`），分别尝试 GET/POST、form-urlencoded/JSON。
4. 观察响应是否返回对象 ID/UUID 与 `succ:true`。
5. 调用列表/详情接口确认对象存在，记录名称、ID、创建时间等证据。
6. 测试参数扩展：`ownerId`、`tenantId`、`status`、`role` 等批量赋值字段；测试同名/重复创建与删除接口，评估影响范围。
7. 仅在授权范围内操作，创建测试对象后按需清理。

## PoC

```http
GET /<app>/project/create HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"code":"1002","succ":false,"message":"项目名称不能为空"}
```

```http
GET /<app>/project/create?name=test HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"result":"6ac36cea-f7df-48fd-b885-38addf410ff0","succ":true}
```

```http
GET /<app>/milestone/projects HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"result":{"projects":[{"name":"test","milestones":[],"errors":["缺少进度信息"]}],"today":"...","succ":true}}
```

原文接口路径与域名打码，以上按截图还原；PoC 未在目标执行。

## 变体与关联

- 变体：同一个 create 接口改用 POST JSON 提交；或参数名与中文提示不一致时，结合报错迭代猜参（见 [[pentest-recon-error-driven-api-param-discovery]]）。
- 变体：未授权 create 用户/管理员/租户对象，可能直接导致账号接管或越权，参见 [[web-generic-auth-unauth-user-create-admin-takeover]]、[[web-generic-auth-eis-userinfo-asmx-unauth-user-create]]。
- 变体：GET 写操作可被 CSRF 利用（诱导已登录用户点击链接/加载图片即创建对象），参见 CSRF 相关卡。
- 关联：[[web-generic-auth-js-api-discovery-unauth-pii-mass-export]]——同用前端 JS 发现接口，但该卡目标是未授权读 PII；本草稿是未授权写/创建业务对象。
- 边界：接口有统一认证过滤器、仅接受 POST+CSRF Token、错误信息统一为“参数错误”、参数名不可猜或需要签名时，本手法不成立。

## 检测与防御

- 检测：未登录/低权限请求命中 create/add/save 类接口；响应中出现“XX不能为空”后紧跟同一接口带参请求；短时间创建大量同名/异常对象。
- 检测：状态变更接口出现 GET 请求；无 Referer/Origin 或跨站来源的创建请求。
- 防御：所有写接口在服务端做认证与功能级授权；create 仅接受 POST/PUT，校验 CSRF Token 与 Content-Type。
- 防御：错误信息统一化，不向客户端泄露内部字段名/业务校验细节；参数使用白名单 DTO，禁止批量赋值 `ownerId/role/status` 等敏感字段。
- 加固：对创建操作做速率限制、审计与配额；定期巡检未授权可写接口。
