---
id: web-generic-auth-related-object-pii-overreturn
title: 业务接口关联对象过返 PII：createUser/verifier 字段泄露姓名、邮箱、手机号与身份证号
type: scenario
domain: web
path: web/generic/auth
technique: related-object-pii-overreturn
tags:
- web
- auth
- pii
- data-exposure
- api
- idor
- masking
- src
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T11:44:46+08:00'
  notes: 已对照原文 content.md 与 18 张图片核对：img02 createUser{userId,userName,email}、img03 /web/home/search 返回 userId+phoneNumber、img04/05 logic1/loadUser 返回 communityPhone、img16 /api/user/cert/certs 返回 verifier 邮箱+realName+idCardNum、img14 /api/enterprise/certs 返回 verifier+contactName+contactPhone、img01 JS chunk 内嵌 name/nickname/email；未授权链 img06 GET /project/create 报项目名称不能为空→img15 补 name=test 返回 UUID succ:true→img13 /milestone/projects 列表可见 name=test，均与 PoC 一致。两卡技术原子独立（关联对象过返 PII / 未授权 GET create 写对象），判粒度合格；dedup 除自身外无 duplicate/likely_duplicate（resume 下载脱敏、user/all 未授权、参数枚举身份证等均为不同触发）。未验证点：接口域名/路径原文打码，未在目标复测。
url: /docs/web/generic/auth/web-generic-auth-related-object-pii-overreturn/
draft: false
kb_aliases:
- 接口过返个人信息
- 关联对象 PII 泄露
- createUser 字段泄露
- verifier 审核人信息泄露
- 响应字段级过度返回
- 接口返回身份证号
---

## 一句话结论

许多业务接口为了让前端直接展示“创建人/审核人/联系人”，会把关联用户或企业实体整对象序列化返回，于是低权限登录用户（部分接口甚至未登录）在列表、详情、审核、证书等响应里就能拿到他人的姓名、邮箱、手机号，甚至 `realName` + `idCardNum` 身份证号；业务只需要一个 ID，实际却泄露了整套 PII。

## 原理

- **后端直接序列化关联实体**：ORM 查询带出 `createUser`、`verifier`、`reviewer`、`contact` 等关联对象后，控制器把整个对象（或 Entity）原样返回，而不是按前端需要构造最小 DTO；字段级权限/脱敏缺失，导致关联主体的所有属性都进入响应。
- **展示脱敏 ≠ 接口脱敏**：页面可能只显示“张大”或打码手机号，但 API 响应里仍是完整 `userName`、`email`、`phoneNumber`、`realName`、`idCardNum`；攻击者只看数据包/响应即可取到完整值。
- **列表与分页放大**：列表/搜索接口（如 `/web/home/search`）一次返回多条记录，每条都带关联用户对象；结合 `pageNum/pageSize` 或批量导出，可放大到大量用户/企业。
- **鉴权边界不清**：有些接口只需任意登录账号（甚至无需登录）即可访问，服务端只校验“登录”不校验“是否有权看这些字段/对象”；审核类接口把审核人、申请人、企业联系人的 PII 一并返回，形成横向信息泄露。
- **前端 JS 内嵌数据**：除 API 响应外，部分 SPA 把服务端渲染/水合数据直接写进 JS chunk（`name`、`nickname`、`email` 等字段），无需调用接口即可从静态资源中提取员工信息。
- **危害**：姓名+邮箱+手机号可做社工/撞库/钓鱼；`realName`+`idCardNum` 属于高敏个人信息，可被用于身份冒用、诈骗；企业联系人信息还可用于针对供应链的攻击。

## 触发条件

- 目标系统的 API 返回嵌套的关联用户/企业对象（`createUser`、`verifier`、`contactUser` 等），且没有字段级权限或脱敏。
- 任意登录账号即可访问列表/详情/审核/证书类接口；或接口本身未做认证/鉴权。
- 列表接口支持分页/搜索/批量查询，或响应量足够大。
- 业务系统中确实存在大量真实用户/企业数据；PII 未加密/未掩码存储。
- 前端 JS chunk 中嵌入了服务端数据（SSR/hydration、配置 JSON），可直接读取。

## 利用步骤

1. 以普通账号登录，打开业务页面，在 Burp/DevTools 中观察列表、详情、审核、证书等请求的响应结构。
2. 重点搜索嵌套对象字段：`createUser`、`updateUser`、`verifier`、`reviewer`、`contact`、`applicant`、`enterprise`，以及 `userName/nickName/realName/email/phoneNumber/mobile/communityPhone/idCardNum/contactPhone`。
3. 对疑似接口做未登录/低权限复测：去掉 Cookie 或换低权限账号，确认是否仍返回同样字段。
4. 对列表接口尝试分页参数（`pageNum/pageSize`、`limit/offset`）与搜索条件，评估可拉取总量；抽样核对数据真实性。
5. 检查前端 JS 静态资源（`*.js`/chunk），搜索内嵌 JSON 中的 `email`、`nickname`、`phone` 等字段，补充泄露面。
6. 汇总泄露字段与数量，按高敏（身份证号、手机号、邮箱、真实姓名）分级；在授权范围内保存最小证据，不批量扩散。
7. 将泄露的手机号/邮箱用于后续口令复用/钓鱼风险评估（仅授权范围内）。

## PoC

```http
GET /web/home/search?pageNo=1&pageSize=10&category=&isAi=true HTTP/1.1
Host: target
Cookie: <普通登录会话>

HTTP/1.1 200 OK
{
  "code": 0,
  "data": {
    "list": [
      {"id": 400, "userId": 12, "phoneNumber": "18840******"},
      {"id": 300, "userId": 15, "phoneNumber": "176021*****"}
    ]
  }
}
```

```http
GET /<app>/api/.../review/media HTTP/1.1
Host: target
Cookie: <普通登录会话>

HTTP/1.1 200 OK
{
  "data": [{
    "createUser": {"userId": "AIO...", "userName": "张大*", "email": "zhangda***@***.com"},
    "files": [...]
  }]
}
```

```http
GET /<app>/api/user/cert/certs HTTP/1.1
Host: target
Cookie: <普通登录会话>

HTTP/1.1 200 OK
{
  "list": [{
    "verifier": "***@***.com",
    "realName": "丁*",
    "idCardNum": "342***...37618"
  }]
}
```

```http
GET /<app>/api/enterprise/certs HTTP/1.1
Host: target
Cookie: <普通登录会话>

HTTP/1.1 200 OK
{
  "list": [{
    "verifier": "gaon***@***.com",
    "contactName": "高*",
    "contactPhone": "186******875"
  }]
}
```

```text
# 前端 JS chunk 内嵌数据（原文另一案例）：
# 在 *.async.js 响应中可直接看到 name/nickname/email 等员工字段的 JSON 片段。
```

原文接口路径与目标域名多处打码，以上按截图还原字段结构；PoC 未在目标执行。

## 变体与关联

- 变体：详情/审核接口返回申请人、审核人、企业联系人的完整对象；导出接口把关联对象一并写入 Excel/CSV。
- 变体：前端页面做掩码但接口返回明文（与 [[web-generic-auth-resume-download-unmasked-pii-leak]] 的“展示脱敏、下载不脱敏”同源）。
- 变体：通过对象 ID 递增/枚举批量拉取（IDOR），见 [[web-generic-auth-api-param-fuzz-idcard-pii-enumeration]]、[[web-generic-auth-mobile-person-permission-userid-idor-pii]]。
- 关联：[[web-generic-auth-js-api-discovery-unauth-pii-mass-export]]——该卡聚焦「前端 JS 提取接口 + 未授权 list 接口批量导出 PII」；本草稿聚焦「已授权业务接口把关联用户/企业实体整对象过返（createUser/verifier 等嵌套字段）」，包括登录后可见的审核/证书数据与 JS 内嵌数据，触发条件与字段面不同。
- 边界：后端使用最小 DTO/字段级权限、对 PII 做统一掩码/加密、列表按租户/对象过滤、接口有严格鉴权时，泄露面显著缩小。

## 检测与防御

- 检测：API 响应中出现 `idCardNum`、`realName`、`phoneNumber`、`email` 等字段且调用者为普通账号/未登录；同一账号高频分页遍历列表/审核/证书接口；前端 JS 中出现员工 PII JSON。
- 防御：为每个接口定义最小返回 DTO，禁止直接序列化 ORM 实体/关联对象；对身份证、手机号、邮箱等做字段级脱敏与访问控制。
- 防御：所有业务接口做功能级+对象级授权；审核/证书类数据按角色与业务关系过滤；列表接口强制租户/用户范围。
- 加固：对 PII 字段加密存储、日志脱敏；对批量导出加二次授权与审计；前端不下发未使用的敏感字段。
- 响应：发现泄露接口后评估数据量与影响范围，按个人信息保护要求处置并通知。
