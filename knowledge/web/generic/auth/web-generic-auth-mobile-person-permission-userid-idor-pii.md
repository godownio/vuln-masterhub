---
id: web-generic-auth-mobile-person-permission-userid-idor-pii
title: 移动端 person/permission 接口按 userId 越权查询：遍历泄露师生 PII 与人脸信息
type: scenario
domain: web
path: web/generic/auth
technique: mobile-person-permission-userid-idor
aliases:
- person/permission userId 越权
- APP userId 遍历
- 师生信息泄露
- 人脸信息越权查询
- 校园 APP 水平越权
- evo-apigw person permission
tags:
- idor
- broken-access-control
- horizontal-privilege-escalation
- mobile
- api
- pii
- face
- enumeration
- education
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:44:08+08:00'
  notes: 已对照原文与19张图核对：图01/04/05 为 GET /evo-apigw/evo-erm/1.0.0/person/permission?userId=6298/6299 请求；图02 Burp Intruder payload 14904-14913 全部 200 且响应长度不同；图03 响应含 manager/personType/personId/userId/brUserId/name/code/idCode/photoUrl/idPhoto 等字段；正文 1-14590 学生、14590-15000 左右教师与约19000条 PII 均一致。原文无版本信息，未设置 affected_versions；frontmatter 无 sources/source_url。未验证点：未在本机复跑遍历。
---

## 一句话结论

校园 APP 的 `GET /evo-apigw/evo-erm/1.0.0/person/permission?userId=<数字>` 只校验 Authorization 是否有效，不校验该 userId 是否属于当前用户；由于 userId 是连续整数，遍历即可批量读取约 1.9 万名师生（1-14590 学生、14590-15000 教师）的姓名、学号/工号、院系、宿舍、身份证号与人脸照片等 PII。

## 原理

- 对象级授权缺失：接口按请求参数 `userId` 查询用户资料/权限，但服务端没有把 `userId` 与令牌主体（当前登录用户）比对，也没有数据范围限制。任何有效登录态都能读取任意 userId 的数据。
- 数字型自增 ID 使枚举成本极低；响应中的 `userId`/`personId`/`brUserId` 等字段相互关联，可用于扩展遍历和后续接口。
- 返回数据包含 `name`、`code`（学号/工号）、`departmentCode`/`departmentName`、`idCode`（身份证）、`phone`、`photoUrl`、`idPhoto`（人脸/证件照）等，属于高敏感个人信息；批量泄露可直接用于身份冒用、钓鱼、人脸认证伪造。
- 本文通过 Burp Intruder 对 userId 递增请求（14904-14913 等）全部返回 200，确认可批量拉取；累计约 19000 条。
- 为什么是完整漏洞而非“正常功能”：接口返回的是他人完整资料，且普通学生账号即可访问；服务端未按角色/归属过滤，违反最小权限与对象级授权原则。

## 触发条件

- 移动端 APP 存在按 userId 查询用户资料/权限的接口，且只校验登录态。
- userId 为连续/可预测整数，或可通过其他接口获得合法 ID 列表。
- 接口响应包含 PII、人脸照片、身份证等敏感字段。
- 无速率限制/批量审计，或限制不足以阻止低频遍历。

## 利用步骤

1. 登录普通账号，抓取首页刷新请求，定位 `GET /evo-apigw/evo-erm/1.0.0/person/permission?userId=<self>`。
2. 将 `userId` 放入 Burp Intruder，按数字递增遍历；观察状态码/响应长度，确认均返回 200 且数据不同。
3. 根据返回的 `personType`/`personId`/`departmentCode` 区分学生与教师；本文 1-14590 为学生、14590-15000 左右为教师。
4. 批量导出响应，提取 `name`、`code`、`idCode`、`phone`、`photoUrl`、`idPhoto` 等字段。
5. 用泄露的 userId/personId 继续测试其他接口（资料修改、人脸、考勤等），把只读泄露扩展为写入/冒用。

## PoC

```http
GET /evo-apigw/evo-erm/1.0.0/person/permission?userId=6299 HTTP/1.1
Host: target
Accept: application/json, text/plain, */*
Authorization: <valid-token-of-any-user>
User-Client: 6
```

```json
{
  "success": true,
  "code": "0",
  "data": {
    "manager": false,
    "personType": "1",
    "personId": 6297,
    "userId": 6299,
    "brUserId": 6299,
    "name": "<victim>",
    "code": "<student-id>",
    "idCode": "<id-card>",
    "phone": null,
    "photoUrl": "<face-photo-url>",
    "idPhoto": null
  }
}
```

说明：原文用 Burp Intruder 遍历 userId（示例 14904-14913 全部 200），累计获取约 19000 条师生信息；PoC 未在本机复跑，字段值已脱敏。

## 变体与关联

- **ID 来源变体**：除自增 userId 外，personId、brUserId、学号/工号、手机号等也可作为查询键；一个接口泄露的 ID 可喂给其他接口。
- **接口变体**：`person/permission`、`person/app/*`、`approval/*`、`app/menu/default` 等移动端 API 常共享同一鉴权缺陷；逐个替换 userId/personId 测试。
- **影响升级**：只读 PII 可用于撞库、钓鱼、人脸认证伪造；若同一 ID 在写接口也被信任，可进一步越权修改资料/人脸（见 [[web-generic-auth-face-photo-update-body-id-idor]]）。
- **关联**：[[web-generic-auth-authlog-userid-enumeration-authz-bypass]]（日志接口泄露 userId 后枚举详情）、[[web-generic-auth-login-header-userid-token-binding-takeover]]（移动端 userId/token 绑定缺陷）、[[web-generic-auth-face-liveness-background-replace-base64]]（人脸认证绕过）。
- **边界**：接口做了对象级授权（令牌主体与 userId 绑定）、userId 为不可预测 UUID、响应脱敏、或批量枚举被限速/封禁时，本路径受限。

## 检测与防御

- **检测**：同一令牌在短时间内请求大量不同 userId；响应 200 且返回不同用户资料；移动端 API 出现顺序 ID 遍历特征。
- **检测**：异常下载/导出量、同一来源访问学生与教师全量数据；WAF/API 网关的枚举告警。
- **防御**：所有对象级接口强制校验“令牌主体 == 目标 userId”或按角色/数据范围过滤；使用不可预测 ID（UUID）仅作为辅助，不替代授权。
- **加固**：响应按角色脱敏（身份证、手机号、人脸照片默认不返回）；对批量查询做速率限制、分页上限与审计；最小权限分配菜单/接口。
- **响应**：确认泄露范围、通知受影响用户、轮换/吊销会话、排查是否已用于人脸冒用或账号接管。
