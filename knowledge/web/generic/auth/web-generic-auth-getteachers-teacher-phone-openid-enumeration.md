---
id: web-generic-auth-getteachers-teacher-phone-openid-enumeration
title: 教学 API getTeachers 按姓名返回教师完整资料：任意登录用户可枚举手机号/openid，删参数取全量
type: scenario
domain: web
path: web/generic/auth
technique: authenticated-teacher-directory-pii-enumeration
aliases:
- getTeachers 越权
- 教师信息泄露
- 删除参数获取所有教师
- 智慧云平台越权
- 教师手机号枚举
- 小程序接口 PII 泄露
tags:
- api
- idor
- broken-object-level-authorization
- pii
- phone-number
- openid
- miniprogram
- information-disclosure
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:59:35+08:00'
  notes: 已对照 content.md 与 img09-12 核对：GET /teach-api/common/school/getTeachers/%E7%8E%8B 仅 Bearer 登录校验、响应含 id/schoolId/userId/code/name/phone/card/openid/password=null 等、删除姓名段返回无人(00000000000)记录均与原文一致。未验证点：原文只说删除参数可获取所有老师信息，未展示完整全量分页；未实际复现越权。
---

## 一句话结论

教学接口 `/teach-api/common/school/getTeachers/<姓名>` 只用 Bearer 校验“已登录”，不校验查询者与目标教师的关系、也不裁剪响应字段，直接返回教师用户实体（id、姓名、`phone`、`email`、`card`、`openid`、`schoolId` 等）；普通学生/测试账号按姓名即可查到任意教师资料，把路径里的姓名段删掉/置空还会返回全量教师记录，从而批量收集手机号与 openid，为弱口令登录或小程序 sessionKey 篡改任意登录提供目标。

## 原理

- **接口行为**：请求 `GET /teach-api/common/school/getTeachers/<姓名>`，路径末段是姓名的 URL 编码（如 `%E7%8E%8B` = “王”），服务端按姓名做查询并返回教师用户对象；请求只带 `Authorization: Bearer <token>` 做登录校验。
- **为什么是越权**：登录校验只回答“你是谁”，没有回答“你能不能查这个人/这些字段”。该接口既没有角色限制（普通账号、测试账号也能调），也没有对象级授权（不要求查询者是被查教师本人或管理员），属于 broken object level authorization / 水平越权。
- **为什么泄露敏感字段**：响应直接把数据库用户实体序列化返回，字段包括 `id`、`schoolId`、`userId`、`code`、`name`、`name2`、`phone`、`password`（null）、`email`、`card`、`openid`、`activate`、`status`、`label`、`delFlag`、`collegeId`、`facultyId` 等。即使 `password` 为 null，`phone` 与 `openid` 已足以支撑后续攻击（手机号用于弱口令/会话伪造，openid 用于绑定关系分析）。
- **为什么删参数能拿全量**：姓名段被删掉或置空后，查询条件变成空/通配，ORM 不再按姓名过滤，接口按默认分页/全量返回教师记录；原文实测删除 `%E7%8E%8B` 后返回了测试账号（`无人`/`00000000000`）等记录，并称可获取所有老师信息。
- **为什么危害不止信息泄露**：教师手机号是最关键的账号标识。原文用它配合小程序弱口令（手机号 + `123456`）和 `sessionKey` 篡改登录，最终以教师/管理员身份进入后台，可查看全年级考勤等敏感数据。因此该接口是整条账号接管链的“目标清单”来源。

## 触发条件

- 目标为智慧校园/教学类小程序或 Web 平台，存在按姓名查询教师的 API（本例 `/teach-api/common/school/getTeachers/`）。
- 攻击者持有任意有效登录态（普通学生、测试账号均可），Bearer token 可通过弱口令/注册等方式获得。
- 接口不做对象级授权与字段裁剪，响应包含手机号、openid 等敏感字段。
- 姓名段可控或可删除/置空，触发全量/模糊查询；接口无严格频率限制。

## 利用步骤

1. 登录任意账号，抓取教师课表/选择教师页面的请求，定位 `getTeachers` 接口与 Bearer token。
2. 按已知或常见姓氏（如“王”“李”“张”）请求 `/teach-api/common/school/getTeachers/<URL编码姓名>`，观察响应中的 `phone`、`openid`、`label` 等字段。
3. 删除路径末段（或置空）请求 `/teach-api/common/school/getTeachers/`，尝试获取全量教师记录；必要时配合分页参数/pageSize 扩大返回量。
4. 汇总教师姓名、手机号、openid、所属学院等，形成目标账号清单。
5. 用手机号尝试弱口令登录（如 `123456`）或结合小程序 `sessionKey` 篡改，登录教师/管理员账号。
6. 以教师身份访问课表、考勤、学生信息等模块，验证权限提升与数据范围。

## PoC

```http
GET /teach-api/common/school/getTeachers/%E7%8E%8B HTTP/1.1
Host: target
Content-Type: application/json
Xweb_xhr: 1
Authorization: Bearer <任意登录用户的 token>
```

响应（节选，字段已脱敏）：

```json
{
  "id": "576",
  "userId": "190",
  "schoolId": "6",
  "code": "wy29",
  "name": "王**",
  "phone": "1**********5662",
  "openid": "og4Rk...E4eBpg",
  "label": "王**（1**********5662）",
  "activate": "yes",
  "status": "0"
}
```

删除姓名段：

```http
GET /teach-api/common/school/getTeachers/ HTTP/1.1
Authorization: Bearer <任意登录用户的 token>
```

## 变体与关联

- 同类参数遍历：把姓名换成空串、`*`、`%` 或常见姓氏，分别观察是否返回全量/模糊匹配；分页参数 `pageNum/pageSize` 可进一步扩大导出。
- 与 `web-generic-auth-api-param-fuzz-idcard-pii-enumeration`（移动端参数增删枚举 PII）同类，但本卡是“已认证接口缺对象级授权 + 响应实体未裁剪”，无需猜参数名。
- 后续利用：小程序手机号弱口令登录（`pentest-initial-access-*`）、`sessionKey`/`encryptedData` 篡改任意用户登录。
- 防御方若只做“登录校验”而不做字段级权限，仍会持续泄露；需要 DTO 裁剪与对象级授权。

## 检测与防御

- 接口层做对象级授权：只有本人或具备教师管理权限的角色才能查询他人资料；普通账号查询通讯录需最小字段（姓名、部门），不返回手机号/openid/邮箱/证件号。
- 响应使用 DTO/白名单字段，禁止直接序列化用户实体；`password` 等敏感字段永久排除。
- 对空查询、通配查询、全量分页做限制；加入频率限制与异常枚举检测（同一账号短时间按大量姓名/空条件查询）。
- 检测：审计 `getTeachers` 的请求模式（空前缀、常见姓氏扫描、大 pageSize）、响应体是否包含 phone/openid；关联同一 token 后续的登录/改密行为。
