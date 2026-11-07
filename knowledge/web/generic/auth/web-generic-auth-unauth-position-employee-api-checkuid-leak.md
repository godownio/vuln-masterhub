---
id: web-generic-auth-unauth-position-employee-api-checkuid-leak
title: 未授权岗位员工接口 + 账号 IDOR：遍历岗位/账号 ID 泄露 Acc_Pw 与鉴权 CheckUID
type: scenario
domain: web
path: web/generic/auth
technique: unauth-position-employees-checkuid-leak
aliases:
- 微厦学习系统未授权
- Position/Employees 未授权
- Account/ForID 越权
- CheckUID 泄露
- 员工密码密文泄露
tags:
- web
- api
- idor
- access-control
- pii
- credential-leak
- enumeration
- dotnet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 微厦在线学习考试系统 2.0
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:49:56+08:00'
  notes: V262 重核：对照正文与24图，Position.cs Employees 仅 [HttpGet]、返回 EmpAccount 全实体含 Acc_Pw/Acc_CheckUID、GET /api/v2/Position/Employees?id=3 未授权返回 super 数据、Account/ForID?{int(10000-13000)} 枚举大量 200（2.8~10.7KB）、近万账号均一致；dup-scan pair6 与 DES 伪造卡为同链上下游但机制不同，判定两卡均保留。affected_versions 设为微厦 2.0。
---

## 一句话结论

微厦在线学习考试系统的 `GET /api/v2/Position/Employees?id=N` 未做任何鉴权，按岗位 ID 即可返回该岗位全部员工的 `Acc_Pw`（密码密文）、`Acc_CheckUID`（后续 Authorization 校验用随机值）以及手机号/身份证等 PII；配套的 `GET /api/v2/Account/ForID?id=N` 同样只按自增 ID 返回账号资料，遍历即泄露近万条账号。

## 原理

- 源码 `Song.ViewData/Methods/Position.cs` 中：

```csharp
[HttpGet]
public Song.Entities.EmpAccount[] Employees(int id)
{
    return Business.Do<IPosition>().GetAllEmployee(id);
}
```

  方法上只有 `[HttpGet]`，没有 `[Admin]`/`[Teacher]` 等权限特性，也没有在方法体内校验当前用户；路由直接暴露为 `/api/v2/Position/Employees`。任何能访问 Web 的人都可以按自增 `id` 取到对应岗位的员工数组。
- 返回的是完整实体 `EmpAccount`（而非裁剪后的 DTO），其中包含 `Acc_Pw`（登录校验码/密码密文，原文的 Acc_Pw 是 DES 加密的校验码）与 `Acc_CheckUID`（服务端登录时写入数据库的随机识别码，Authorization 校验要用到，见关联卡）。
- `Account/ForID?id=` 同样是按对象 ID 直查：请求 `GET /api/v2/Account/ForID?id={int(10000-13000)}`，服务端不校验该账号是否属于当前用户，200 响应返回 2.8KB~10.7KB 的个人资料；自增整数 ID 可被批量枚举，原文据此控制接近 1 万条账号。
- 这类问题的共性是：API 控制器方法缺少授权过滤器/ownership 校验，且响应直接序列化持久化实体，把“内部字段”一并暴露；自增 ID 让横向遍历成本极低。

## 触发条件

- 目标为微厦在线学习考试系统（源码/特征 `LICENSE.txt`、`WEISHAKEJI_LICENSE`、`X-Powered-By: WeishaKeji`），API 路由 `/api/v2/Position/Employees`、`/api/v2/Account/ForID` 可从外部访问。
- 接口未要求登录或只要求任意低权账号；岗位/账号 ID 为自增整数，可顺序枚举。
- 响应实体包含 `Acc_Pw`、`Acc_CheckUID`、手机号、身份证号等敏感字段，且未被全局过滤器脱敏。
- 目标使用该 `Acc_CheckUID` 作为 Authorization 令牌的一部分（后续伪造链的前提）。

## 利用步骤

1. 请求 `GET /api/v2/Position/Employees?id=1`、`id=2`、`id=3`…，无需认证头；从 JSON `result` 数组读取每个员工的 `Acc_Id`、`Acc_AcName`、`Acc_Pw`、`Acc_CheckUID`、`Acc_Phone` 等。
2. 重点记录超级管理员（如 `Acc_Id=1`、`Acc_AcName=super`）的 `Acc_CheckUID`，用于后续伪造 Authorization。
3. 并行枚举 `GET /api/v2/Account/ForID?id={10000..13000}`，按响应长度/字段判断有效账号；原文在 3000 个 ID 上得到大量 200 响应（单条 2.8KB~10.7KB），确认可控制约 1 万条账号。
4. 汇总泄露数据：账号名、密码密文、CheckUID、姓名、手机号、身份证号；可用于撞库、伪造登录与社工。
5. 若 `Acc_Pw` 使用可逆的静态密钥加密（见关联卡），可直接解密/伪造管理员 Authority。

## PoC

```http
GET /api/v2/Position/Employees?id=3 HTTP/1.1
Host: target.example
Connection: keep-alive
```

```json
{"success":true,"state":1,"result":[{"Acc_Id":1,"Acc_AcName":"super",
"Acc_Pw":"f17d...","Acc_Name":"...","Acc_Phone":"...",
"Acc_CheckUID":"3a3c6...a4f1"}]}
```

```http
GET /api/v2/Account/ForID?id=10708 HTTP/1.1
Host: target.example
```

原文用 Web Fuzzer 对 `id={int(10000-13000)}` 批量发包，确认大量 200 与不同长度的响应体。

## 变体与关联

- `Account/ForID` 是同一系统的平行越权变体；其他只挂 `[HttpGet]` 而未加 `[Admin]/[Teacher]` 的控制器方法（如员工、岗位、组织相关接口）都可能有同类问题。
- 与本卡直接关联的下一步：`web-generic-auth-dotnet-des-checkcode-authorization-forgery`——用泄露的 `Acc_CheckUID` + Web.config 默认 DES 密钥伪造 Authorization，接管超级管理员。
- 与通用 IDOR/PII 枚举卡的区别：本卡的关键不仅是越权读资料，还泄露了服务端鉴权令牌的构成要素（CheckUID）与密码密文，直接把权限提升到“可伪造任意管理员”。

## 检测与防御

- 所有 API 控制器方法显式加授权特性（`[Admin]`、`[Teacher]` 或自定义策略），并在方法体内做 ownership/租户校验；不要依赖“前端不显示入口”。
- 返回 DTO 而非持久化实体，`Acc_Pw`、`Acc_CheckUID`、身份证等字段默认不序列化；全局响应过滤器做敏感字段脱敏。
- 对外标识使用不可预测的 UUID/哈希并校验归属，避免自增 ID 顺序遍历；对批量枚举做频率限制与告警。
- 把 `Acc_CheckUID` 视为服务端机密：不要通过任何 API 返回；令牌应使用 HMAC/JWT 签名并绑定会话，而非仅靠“知道随机值”。
- 监控：单 IP 高频访问同一接口且 `id` 连续递增、响应体包含密码/CheckUID 字段；对 `/api/v2/Position/Employees` 等敏感路由做未授权访问审计。
