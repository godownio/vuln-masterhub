---
id: web-dotnet-deser-servicehandler-typenamehandling
title: 未授权 ServiceHandler 配合 TypeNameHandling.All 的 JSON 反序列化
type: scenario
domain: web
path: web/dotnet/deserialization
technique: json-net-typenamehandling-service-handler
tags:
- dotnet
- aspnet
- json.net
- newtonsoft
- deserialization
- typenamehandling
- iis
- servicehandler
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-G
  verified_at: '2026-11-04T19:22:25+08:00'
  notes: 已对照 content.md 与全部 50 张图片核对：ServiceHandlerFactory 的 /wf/* 映射、UrlParser 正则、NamespaceMap->AppService、EnsureServicePostfix、ActionIsMatch 无 [Action] 默认放行、BindingFlags.Instance|Static|Public、GetDictResult 无 CheckLogin、JsonnetDataProvider TypeNameHandling.All 且单参数整包反序列化、WebSecurity 仅覆盖 .aspx/.ashx/.ajax，均与截图一致；NETWORK SERVICE 与 SeImpersonatePrivilege 来自原文文字说明。原文未披露具体 gadget 与命令执行请求体，PoC 仅为结构示意。
  unverified:
  - 未公开具体 gadget 与命令执行载荷，未独立复现；PoC 截图在原文中为空
url: /docs/web/dotnet/deserialization/web-dotnet-deser-servicehandler-typenamehandling/
draft: false
kb_aliases:
- TypeNameHandling.All
- ServiceHandlerFactory 未授权
- GetDictResult 反序列化
- .NET JSON 反序列化
---

## 一句话结论

自研 ASP.NET 路由把无扩展名 URL 交给 ServiceHandlerFactory 反射调用 public 方法，若该方法缺少认证与 `[Action]` 约束、且参数反序列化使用 Json.NET `TypeNameHandling.All`，攻击者就能在请求体中用 `$type` 实例化任意类型，通常最终导向命令执行。

## 原理

漏洞由“路由可达 + 认证缺失 + 不安全反序列化 + 防护不覆盖”四段共同成立：

1. **处理器接管**：`web.config` 的 `system.webServer/handlers` 把 `/wf/*` 映射到自研 `ServiceHandlerFactory`，无文件扩展名的路径因此进入 ASP.NET 管线，绕过只针对 `.aspx` 等扩展名的常规检查。
2. **URL 解析**：自定义正则把 `/wf/appservice/BusinessObjectService/GetDictResult` 拆成 type=`wf`、namespace=`appservice`、name=`BusinessObjectService`、method=`GetDictResult`，扩展名可选。
3. **类与方法定位**：程序集 `NamespaceMap` 特性把命名空间映射为 `AppService`；识别器为类名补 `Service` 后缀；方法缓存以 `Instance | Static | Public` 查找；`[Action]` 特性缺失时 `ActionIsMatch` 直接返回 true。
4. **认证缺失**：目标方法为 `public virtual`，方法体没有 `CheckLogin()`，类上无 `[Authorize]`、方法上无自定义权限特性，而同文件其他方法普遍显式鉴权，形成“漏网之鱼”。
5. **反序列化 sink**：参数提供器按 `Content-Type` 选择反序列化器，`application/json` 进入 Json.NET provider；单参数方法的整个请求体被一次性反序列化，且全局配置为 `TypeNameHandling.All`。参数类型为 `Dictionary<string, object>`，其 value 声明为 `object`，正是 `$type` 能生效的位置。
6. **防护落空**：Web 安全类静态构造函数只把 `.aspx`、`.ashx`、`.ajax` 加入 SQL 关键字检查扩展名列表，`/wf/` 无扩展名路径不在范围内；且反序列化发生在参数绑定阶段，早于方法体执行，因此 IIS 日志只看到 200，看不到任何 SQL 语句。

该案例的实际执行身份是 IIS 工作进程（NETWORK SERVICE），令牌含已启用的 `SeImpersonatePrivilege`，为后续提权到 SYSTEM 提供了条件。

## 触发条件

- .NET Framework / ASP.NET 应用使用自研 ServiceHandlerFactory 或类似反射路由；
- 处理方法为 `public`，无 `[Action]`/权限特性且未调用统一的登录校验；
- 方法参数为单个 `object`/`Dictionary<string, object>` 等可承载 `$type` 的类型；
- 使用 Newtonsoft.Json，且 `TypeNameHandling` 为 `All`、`Objects` 或 `Auto`；
- 请求体可被攻击者完整控制，接口对公网或低权限网络开放。

## 利用步骤

1. 从 `web.config` 的 handlers 节枚举自研处理器路径（本例 `/wf/*`、`/api/*`），确认哪些前缀被接管；
2. 构造符合正则的 URL，枚举可访问的 Service 与方法；
3. 优先寻找未调用 `CheckLogin()`、无权限特性的 public 方法（可结合反编译静态排查）；
4. 以 `application/json` POST 单参数方法，在请求体放入带 `$type` 的对象；
5. 选择一个适用于 .NET Framework 的 Json.NET gadget 完成实例化/命令执行，观察响应时延、回显或子进程；
6. 以工作进程权限投放后续载荷；若令牌含 `SeImpersonatePrivilege`，可进一步提权。

## PoC

原文未披露完整 gadget 与命令执行载荷，因此这里只给出**请求结构**，不对具体 gadget 类名作断言：

```http
POST /wf/appservice/BusinessObjectService/GetDictResult HTTP/1.1
Host: <target>:9010
Content-Type: application/json
Content-Length: <n>

{"$type":"<可实例化类型全名>, <程序集名>", "<键>":"<值>"}
```

判定要点：

- 正常业务响应与带 `$type` 的响应时延/内容出现明显差异；
- 反序列化阶段即触发类型构造，方法体内即使没有危险代码也可能执行；
- 可用无害类型先验证 `$type` 是否被解析，再评估具体 gadget。

## 变体与关联

- 变体：`/api/*` 使用同类 `JsonnetDataProvider`；`TypeNameHandling.Objects/Auto`；XML 反序列化器；多参数方法逐参数反序列化；表单编码路径。
- 关联 gadget 家族：Json.NET 常见利用面包括 `ObjectDataProvider`、`TypeConfuseDelegate`、`DataSet` 等，但是否可用取决于目标程序集与 .NET 版本，需实测。
- 关联：[[defense-detection-sqlps-lolbin-powershell]]（拿到命令执行后的替代 PowerShell 宿主）；[[defense-forensics-multisource-timeline-log-clear]]（日志被清后的时间线还原）。

## 检测与防御

- **代码审计关键字**：`TypeNameHandling`、`ServiceHandlerFactory`、`GetCustomAttribute<ActionAttribute>`、`BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public`、`CheckLogin`；对比同类方法，找出未鉴权的 public 方法。
- **修复优先级**：把 `TypeNameHandling` 改为 `None`，或使用带类型白名单的 `ISerializationBinder`；禁止请求体直接反序列化为 `object`/`Dictionary<string, object>`。
- **访问控制**：所有服务方法默认要求认证与权限特性，`[Action]` 缺失应默认拒绝而非放行；敏感接口只在内网或经网关暴露。
- **临时缓解**：在 IIS `denyUrlSequences` 或 WAF 中封禁具体路径只是止血，攻击者可换方法/路径，必须修根因。
- **运行时检测**：IIS 日志中出现无扩展名路径的 POST 且返回 200、响应时差异常；`w3wp.exe` 派生子进程（`cmd`、`powershell`、`sqlps`、`net` 等）；应用池账户异常访问网络或写入可执行文件。
- **权限收敛**：应用池使用低权限账户，禁用不必要特权；即使反序列化 RCE，也提高后续提权成本。
