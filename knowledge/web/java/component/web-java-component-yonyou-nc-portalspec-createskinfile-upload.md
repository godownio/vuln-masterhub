---
id: web-java-component-yonyou-nc-portalspec-createskinfile-upload
title: 用友 NC PortalSpecServiceImpl.createSkinFile 任意文件上传：接口名作 rpcname 反射调用 + 双 URL 编码绕过 '/' 截断写 webroot
type: scenario
domain: web
path: web/java/component
technique: yonyou-nc-portalspec-createskinfile-double-url-encode-upload
aliases:
- 用友 NC 任意文件上传
- createSkinFile
- PortalSpecServiceImpl
- IPortalSpecService
- lfw 接口任意文件上传
- 双 URL 编码绕过路径过滤
- NCM_NC6.5_000_109902
tags:
- java
- yonyou
- nc
- lfw
- file-upload
- path-traversal
- double-url-encode
- reflection
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: NC 6.5 / NC Cloud（lfw 接口；原文 2024-03-01 通告，补丁编码 NCM_NC6.5_000_109902_20240301_GP_281362040）
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:45:30+08:00'
  notes: 已对照原文0x02-0x04及图14/20-24核对：createSkinFile 六参数拼接 filePath、FileUtils.writeStringToFile、JSONTokener 以'/'截断、..%252f 双编码经 JsURLDecoder.decode 还原均为原文所述；图20请求体可见 rpcname=nc.uap.portal...。注意：接口名最终走 ServiceCache 还是 findMeta 分支，原文表述不完全明确（截图请求无 -> 前缀），卡内按原文叙事记录，需实机确认；未在真实目标复现上传。
---

## 一句话结论

用友 NC 的 `/lfw/core/rpc` 反射调用可落到已注册服务 `nc.uap.portal.service.itf.IPortalSpecService` 的实现类 `PortalSpecServiceImpl.createSkinFile(projectPath, projectModuleName, type, themeId, fileName, fileText)`：六个字符串参数被拼进 `filePath`，最终 `FileUtils.writeStringToFile(new File(filePath + "/" + fileName), fileText, "UTF-8")`；由于 JSONTokener 解析参数时把 `/` 当作终止字符，单层编码的 `../` 会被截断成 `..`，把穿越串做两层 URL 编码（`..%252f..%252f`）即可让第一次解码后仍不含字面 `/`、随后 `JsURLDecoder.decode` 还原成 `../../`，从而把任意内容写到 web 根目录下的可执行文件（如 JSP webshell）。

## 原理

- **入口与参数**：`RpcControlPlugin` → `RpcHelper.processJsonRequest` 读取 `rpcdata` JSON；`call()` 取 `rpcname`/`method`/`params0..9`（最多 10 个），参数经 `LfwJsonSerializer.fromJsObject` 转换、`$S_` 前缀剥离、`JsURLDecoder.decode(value,"UTF-8")` 解码后放入 `paramObjs`。
- **为什么用接口名**：`ServiceLocator.getService(name)` 经 `NCLocator.lookup` 的 `findMeta` 按注册的组件元数据取实例；`PortalSpecServiceImpl` 注册在接口 `nc.uap.portal.service.itf.IPortalSpecService` 名下，直接传实现类名 `nc.uap.portal.service.impl.PortalSpecServiceImpl` 会找不到元数据（返回 500），改成接口名后 `findComponent` 通过 `getImplementationClass()`/`instantiate` 得到实现类实例，再用 `getMethod("createSkinFile", String[].class 匹配)` 反射调用，服务器返回 200（body 为 `null`）。
- **写文件逻辑**：`createSkinFile` 把 `projectPath`、`projectModuleName`、`themeId`、`type` 等拼成 `filePath = getPortalSpecPath(projectPath, projectModuleName) + "/ftl/portaldefine/skin/" + themeId + "/" + type...`，`new File(filePath).mkdirs()` 建目录，然后 `new File(filePath + "/" + fileName)` 并以 UTF-8 写入 `fileText`。六个参数全部来自 RPC，未做规范化，拼接后可穿越到任意目录。
- **`/` 截断与双编码绕过**：`fromJsObject` 最终调用 JSONTokener 的 `nextValue()`，其无引号字符串循环在遇到 `':'`、`','`、`'['`、`']'`、`'}'`、`'/'` 等字符时停止（原文截图显示条件含 `c != '/'`）。因此参数里直接放 `../../../` 会被截成 `..`；发送 `..%252f..%252f` 时：
  1. Servlet 先对表单参数做一次 URL 解码 → `..%2f..%2f`（此时不含字面 `/`，JSONTokener 不截断）；
  2. `JsURLDecoder.decode` 再解码 `%2f` → `../../`，拼进 `filePath` 完成目录穿越。
- **为什么能 getshell**：NC 运行在 Tomcat/中间件中，web 根目录（如 webapps 下应用目录）可写时，写入 `.jsp` 等可执行扩展名文件即可被容器解析；文件内容 `fileText` 也完全可控。
- **Windows 差异**：Windows 下也可直接用 `..\..\`（反斜杠不被 JSONTokener 截断），但为通用性使用双编码 `..%252f..%252f`。
- **同一反射入口的其他用途**：注册服务中若有读文件/执行命令的 public 方法，也可被同样调用；原文最后用同一入口调用其他类方法读取了 `win.ini`（`[16-bit app support]`、`[fonts]` 等段落）。

## 触发条件

- 目标为用友 NC / NC Cloud，`/lfw/core/rpc` 可未授权访问。
- 目标版本存在 `IPortalSpecService`/`PortalSpecServiceImpl.createSkinFile`，且 NC 进程对 web 根目录或目标目录有写权限。
- 参数解析路径与原文一致（JSONTokener 的 `/` 截断 + `JsURLDecoder.decode` 二次解码）。
- 写入的可执行文件需落在容器可解析的 web 目录（如 `webapps/<app>/` 下）。
- 仅限授权测试。

## 利用步骤

1. 先确认 `/lfw/core/rpc` 可达，并用一个错误 `rpcname` 观察 500/异常特征。
2. 构造 `rpcdata`：`rpcname` 为 `nc.uap.portal.service.itf.IPortalSpecService`，`method` 为 `createSkinFile`，`params0..params5` 对应六个 String 参数。
3. 在参与 `filePath` 拼接的参数中放入双层 URL 编码的穿越串（如 `..%252f..%252f..%252f..%252fwebapps%252fROOT`），`fileName` 设为 `shell.jsp`，`fileText` 为 JSP webshell 内容。
4. 以 `application/x-www-form-urlencoded` POST 到 `/lfw/core/rpc`；响应 200 且 body 为 `null` 表示方法调用完成。
5. 访问写入的 URL（如 `http://target/shell.jsp`）验证解析；若路径不对，按 `getPortalSpecPath` 的实际前缀调整穿越层数与落点。
6. 若只需读取文件，可改用同一反射入口调用其他注册服务的读文件方法（如读取 `win.ini`）。

## PoC

```http
POST /lfw/core/rpc HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

rpcdata={"rpcname":"nc.uap.portal.service.itf.IPortalSpecService","method":"createSkinFile","params0":"..%252f..%252f..%252f..%252fwebapps%252fROOT","params1":"x","params2":"x","params3":"x","params4":"shell.jsp","params5":"<% out.println(123); %>"}
```

说明：参数顺序按 `createSkinFile(projectPath, projectModuleName, type, themeId, fileName, fileText)` 对应；原文截图中的成功请求参数被脱敏，穿越串所在参数与目标落点需按实际 `getPortalSpecPath` 前缀调整。以上为按文章代码与请求整理的最小示意，未在未授权目标执行。

## 变体与关联

- **编码变体**：Windows 目标可直接用 `..\..\`；其他中间件可能在 Servlet/框架层多做一次解码，此时调整编码层数（原文已验证两层）。
- **JNDI 变体**：同一接口把 `rpcname` 设为 `ldap://...` 可走 `NCLocator` 的 JNDI 分支，见 [[web-java-component-yonyou-nc-lfw-rpc-reflection-service-locator-jndi]]。
- **同类用友上传**：NCCloud GatewayServlet 的 `IFileTrans` 上传变体见 [[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]（需 gatewaytoken）；用友 KSOA 上传见 [[web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload]]；U8 的上传链见 [[web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload]]。
- **通用路径穿越**：`../` 被截断后二次解码还原的思路，与双重编码绕过 WAF/过滤器的通用技巧同源，可参考 `web/generic/file-upload` 下相关卡。
- **边界**：目标目录不可写、web 目录不在拼接路径可达范围、扩展名被容器限制、补丁已修复 `lfw` 接口时利用失败。

## 检测与防御

- **流量检测**：`/lfw/core/rpc` 请求体出现 `rpcname` 为 `IPortalSpecService`、`method` 为 `createSkinFile`；参数含 `%252f`、`%252e`、`..\`、`webapps`、`.jsp` 等特征；对 `rpcdata` 中 `%25` 二次编码与路径穿越组合直接告警。
- **文件/主机**：web 根目录出现非发布流程生成的新文件（尤其 `.jsp`/`.jspx`）；NC 进程对 webapps 目录的写操作；文件创建后紧接 HTTP 访问。
- **防御**：应用官方补丁（原文补丁编码 `NCM_NC6.5_000_109902_20240301_GP_281362040`）；限制 `/lfw/*` 对外访问；对注册服务的反射调用建立方法/参数白名单并规范化路径；web 目录设为运行账户只读或部署与运行分离；WAF 仅作补充。
- **注意**：NC 版本与补丁差异较大，需按实际版本确认接口、类名与参数签名。
