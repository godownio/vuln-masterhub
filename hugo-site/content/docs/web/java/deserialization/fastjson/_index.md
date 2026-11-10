---
title: Fastjson
weight: 1
---

# Fastjson

## 这层是什么

Fastjson AutoType、缓存与绕过。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [APK 逆向复现 RSA+AES-GCM 加密登录：向 Fastjson 1.2.24 接口注入 JdbcRowSetImpl](web-java-deser-fastjson-apk-hybrid-rsa-aes-gcm-login/) | verified | high | 2026-11-05 |
| [Fastjson 1.2.47 类缓存绕过 AutoType：java.lang.Class 预置 JdbcRowSetImpl/BCEL/C3P0](web-java-deser-fastjson-1247-class-cache-bypass/) | draft | high | 2026-11-04 |
| [Fastjson 1.2.47 缓存绕过 + C3P0 HexAsciiSerializedMap 投递 TemplatesImpl 字节码内存马](web-java-deser-fastjson-1247-c3p0-templatesimpl-memshell/) | verified | high | 2026-11-10 |
| [Fastjson 1.2.68 AutoCloseable 期望类绕过：双 @type 触发任意文件读写与目录创建](web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw/) | draft | high | 2026-11-04 |
| [Fastjson 1.2.80 Exception 期望类 + 反序列化器缓存两段式绕过：Groovy/Jackson/IO 链](web-java-deser-fastjson-1280-exception-deserializer-cache-bypass/) | draft | high | 2026-11-04 |
| [Fastjson 1.2.80 Throwable 思路缓存 OutputStream 类型：JSONGenerator 链 + MarshalOutputStream/InflaterOutputStream 触发目标流写入](web-java-deser-fastjson-1280-outputstream-cache-file-write/) | verified | medium | 2026-11-08 |
| [Fastjson 1.2.80 在 Spring Boot/Tomcat 部署下的写类→类加载 RCE：从 /tmp 枚举 docbase，写 WEB-INF/classes，再由 @type 经 TomcatEmbeddedWebappClassLoader 触发加载](web-java-deser-fastjson-1280-springboot-tomcat-webresources-class-load-rce/) | verified | medium | 2026-11-08 |
| [fastjson 1.2.83 file: 协议不出网加载本地 class RCE](web-java-deser-fastjson-file-protocol-no-egress-rce/) | verified | high | 2026-11-04 |
| [fastjson 1.2.83 不出网 RCE：Tomcat 临时文件 fd + jar:file](web-java-deser-fastjson-fd-jar-no-egress-rce/) | verified | high | 2026-11-04 |
| [fastjson 1.2.83 用 jar:http 种子拉取触发 /tmp/jar_cache fd 二次加载 RCE](web-java-deser-fastjson-jar-cache-fd-reload-rce/) | verified | high | 2026-11-05 |
| [fastjson AutoType 关闭时的资源探测类型名导致远程类加载 RCE](web-java-deser-fastjson-resource-probing-rce/) | verified | high | 2026-11-04 |
| [Fastjson checkAutoType 类描述符绕过演进：1.2.25 L; → 1.2.42 LL;; → 1.2.43 [ → 1.2.44 修复](web-java-deser-fastjson-autotype-descriptor-bypass-evolution/) | verified | high | 2026-11-08 |
| [Fastjson JdbcRowSetImpl 触发 JNDI 注入](jdbc-rowset/) | draft | high | 2026-11-04 |
| [Fastjson parseObject 开启 AutoType：TemplatesImpl _bytecodes 在 batchUpdate 触发命令执行](web-java-deser-fastjson-templatesimpl-batchupdate-rce/) | verified | high | 2026-11-06 |
| [Fastjson WAF 绕过：\x 非 hex 字符与 Unicode 数字伪造 @type（GhostBits）](web-java-deser-fastjson-waf-ghostbits-escape/) | draft | medium | 2026-11-04 |
| [Fastjson 任意文件写转 RCE：计划任务、JSP、JRE jar/classes、SPI 与 tomcat-docbase 落地点](web-java-deser-fastjson-file-write-to-rce/) | draft | medium | 2026-11-04 |
| [Fastjson 加密参数入口：复用目标 AES 工具加密 payload 通过 Base64+AES 解密层](web-java-deser-fastjson-encrypted-param-aes-wrapper/) | verified | high | 2026-11-05 |
| [Fastjson 有期望类时用 java.util.Currency 包装触发所有 getter](web-java-deser-fastjson-currency-getter-expected-class/) | draft | medium | 2026-11-04 |
| [Fastjson 触发 C3P0 JndiRefConnectionPoolDataSource setter 链导致 JNDI 注入](web-java-deser-fastjson-c3p0-jndiref-jndi/) | verified | high | 2026-11-05 |
| [Fastjson 触发 C3P0 userOverridesAsString 十六进制原生反序列化](web-java-deser-fastjson-c3p0-hex-useroverrides/) | verified | high | 2026-11-05 |
| [Fastjson 触发 MySQL JDBC autoDeserialize：恶意 MySQL 服务端返回序列化对象 RCE](web-java-deser-fastjson-mysql-jdbc-autodeserialize/) | draft | high | 2026-11-04 |
| [Fastjson 触发 PostgreSQL PgConnection socketFactory 加载远程 Spring XML 执行命令](web-java-deser-fastjson-postgres-pgconnection-xml-rce/) | draft | high | 2026-11-04 |
| [Fastjson 识别与版本/依赖/期望类探测：解析指纹、AutoType 探测与 DNS 回显](web-java-deser-fastjson-recon-version-dependency-probe/) | draft | medium | 2026-11-04 |
| [Fastjson 高版本原生链被 resolveClass 黑名单封掉 BadAttributeValueExpException 后，改用 HashMap+HotSwappableTargetSource→XString.equals 触发 toString，并用 JSONArray 引用包裹穿过类名检查](web-java-deser-fastjson-xstring-hotswappable-tostring-waf-bypass/) | verified | medium | 2026-11-09 |
| [Fastjson 黑名单覆盖不到的第三方 JNDI 工厂：MyBatis JndiDataSourceFactory / XBean JndiConverter / Shiro JndiObjectFactory](web-java-deser-fastjson-thirdparty-jndi-factory-blacklist-gap/) | verified | high | 2026-11-08 |
| [FastJson1 1.2.83 原生反序列化 gadget：HashMap 键先入 TemplatesImpl，BadAttributeValueExpException(val=JSONArray) 经 JSONArray.toString/ASMSerializer 调 getOutputProperties 执行字节码](web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain/) | verified | high | 2026-11-08 |
| [Fastjson2 FNV-1a 哈希碰撞绕过 AutoType 白名单 RCE](web-java-deser-fastjson2-fnv-collision-autotype-bypass/) | verified | high | 2026-11-04 |
| [Fastjson2 ObjectReaderSeeAlso 开启 AutoType 后回退 loadClass RCE](web-java-deser-fastjson2-seealso-fallback-loadclass-rce/) | verified | high | 2026-11-04 |
| [Fastjson2 序列化触发 getter RCE：TemplatesImpl 直用与 ≥2.0.27 双代理黑名单绕过](web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass/) | verified | high | 2026-11-05 |
| [Fastjson2 默认 accept 哈希的 FNV-1a z3 预映像碰撞：任意前缀 jar:http 绕过 AutoType RCE](web-java-deser-fastjson2-fnv-z3-preimage-collision-rce/) | draft | high | 2026-11-05 |
| [JFinal CMS 未授权 API 的 version/method/p 三参分发：version 选 Logic 类、method 经反射 invokeMethod 调方法、p 直接进 fastjson parseObject（CVE-2024-53477）](web-java-deser-fastjson-jfinalcms-api-version-method-dispatch-sink/) | verified | medium | 2026-11-09 |
| [MetaCRM download.jsp AES 十六进制参数包裹的 Fastjson JdbcRowSetImpl JNDI RCE](web-java-deser-fastjson-crm-download-jsp-aes-jdbcrowset-jndi/) | verified | high | 2026-11-07 |
| [UEditor config.json 成为 fastjson 反序列化入口：后台任意文件写覆盖该配置，访问 /ueditor 即触发 parseObject](web-java-deser-fastjson-ueditor-config-json-file-sink/) | verified | high | 2026-11-08 |
| [入口只用 JSON.parse 时 getter 调用受限：用 $ref 的 JSONPath 解析或把 JSONObject 当 key 走 toString，强行触发任意 getter](web-java-deser-fastjson-parse-getter-bypass-ref-jsonobject-key/) | verified | medium | 2026-11-09 |
| [汉王e脸通 fastjson 1.2.46 反序列化：addVisitDeviceAppointmentInfoTest 的 parseObject 触发 JdbcRowSetImpl JNDI](web-java-deser-fastjson-hanvon-addappointment-jdbcrowset-jndi/) | verified | medium | 2026-11-07 |
| [高版本 Fastjson 内置 InetAddress 解析实现 DNS 探测：Inet4Address/Inet6Address 与畸形 InetSocketAddress](web-java-deser-fastjson-inetaddress-dns-probe-malformed/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
