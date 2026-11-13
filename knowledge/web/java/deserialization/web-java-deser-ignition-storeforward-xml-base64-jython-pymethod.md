---
id: web-java-deser-ignition-storeforward-xml-base64-jython-pymethod
title: Ignition StoreAndForward XML 导入 Base64 反序列化 RCE（CVE-2023-50220）
type: scenario
domain: web
path: web/java/deserialization
technique: ignition-store-forward-base64xmlreader-jython-pymethod-deserialization
aliases:
- Ignition CVE-2023-50220
- /data/status/store_forward_import 反序列化
- Base64XmlReader 反序列化
- Ignition Jython PyMethod RCE
- QuarantinedXmlImporter RCE
tags:
- java
- deserialization
- rce
- ignition
- scada
- xml
- jython
- pymethod
- priorityqueue
- authenticated
cve:
- CVE-2023-50220
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
affected_versions: < 8.1.35（原文分析版本 8.1.30）
verification:
  verified_by: verifier-V557
  verified_at: '2026-11-12T00:23:55+08:00'
  notes: 已对照原文与11张截图核对：入口 POST /data/status/store_forward_import/:storeName、storeName 需存在（默认 sample_sqlite_database）、flavor=__datasourcedata__ + base64 标签、QuarantinedXmlImporter→Base64XmlReader→ClusterUtil.deserializeObject→ModuleObjectInputStream 链路、PyFunction.readResolve 抛异常改用 PyMethod 改造 Jython2 链、8.1.35 CompositeClassRejectListFilter 黑名单均与原文/截图一致；affected_versions 原文明确 <8.1.35。原文未给最终命令回显截图（依赖漏洞作者复现），PoC 未在本机执行。dedup 仅命中自身与通用 PyMethod gadget 卡（web-java-deser-jython-pymethod-proxy-builtin-eval，只顺带提及产品），非同链，保留。
---

## 一句话结论

Inductive Automation Ignition 的 StoreAndForward 导入路由 `/data/status/store_forward_import/:storeName` 接收 XML，其中 `flavor="__datasourcedata__"` 的 `<data>` 元素会交给 `HistoryFlavor` 的 `Base64XmlReader` 处理，后者把 `<base64>` 内容解码（必要时 gunzip）后直接交给 `ClusterUtil.deserializeObject` → `ModuleObjectInputStream.readObject`；8.1.35 之前没有反序列化类过滤器，持有后台管理员会话的攻击者提交一段 Jython `PyMethod` gadget 的序列化数据即可执行任意命令。

## 原理

- 入口路由：`StoreAndForwardRoutes.mount()` 注册 `POST /data/status/store_forward_import/:storeName`（前端 JS 中完整路径即此形式），处理函数调用 `importData()`；路由带 `RouteAccessControl.requireAll(STATUS_SECTION, CONFIG_SECTION)`，需要已登录且具备状态/配置区权限（原文利用条件即管理员后台权限）。
- 导入链路：`HistoryManagerImpl.importQuarantinedFromXML(storeName, InputStream)` 先按名字取 `DataSink`，再取 `QuarantineManager`（需为 `QuarantineStore`），构造 `QuarantinedXmlImporter` 并 `doImport(is)`。
- XML 解析：`QuarantinedXmlImporter.doImport` 用 `SAXParserFactory`（关闭 external-general-entities，XXE 被禁用），`startElement` 遇到标签名 `data` 且未在嵌套历史元素内时，读取 `flavor`、`subtype` 属性，经 `flavorRegistry` 查找对应 `HistoryFlavor`，再取其 `getXmlImportHandler()`。
- 危险分支：`flavor="__datasourcedata__"`、`subtype=""` 命中 `HistoryFlavor`，其 `getXmlImportHandler` 返回内部类 `Base64XmlReader`；`Base64XmlReader` 注册的 `Base64Element.getValue()` 执行 `ClusterUtil.deserializeObject(context, Base64.decodeAndGunzip(data))`，最终 `ModuleObjectInputStream.readObject()`——这是 Ignition 自定义的 `ObjectInputStream`（用于解析模块类），在 8.1.35 前没有任何类黑名单/过滤器。
- 为什么能 RCE：反序列化器把攻击者完全可控的字节流交给原生 Java 反序列化，只要 classpath 上存在可用 gadget 即可执行代码。Ignition 自带 `jython-ia-2.7.2.1.jar`：
  - 公开的 ysoserial `Jython1` 链依赖 `org.python.core.PyFunction` 作为动态代理 `InvocationHandler`；但该定制版 `PyFunction` 重写了 `readResolve()` 并直接 `throw new UnsupportedOperationException()`，反序列化时先触发该钩子导致利用失败。
  - 同 jar 的 `org.python.core.PyMethod` 功能等价且未受影响，可作为 `Comparator` 动态代理的 handler；`PriorityQueue.readObject` 的 heapify 触发 `compare` → `PyMethod.invoke` → 持有的 `__func__.__call__`，把 `__func__` 设为 `BuiltinFunctions`（index=18 的 `eval`）即可在 JVM 内执行任意 Python 代码/命令。即公开 Jython2 链略作改造。
- 触发顺序上的两处前置校验：`storeName` 必须是系统中已存在的数据源（默认 `sample_sqlite_database`）；XML 必须包含属性正确的 `<data>` 元素，否则在反序列化前返回/报错。

## 触发条件

- 目标为 Inductive Automation Ignition < 8.1.35（工业自动化网关，默认 8088 端口）。
- 攻击者持有可访问后台配置区的会话（管理员权限；路由要求 STATUS_SECTION + CONFIG_SECTION）。
- 目标存在至少一个 StoreAndForward 数据源（默认安装有 `sample_sqlite_database`）。
- 目标 classpath 含 `jython-ia-2.7.2.1.jar` 等可用 gadget 依赖（默认安装即含）。

## 利用步骤

1. 登录后台，取得有效 `JSESSIONID`（示例为 `node01...node0` 形式的 Ignition 会话）。
2. 用 ysoserial 的 Jython2 链改造载荷：把 `PyFunction` 换成 `PyMethod`，构造 `PriorityQueue` + `Comparator` 代理 + `BuiltinFunctions`(eval, index=18) + 待执行命令；序列化后按接口要求 gzip 并 base64 编码。
3. 构造 XML：`<data flavor="__datasourcedata__" subtype=""><base64>…</base64></data>`。
4. 以 multipart 形式 POST 到 `/data/status/store_forward_import/sample_sqlite_database`（storeName 换成目标实际存在的数据源名）。
5. 反序列化在 `Base64Element.getValue()` 处触发，命令以 Ignition 网关进程身份执行；若失败，检查 JSON/日志中的 `CompositeClassRejectListFilter` 拒绝记录以判断是否已打补丁。

## PoC

最小触发请求（载荷为 Jython `PyMethod` 链的序列化数据经 gzip+base64）：

```http
POST /data/status/store_forward_import/sample_sqlite_database HTTP/1.1
Host: target:8088
Cookie: JSESSIONID=<后台会话>
Content-Type: multipart/form-data; boundary=--------437556657
Content-Length: 594

----------437556657
Content-Disposition: form-data; name="file"; filename="test.xml"

<?xml version="1.0"?>
<data flavor="__datasourcedata__" subtype="">
    <base64>序列化数据 base64 编码</base64>
</data>
----------437556657--
```

```text
# 预期：请求命中 importData → Base64XmlReader → readObject，命令执行；
# 未打补丁时响应为重定向到 /web/status/con.history?store=<storeName>；
# 8.1.35 上日志出现：Serial class 'org.python.core.PyMethod' REJECTED by Platform pattern ...
```

gadget 构造要点（改造 Jython2 链，细节见关联卡）：

```java
// PyFunction 的 readResolve 在本产品定制 jython 中抛异常，改用 PyMethod
PyMethod handler = new PyMethod(builtinFunctionsEvalAt18, null, codeobj);
Comparator proxy = (Comparator) Proxy.newProxyInstance(
    cl.loadClass("java.util.Comparator").getClassLoader(),
    new Class[]{Comparator.class}, handler);
PriorityQueue<Object> q = new PriorityQueue<>(10, proxy);
// 反射把 queue.size 设为 2，元素含 PyBytecode 与 locals，readObject 时 heapify 触发
```

## 变体与关联

- 变体：`PyMethod` 的 `__func__` 换成 `com.ziclix.python.sql.connect.Lookup` 可把反序列化转为 JNDI/LDAP 查询，见 [[web-java-deser-jython-pymethod-proxy-lookup-jndi]]；换成 `BuiltinFunctions#eval` 见 [[web-java-deser-jython-pymethod-proxy-builtin-eval]]。
- 关联：[[web-java-deser-jython-pyfunction-pybytecode]]（Jython <= 2.5.2 的 `PyFunction` 原链；本产品定制版因 `readResolve` 抛异常不可直接用）。
- 关联：同产品 CVE-2023-39475/39476 的利用思路同样落在 Jython `PyMethod` 链上，说明该 gadget 是 Ignition 系的通用后利用负载。
- 变体：`Base64XmlReader` 只是众多 XML 导入 handler 之一；同架构下其它 `HistoryFlavor` 若也把序列化数据交给 `ClusterUtil.deserializeObject`，属于同类入口，可复用本卡排查思路。

## 检测与防御

- 根治：升级到 8.1.35+。该版本启动类新增 `CompositeClassRejectListFilter` 并注册为 JVM 级 `ObjectInputFilter`，黑名单覆盖 `org.python.core.PyMethod`、`PyFunction`、commons-collections、groovy、hibernate、RMIConnector 等常见 gadget 类；注意黑名单是枚举式防护，升级后仍需持续关注新 gadget。
- 加固：`/data/status/store_forward_import/*` 仅对可信管理员开放并加二次认证；不需要 StoreAndForward 导入时关闭该路由/功能；最小化 classpath 中的 Jython/Commons-Collections 等 gadget 依赖。
- 检测：网关日志中的 `REJECTED by Platform pattern` 记录（未打补丁目标不会有）；HTTP 访问 `/data/status/store_forward_import/` 且 XML 内含 `flavor="__datasourcedata__"` 与长 base64 串；base64 解码后以 gzip 魔数 `1f 8b` 开头且内容为 Java 序列化魔数 `ac ed 00 05`。
- 检测：`store_forward_import` 请求后网关进程异常创建子进程或执行 `Runtime.exec` 相关行为。
