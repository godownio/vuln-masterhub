---
id: web-java-deserialization-axis-wsdd-hidden-service-readobject
title: Axis server-config.wsdd 隐藏服务反序列化：allowedMethods=* 的 receiveData 直通 readObject
type: scenario
domain: web
path: web/java/deserialization
technique: axis-wsdd-hidden-service-deserialization
aliases:
- Axis 反序列化
- server-config.wsdd 隐藏接口
- RefreshUserCachesService
- allowedMethods=*
- Axis RPC 未授权服务
- receiveData serializeData
- deSerializeData readObject
tags:
- java
- deserialization
- axis
- webservice
- wsdd
- readobject
- hidden-endpoint
- code-audit
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V192
  verified_at: '2026-11-06T23:06:16+08:00'
  notes: 已对照幻灯片第8/39/40页核对：server-config.wsdd allowedMethods为星号、receiveData到deSerializeData、CC10/Runtime Java52生成器一致；deSerializeData内部readObject为原文未展示的推断，卡内confidence low且注明无完整PoC。
---

## 一句话结论

传统 Servlet/Axis 项目常把 WebService 路由写在 `WEB-INF/server-config.wsdd`，其中 `provider="java:RPC"`、`allowedMethods="*"` 的服务会暴露该类的全部公开方法；某证券投研平台的 `RefreshUserCachesService.receiveData(String header, String serializeData)` 在解析 JSON 头后，把 `serializeData` 交给自定义 `deSerializeData` 做原生反序列化，形成网络可达的 `readObject` 入口，而静态扫描常因“入口不是 servlet + 反射/工厂分派”而漏报。

## 原理

- **Axis 1.x 的服务声明**：`server-config.wsdd` 的 `<service name="..." provider="java:RPC">` 定义 RPC 服务；`<parameter name="className" value="..."/>` 指定实现类，`<parameter name="allowedMethods" value="*"/>` 表示该类所有 public 方法都作为可调用操作暴露，`<parameter name="scope" value="Application"/>` 表示单例；`<namespace>` 与服务名组成访问路径（如 `/axis/services/RefreshUserCachesService`，实际前缀取决于 Axis 部署）。
- **入口方法**：`receiveData(String header, String serializeData)` 先 `ObjectUtils.deserializeObjectFromJson(header, DataSynHeader.class)` 解析出 `serviceName`，再通过 `DataSynServiceFactory.getDataReceiver(serviceName)` 取到具体 `IDataReceiver`，最后 `dataReceiver.receiveData(_header, serializeData)`。
- **sink**：`IDataReceiver` 的实现里 `receiveData(DataSynHeader header, String serializeData)` 调用 `this.deSerializeData(serializeData)`；该自定义方法内部通常用 `ObjectInputStream.readObject()` 还原对象。只要 `serializeData` 是攻击者可控的原生序列化字节流，且 classpath 存在可用 gadget，即可 RCE。
- **为什么静态工具会漏**：
  - 入口不在 `@Controller/@RequestMapping` 或 `web.xml` 的 `servlet-mapping` 中，而在 Axis 的 `server-config.wsdd` 里；
  - 真正的接收者由 `DataSynServiceFactory.getDataReceiver(serviceName)` 运行时选择，静态调用图可能只看到接口方法，看不到实现类；
  - sink 是项目自定义的 `deSerializeData`，不是直接出现 `ObjectInputStream`，基于 sink 签名的规则容易漏；
  - 代码库是多应用架构（主代码编译进 `lib` 下的 jar），扫描器可能只索引了部分 jar。
- **危害路径**：Axis 服务是 HTTP/SOAP 可达的；攻击者用合法 `DataSynHeader` JSON 通过工厂选择到目标 receiver，再把 CommonsCollections 等 gadget 序列化流作为 `serializeData` 传入，反序列化时触发命令执行。演讲中的 payload 生成器选择 `CommonsCollections10 / Runtime`、Java 版本 52（Java 8 字节码）、命令 `calc`。

## 触发条件

- 目标为传统 Servlet + Axis 1.x 架构，`WEB-INF/server-config.wsdd` 暴露了业务服务；服务使用 `provider="java:RPC"` 且 `allowedMethods="*"`（或至少暴露 `receiveData`）。
- 服务方法可达，且 `header` 能构造出合法 `DataSynHeader`（含正确的 `serviceName`/`operation`，可能需要匹配工厂中的 receiver）。
- `serializeData` 进入原生 `ObjectInputStream.readObject`，没有 `ObjectInputFilter`/类白名单；classpath 含可用的 gadget 链（如 CommonsCollections）。
- 攻击者能访问 Axis 端点；是否需要额外认证取决于部署（演讲未给出鉴权结论）。

## 利用步骤

1. 检查 `WEB-INF/server-config.wsdd`，列出所有 `<service>`：重点看 `provider="java:RPC"`、`allowedMethods="*"`、`scope="Application"` 和 `<namespace>`。
2. 把服务名与 `className` 对应到实现类，阅读公开方法，找带 `String`/`byte[]` 参数且最终进入反序列化的方法（如 `receiveData`、`deSerializeData`）。
3. 检查 `web.xml` 的 Axis servlet 映射（常见 `/services/*`、`/axis/*`）与 `server-config.wsdd` 的实际前缀，确定 URL。
4. 构造合法的 `header` JSON，使 `DataSynServiceFactory.getDataReceiver(serviceName)` 返回目标 receiver，并满足其 `operation` 校验。
5. 用目标 JDK 兼容的 gadget（演讲用 CommonsCollections10/Runtime、Java 8 字节码）生成序列化 payload，作为 `serializeData` 发送。
6. 观察命令执行/回连；若 `serializeData` 是 Base64 或十六进制编码，按接口实际类型编码。

## PoC

无完整 PoC（演讲只展示了 `server-config.wsdd`、`receiveData` 代码与 payload 生成器界面，没有给出实际 SOAP 请求/响应）。可按以下结构自行构造并验证：

```xml
<!-- 端点与参数名按 WEB-INF/server-config.wsdd 和 Axis 部署确认 -->
POST /axis/services/RefreshUserCachesService HTTP/1.1
Host: target
Content-Type: text/xml; charset=utf-8
SOAPAction: ""

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:ns="http://xxxxxxk/um">
  <soapenv:Body>
    <ns:receiveData>
      <header>{"serviceName":"...","operation":"..."}</header>
      <serializeData>BASE64_OR_RAW_SERIALIZED_GADGET</serializeData>
    </ns:receiveData>
  </soapenv:Body>
</soapenv:Envelope>
```

## 变体与关联

- 变体：Axis2 的 `services.xml`、CXF 的 `cxf.xml`/`@WebService`、JAX-WS 的 `sun-jaxws.xml` 同样可能暴露不在 Spring 路由表中的隐藏服务；审计时应把所有 WebService 描述符纳入 source 清单。
- 变体：`header` 的 JSON 反序列化若使用 Jackson 多态/`ObjectUtils.deserializeObjectFromJson`，也可能形成二次反序列化或属性注入；本卡只讨论 `serializeData` 的原生反序列化 sink。
- 关联：[[web-java-deser-readobject-reflection-rmiconnector-secondary]]（自定义 readObject 反射调用 + 二次反序列化）、[[web-java-deserialization-custom-readobject-runtime-exec]]（自定义 readObject 直接执行命令）、[[web-java-deserialization-payload-length-compression]]（payload 压缩）。
- 关联：[[code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow]] 中“静态工具漏掉反射/工厂调用”的漏报原因，本卡是其在 Axis `server-config.wsdd` 场景的具体例子。

## 检测与防御

- 审计：把 `server-config.wsdd`、`services.xml`、`web.xml`、`sun-jaxws.xml` 作为入口清单；对 `allowedMethods="*"` 的服务逐个确认是否必要，检查所有进入 `ObjectInputStream`/`readObject`/自定义 `deSerializeData` 的参数。
- 开发：Axis 服务只暴露明确方法（不要用 `*`），下线不用的服务；反序列化使用 `ObjectInputFilter` 白名单，禁止 CommonsCollections 等危险类；对 `header`/`serializeData` 做签名/认证。
- 运行：Axis 端点加统一认证与访问控制；RASP/WAF 监控 `java.io.ObjectInputStream` 反序列化行为与危险 gadget 类加载。
- 检测：`server-config.wsdd` 中出现 `allowedMethods="*"`；请求体包含 Java 序列化魔数 `AC ED 00 05`（或 Base64 `rO0AB`）；服务端加载 CC/CommonsBeanutils 等 gadget 类。
