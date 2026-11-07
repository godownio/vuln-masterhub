---
id: web-java-deserialization-cookie-userinfo-cc8-springecho
title: Cookie userInfo Java 反序列化 + SpringEcho 无出网回显：CC8/TemplatesImpl 载荷直接命令执行
type: scenario
domain: web
path: web/java/deserialization
technique: cookie-userinfo-cc8-springecho
aliases:
- userInfo Cookie 反序列化
- Cookie 字段 Java 反序列化
- SpringEcho 回显
- CommonsCollections8 TemplatesImpl
- 不出网反序列化回显
- Yso-Java Hack SpringEcho
tags:
- java
- deserialization
- cookie
- spring
- springecho
- templatesimpl
- commons-collections4
- ysoserial
- no-egress
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V243
  verified_at: '2026-11-07T13:18:47+08:00'
  notes: 已对照原文与56张图核对：userInfo Cookie 为 rO0AB/AC ED 00 05 序列化流、Yso-Java Hack 选 CommonsCollections8/SpringEcho、回显 Header Etag/动作 exec/位置 body/whoami 返回 mail-svc、随后 java-memshell-generator 生成 Behinder SpringMVC Interceptor（/test1、密码 Rzxtdjirc、UA Ckrorh）、正向客户端上传 /var/www/html/shell.exe 均与截图一致；CC2/TemplatesImpl 尝试返回 500 也有截图。dup-scan 与其他 CC 链卡为 related/new，非同一链。未验证点：未复跑；frontmatter 无 sources/source_url；无受影响版本。
---

## 一句话结论

当应用把登录后下发的 Cookie（案例为 `userInfo`）Base64 解码后直接 `ObjectInputStream.readObject()`，攻击者可用 CommonsCollections8/TemplatesImpl gadget 生成序列化对象替换 Cookie；目标不出网时，再由 SpringEcho（`RequestContextHolder` 取当前 request/response）把命令输出写回 HTTP 响应体，实现无需反连的外部命令执行。

## 原理

- **入口**：案例的邮件系统在登录后下发 `userInfo` Cookie，其值以 `rO0AB...` 开头；Base64 解码后是 Java 序列化魔数 `AC ED 00 05`，说明服务端会把该 Cookie 当作序列化对象反序列化，而不是当作普通字符串/签名 token。
- **gadget**：目标 classpath 含 `commons-collections4-4.0`、Spring Boot 2.6.7、Spring Web 5.3.19、JDK 8。使用 CommonsCollections8（CC8）搭配 `TemplatesImpl`：反序列化时触发 gadget 链，调用 `TemplatesImpl.newTransformer()`/`getOutputProperties()` 一类的反射入口，加载并实例化攻击者内嵌的转译器类（继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`）。该类的静态初始化块/构造逻辑执行攻击者代码。
- **无出网回显**：单纯 `Runtime.exec` 在不出网目标上拿不到结果。SpringEcho 类在恶意字节码中通过 `org.springframework.web.context.request.RequestContextHolder.getRequestAttributes()` 取得当前 `ServletRequestAttributes`，再 `getResponse()` 拿到 `HttpServletResponse`，把命令输出写入响应体（或指定 Header）；因为使用的是当前请求上下文，不需要目标反连攻击者。
- **生成器配置**：案例用 Yso-Java Hack（ysoserial GUI）选择 `CommonsCollections8 / SpringEcho`，配置回显 Header `Etag`、动作 `exec`、位置 `body`、命令 `whoami`；请求 `/mail/u/0/` 时 Cookie 换成 payload，响应体返回 `mail-svc`（`whoami` 结果），证明命令执行与回显成功。
- **为什么必须换链**：案例在另一台主机上先试 CC2/TemplatesImpl 得到 500，说明 gadget 是否可用取决于目标 classpath、JDK 版本和反序列化入口的过滤；CC8 在该 Spring Boot + commons-collections4 环境中可用。

## 触发条件

- 应用存在可控的反序列化入口：Cookie/参数/请求体 Base64 解码后进入 `ObjectInputStream.readObject()`，且没有类白名单、`ObjectInputFilter`、签名或来源校验。
- classpath 中存在可用 gadget（案例为 commons-collections4 4.0 + TemplatesImpl；JDK 8 环境）。
- 攻击者能控制该 Cookie（登录后即可获得同名 Cookie，替换其值）。
- 目标可以不出网：SpringEcho 依赖当前请求/响应上下文，不需要反向连接。
- 入口请求能到达反序列化代码路径（案例为 `/mail/u/0/`，携带 Cookie 即触发）。

## 利用步骤

1. 正常登录邮件系统，抓取 `userInfo` Cookie；Base64 解码，确认开头为 `AC ED 00 05`（Java 序列化流）。
2. 用 Yso-Java Hack/ysoserial 选择 `CommonsCollections8` + `SpringEcho`，设置回显 Header（如 `Etag`）、动作 `exec`、位置 `body`、命令 `whoami`，生成 payload 并 Base64 编码。
3. 把 `Cookie: userInfo=<payload>` 发送到会触发反序列化的页面（案例 `GET /mail/u/0/`），观察响应体是否返回命令输出（案例为 `mail-svc`）。
4. 替换命令做信息收集：`id`、`ls /`、`cat /etc/passwd`、`find / -perm -u=s -type f 2>/dev/null`；读取 flag/二进制文件时可结合 `cmp -l file /dev/zero | awk '{printf "%c", strtonum("0"$2)}'` 或 `base64`。
5. 需要持久化时，用 java-memshell-generator 生成 Behinder SpringMVC Interceptor 内存马，通过同一反序列化入口注入；Behinder 连接时填写 URL 路径、连接密码与自定义 User-Agent（案例为 `/test1`、`<password>`、`User-Agent: <custom-ua>`）。内存马注入细节见 [[web-java-framework-spring-mvc-interceptor-memshell]]。
6. 目标不出网时，可把正向连接客户端上传到入口机的 Web 目录（案例 `/var/www/html/shell.exe`），由内网被控主机主动连接入口机的监听端口，建立隧道后再横向。

## PoC

确认 Cookie 是 Java 序列化流：

```bash
echo 'rO0ABXNy...' | base64 -d | xxd | head -1
# 00000000: aced 0005 7372 00...   <- AC ED 00 05
```

生成 CC8 + SpringEcho payload（工具界面配置；实际类名/回显头可按目标调整）：

```text
利用链: CommonsCollections8 / SpringEcho
回显Header: Etag
动作: exec
位置: body
命令: whoami
```

发送：

```http
GET /mail/u/0/ HTTP/1.1
Host: target:8080
Cookie: userInfo=<Base64(CC8 + SpringEcho payload)>
```

响应（案例）：

```http
HTTP/1.1 200 OK
Content-Length: 10

mail-svc
```

> 普通 ysoserial 的 `CommonsCollections8` 只负责触发 `Runtime.exec`，不会自动回显；本场景的关键是使用带 SpringEcho 的 payload 生成器，或在恶意 `AbstractTranslet` 类中自行实现 `RequestContextHolder` 回显。

## 变体与关联

- 变体：入口不限于 Cookie，任何 Base64 序列化参数/请求体/Header 都可能；先确认序列化魔数，再按 classpath 选链。
- 变体：CC2/CC4/CC6/TemplatesImpl、JDK17 原生链等都可搭配 SpringEcho 或其它回显器；案例另一台主机 CC2/TemplatesImpl 返回 500，说明要按目标依赖逐个试链。
- 变体：回显位置可改为响应 Header（如 `Etag`）或自定义 Header；命令可改为从请求头动态读取，便于交互式执行。
- 变体：拿到命令执行后可注入 Behinder SpringMVC Interceptor/Filter/Controller 内存马（参见 [[web-java-framework-spring-mvc-interceptor-memshell]]、[[web-java-framework-spring-mvc-dynamic-controller-memshell]]）。
- 变体：不出网环境下，命令回显 + 正向连接客户端（上传到入口 Web 目录）可替代反弹 shell；可参考 [[pentest-c2-forward-node-jsp-joda-smux-tunnel]] 的正向节点思路。
- 关联：[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（CC4/CC2 触发 TemplatesImpl 的 gadget 原理）。
- 关联：[[web-java-deserialization-custom-readobject-runtime-exec]]（业务类 readObject 直接执行命令的入口类型）。
- 边界：如果服务端使用 `ObjectInputFilter`/类白名单、禁用 commons-collections4 或升级 JDK，CC8/TemplatesImpl 可能失效；需要换链或寻找其他反序列化入口。

## 检测与防御

- **不要反序列化不可信 Cookie**：改用 JSON/JWT 并校验签名；必须反序列化时使用 `ObjectInputFilter` 类白名单，拒绝 `TemplatesImpl`、`TrAXFilter`、`InstantiateTransformer`、`TiedMapEntry`、`PriorityQueue` 等 gadget 类。
- **清理依赖**：移除不必要的 commons-collections/commons-collections4、Xalan 等 gadget 库；升级 JDK 并开启序列化过滤。
- **检测特征**：Cookie/参数值以 `rO0AB` 开头；`java.io.ObjectInputStream.readObject` 出现在请求线程栈；响应体异常短且内容为 `id`/`whoami` 输出；`TemplatesImpl`、`AbstractTranslet` 动态类加载；后续出现 `/test1` 等未知路径的 Behinder 流量。
- **响应处置**：发现可疑 Cookie 反序列化后，排查 JVM 中的内存马（java-memshell-scanner/Arthas）与异常类加载，重置会话密钥，修复反序列化入口并重启。
