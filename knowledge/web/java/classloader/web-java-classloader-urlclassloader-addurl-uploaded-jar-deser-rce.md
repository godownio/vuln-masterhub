---
id: web-java-classloader-urlclassloader-addurl-uploaded-jar-deser-rce
title: JAR 上传 + 可控 getter 反射 URLClassLoader.addURL 动态加 classpath：jar:file 绕过协议黑名单，反序列化加载类触发 static 块 RCE
type: scenario
domain: web
path: web/java/classloader
technique: urlclassloader-addurl-uploaded-jar-deserialization-rce
aliases:
- URLClassLoader.addURL 注入
- jar:file 协议绕过
- 上传恶意 JAR 加 classpath
- 动态 classpath 反序列化 RCE
- User.getGift 链
- addURL getter 触发
tags:
- java
- classloader
- urlclassloader
- jar
- file-upload
- deserialization
- rce
- protocol-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T01:06:49+08:00'
  notes: '已对照原文与 img/01-05 核对：Shiro 1.2.4 尾部斜杠 /user/index/ 绕过；/user/upload 仅拦 ../ 与 .jsp、其余后缀写 /templates/<name>；User.getGift 对 username trim/lower 后仅拦 http/file 前缀，再 new URL+反射 URLClassLoader.addURL(getSystemClassLoader)；payload jar:file:///templates/evil.jar!/ 以 jar 开头绕过；POJONode+TextAndMnemonicHashMap/HashMap 在 readObject 触发 toString/getter；第二次反序列化加载 Evil 类 static 块外带（img/02-05 外带日志与 DASCTF flag）。卡内链条、PoC 与原文一致。注意与 web-java-deserialization-pojo-getter-urlclassloader-uriprefix（14878 同赛题、url: 前缀绕过、远程 HTTP 加载）共享入口/getter/gadget/sink，但本卡多了任意 JAR 上传落 /templates 与 jar:file 本地 JAR 载体、无需出网，前置与 PoC 不同，按不同 bypass/carrier 变体保留并建议互链；若维护者按同一链合并，可保留 14878 的 url: 版并删除本卡。未复跑。dedup 候选 c3p0 组件内置 URLClassLoader 链非同链。'
---

## 一句话结论

应用把上传文件写入固定目录且只拦 `.jsp` 后缀与 `../`（`.jar` 可传），同时存在把用户可控字符串反射进 `URLClassLoader.addURL` 的 getter；由于黑名单只判 `http`/`file` 前缀，用 `jar:file:///templates/evil.jar!/` 即可绕过，把恶意 JAR 加入系统 classloader。随后向反序列化接口发送该 JAR 内类的序列化对象，JVM 从新增 classpath 解析并加载该类，`static` 初始化块在 `readObject` 之前执行，形成上传到 RCE 的完整链。

## 原理

- **上传落点可控**：上传逻辑取 `getOriginalFilename()`，仅检查文件名不含 `../`、`..\`，并拒绝后缀等于 `.jsp`；其余后缀（含 `.jar`）原样写入 `/templates/<fileName>`。这给攻击者一个可预测、可被远端读取的 JAR 路径。
- **动态加 classpath 的 sink**：某 getter（示例为 `User.getGift()`）对 `username` 做 `trim()`/`toLowerCase()`，若以 `http` 或 `file` 开头则替换为 `nonono`，否则 `new URL(gift)` 并反射调用 `URLClassLoader.addURL(URL)`，目标是 `ClassLoader.getSystemClassLoader()`。即用户输入可把一个 URL 追加到系统类加载器的搜索路径。
- **协议黑名单绕过**：黑名单按字符串前缀判 `http`/`file`，未涵盖 `jar`。`jar:file:///templates/evil.jar!/` 以 `jar` 开头，能通过检查，且是合法 JAR URL，指向已上传文件；`addURL` 接受后，该 JAR 进入系统 classpath。
- **getter 触发**：反序列化入口把 Base64 解码后交给 `ObjectInputStream.readObject()`。`POJONode` 包装 `User` 后，`POJONode.toString()` 会走 Jackson 序列化，`BeanPropertyWriter.serializeAsField` 反射调用所有 getter，从而执行 `getGift()`；外层用 `UIDefaults$TextAndMnemonicHashMap`（配合 `HashMap`/`Hashtable` 的 key 比较）在 `readObject` 阶段触发该 `toString`，可绕过寄存器/黑名单限制。
- **加载即执行**：第二次反序列化时，流中类描述符对应的类由系统 classloader 解析；由于 JAR 已被 `addURL` 加入，JVM 找到并加载该类，类初始化（`static {}`）在实例恢复前执行，攻击者代码落地。若目标可出网，可在 static 块中执行命令并通过 HTTP 外带结果（原文先用 URLDNS 确认出网）。
- 两步是必要的：第一次反序列化只改变 classpath（getter 副作用），第二次反序列化才会真正触发新 JAR 中类的加载与静态初始化。

## 触发条件

- 存在任意后缀文件上传，落点路径可预测，且应用能通过 `jar:file://` 读取该路径（同机文件系统即可）。
- 上传校验只做后缀/路径黑名单，未限制 `.jar`，也未把上传目录排除在类加载范围之外。
- 存在可被反射调用的 getter/方法，把用户可控字符串传入 `URLClassLoader.addURL` 或等价 classpath 追加 API；协议黑名单只拦部分 scheme。
- 有可用的 Java 原生反序列化入口，并存在触发任意 `toString`/getter 的 gadget（如 POJONode + TextAndMnemonicHashMap）以调用上述 getter。
- 恶意 JAR 内类名与第二次 payload 的类描述符一致，且类带 `static` 初始化块。
- 目标可出网或存在其他外带通道（写文件、DNS、回连）；不出网时仍可执行命令但需另找回显方式。

## 利用步骤

1. 编写 `Evil implements Serializable`，在 `static {}` 中执行命令（如读取 flag/执行系统命令），把结果 Base64 后通过 `HttpURLConnection` GET 到攻击者服务器。
2. 按目标期望的包名/类名把 `Evil.class` 打进 `evil.jar`，保持第二次序列化流中的类描述符与该类名一致。
3. 通过上传接口传 `evil.jar`，得到路径如 `/templates/evil.jar`。
4. 构造第一次反序列化 payload：`User.username = "jar:file:///templates/evil.jar!/"`；用 `POJONode` 包装该 `User`，再用 `UIDefaults$TextAndMnemonicHashMap` + `HashMap` 构造触发 `toString` 的 gadget；序列化后 Base64，POST 到反序列化接口（示例 `/user/ser`）。
5. 第一次请求执行 `getGift()` → `addURL`，系统 classpath 增加 `/templates/evil.jar`。
6. 构造 `Evil` 对象的序列化流并 Base64 POST 同一接口；`readObject` 解析类时从新 classpath 加载 `Evil`，`static` 块执行。
7. 在攻击者 HTTP 服务上接收外带数据（原文先打一次 `ls /` 枚举出 flag 文件路径，第二次读取 flag）。
8. 若反序列化入口受 Shiro 等鉴权保护，可先利用对应的路径解析鉴权绕过（如 Shiro 1.2.4 尾部斜杠）访问接口。

## PoC

上传（`.jsp` 被拒，`.jar` 放行）：

```http
POST /user/upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="evil.jar"
Content-Type: application/octet-stream

<JAR bytes>
------x--
```

第一次反序列化（触发 getter 加 classpath，Base64 省略）：

```text
User.username = "jar:file:///templates/evil.jar!/"
payload = Base64( serialize( HashMap[ TextAndMnemonicHashMap -> POJONode(User) ] ) )
POST /user/ser  ser=<payload>
```

第二次反序列化（加载 JAR 中的类）：

```text
payload2 = Base64( serialize( new Evil() ) )
POST /user/ser  ser=<payload2>
```

`Evil` 的 static 块（最小化）：

```java
public class Evil implements Serializable {
    static {
        try {
            Process p = Runtime.getRuntime().exec("cat /flag");
            // 读输出、Base64、HTTP GET 外带到攻击者服务器
        } catch (Exception ignored) {}
    }
}
```

原文实测：第一次外带拿到根目录列表并看到 flag 文件，第二次外带 Base64 解码得到 flag。

## 变体与关联

- 协议变体：除 `jar:file://` 外，可尝试 `jar:http://`、嵌套 JAR、其他未被黑名单覆盖的 scheme；关键是黑名单只枚举了 `http`/`file`。
- 触发变体：`toString` 触发可用 `Hashtable`/`HashMap` + `TextAndMnemonicHashMap`、`XString.equals`、`EventListenerList` 等；getter 调用也可由其他 Jackson/框架序列化桥接。
- sink 变体：`URLClassLoader.addURL`、`ScriptEngineManager` SPI、JDBC DriverManager/SPI、ServletContainerInitializer 等都可由「可控 JAR 落盘 + 让 JVM 从该路径加载」组合成 RCE，区别只在 classpath 注入方式。
- 关联：Shiro 路径解析鉴权绕过可把受保护的反序列化/上传接口暴露给未授权用户；TextAndMnemonicHashMap 触发 toString 的独立 gadget 与 POJONode 链已有专卡。
- 边界：本链依赖应用自身存在 `addURL` sink 与可写 JAR 落点，不是通用 JDK gadget；目标为精简 JRE 或禁止出网时需调整回显方式。

## 检测与防御

- 上传：后缀/内容类型白名单（业务只需图片就不允许 JAR/ZIP），落盘目录移出类加载可见范围，文件名随机化并禁止保留原始扩展名。
- classpath：禁止把用户可控 URL 交给 `URLClassLoader.addURL`/`getSystemClassLoader`；必须使用时用 scheme+host+path 全白名单，而不是只黑名单 `http`/`file`。
- 反序列化：使用 `ObjectInputFilter` 限制类，最好移除原生 Java 反序列化入口；对 `javax.swing`/Jackson node 等 gadget 类做拒绝。
- 检测：上传目录出现 `.jar`；请求参数/日志出现 `jar:file`、`jar:http`、`URLClassLoader.addURL`；JVM 从 `/templates` 等非 lib 目录加载类；`static` 初始化阶段出现异常网络请求；反序列化流中出现 `TextAndMnemonicHashMap`、`POJONode`。
- 审计：搜索 `addURL(`、`URLClassLoader`、`getSystemClassLoader`、`Class.forName` 的用户可控入参，以及上传写入路径是否与上述 sink 可组合。
