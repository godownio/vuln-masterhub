---
id: web-java-classloader-agent-replace-jplisagent-transform-custom-method
title: 替换 JPLISAgent 的 mInstrumentationImpl/mTransform 为自定义类方法：消除 ClassFileTransformer 与 addTransformer 特征
type: scenario
domain: web
path: web/java/classloader
technique: java-agent-replace-jplisagent-transform-custom-method
aliases:
- 无 transformer 的 Agent
- 替换 mTransform
- 自定义 transform 方法
- AgentB 内存马
- 规避 addTransformer 检测
tags:
- java
- agent
- memshell
- jvmti
- transform
- evasion
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:40:45+08:00'
  notes: 已对照原文 12556 全文与 49 张图核对：JPLISAgent.mInstrumentationImpl/mTransform 字段（图44）、Hack.r 六参方法与 Base64 恶意 class、AgentB 输出 methodCount:0x2 / size_of_parameters:1 与 7 / transform method is 1th / transform methodID 0x7f9274d31558（图45）均与卡片一致。修正一处：原稿称 r 的 7 参与 transform 的 7 参不同，实际 _size_of_parameters 含 receiver 后两者同为 7，已改为按构造器 1 与 r 7 区分定位。与自建 JPLISAgent 卡为前置/变体关系，机制不同，保留。未实测运行 PoC。
---

## 一句话结论

常规 Agent 内存马必须实现 `ClassFileTransformer.transform` 并调用 `addTransformer`，这两个特征很容易被防御方监控；若已能自建/取得 `JPLISAgent`，可直接把它的 `mInstrumentationImpl` 换成一个自定义类的对象、把 `mTransform` 换成该类中“接收 6 个参数、返回 byte[]”的任意方法（无需叫 transform），JVM 的 `transformClassFile` 会照常调用它完成类改写，从而绕开 `addTransformer`/`ClassFileTransformer` 两类检测特征。

## 原理

- `JPLISAgent` 的类转换路径在 `transformClassFile` 中并不关心 transformer 列表，而是直接调用 `mInstrumentationImpl` 对象上的 `mTransform` 方法：签名对应 `transform(ClassLoader, String, Class, ProtectionDomain, byte[], boolean)`（6 参，jdk8 的 `ClassFileTransformer` 接口在内部调用时多一个 isRetransformer 布尔）。
- 因此攻击者只要构造一个普通类 `Hack`，提供参数类型兼容的私有方法 `r(Object,Object,Object,Object,byte[],boolean)`（方法名任意），把 `mInstrumentationImpl` 指到 `Hack` 实例的 jobject、`mTransform` 指到 `r` 的 `jmethodID`，JVM 在转换时就会回调 `r`，在其中返回恶意字节码。
- 防御方常见的两个检测点被绕过：
  - `InstrumentationImpl.addTransformer` 被 hook/监控 —— 本方式根本不调用它；
  - 扫描 `ClassFileTransformer` 实现类 —— 本方式没有任何 transformer 实现类，`Hack` 只是普通业务类形态。
- 方法定位仍用 `_size_of_parameters`：`r` 在 Java 层是 6 个参数，但 JVM 视角含 receiver 后 `_size_of_parameters=7`；在 `Hack` 类的 `_methods` 中按该值即可定位 `r`（原文实测 AgentB 输出构造器 `size_of_parameters: 1` 与 `r` 的 `7`，取 7 的那项，`the transform method is 1th`）。
- 与“自建 JPLISAgent”卡的区别：那张卡填的是标准 `InstrumentationImpl.transform`；本卡把两个关键字段整体替换为自定义实现，属于检测规避变体。

## 触发条件

- 已具备自建 `JPLISAgent` 或复用已有 `InstrumentationImpl` 的能力（见关联卡）；
- 目标 JDK8 系，`JPLISAgent` 结构偏移已知；
- 防御方依赖 `addTransformer`/`ClassFileTransformer` 特征做检测（大多数查杀工具）。

## 利用步骤

1. 构造 `Hack` 类与 `r` 方法，在 `r` 中判断目标类名并返回恶意字节码（Base64 解码后的 class）。
2. 自建 `JPLISAgent` 后，用 `Unsafe.getObject` 取 `Hack` 实例的 jobject 地址填入 `mInstrumentationImpl`。
3. 解析 `Hack` 类的 `InstanceKlass._methods`，按参数个数找到 `r` 的 `Method*` 地址填入 `mTransform`。
4. 触发任意类转换（如主动 `retransformClasses`，或在类加载时）即回调 `r`，完成内存马改写。
5. 防御方检查 transformer 列表与实现类时看不到任何异常（列表为空/只有正常 Agent）。

## PoC

自定义方法（原文，AgentB）：

```java
class Hack {
    // 参数与内部 transform 一致，方法名任意
    private byte[] r(Object loader, Object classname, Object classBeingRedefined,
                     Object protectionDomain, byte[] classfileBuffer, boolean isRetransformer) {
        if (!"com/rzte/agentcrack/T".equals(classname)) return null;
        System.out.println("will hack the class: " + classname);
        String data = "yv66vgAAADQAKAoABAAVCQAW..."; // Base64 恶意 class
        return Base64.getDecoder().decode(data);
    }
}
```

AgentB 输出（jdk 1.8.0_181）：

```text
use mInstrumentationImpl addr: 0x93866f58
methodCount: 0x2
size_of_parameters: 1
size_of_parameters: 7
the transform method is 1th
transform methodID is: 0x7f9274d31558
add transformer success!
Instrumentation object addr: 0x93866f68
will retransform class: T
will hook class ==========> com/rzte/agentcrack/T
```

## 变体与关联

- 变体：把 `mInstrumentationImpl` 指到任意已存在对象（甚至 JDK 自带类实例），`mTransform` 指向任意 6 参方法，可组合出多种回调形态。
- 变体：`r` 内不直接返回字节码，而是记录类加载信息做“静默侦察”，避免改动字节码触发行为检测。
- 关联：[[web-java-classloader-agent-self-build-jplisagent-java-vm-method-parse]]——自建 JPLISAgent 的前置能力。
- 关联：[[web-java-classloader-agent-reuse-existing-instrumentation-jvmti-chain]]——复用已有 Agent 对象。
- 关联：[[defense-detection-arthas-agent-memshell-detect-remove]]——基于 transformer 列表的查杀，本卡正是其盲区。

## 检测与防御

- 检测：不能只查 `mTransformerManager`/`mRetransfomableTransformerManager` 列表；应校验 `JPLISAgent.mInstrumentationImpl` 是否为预期的 `InstrumentationImpl` 类型、`mTransform` 是否指向 `InstrumentationImpl.transform`，并比对 `JvmtiEnv` 节点与已知 Agent 的对应关系。
- 防御：RASP 对 `transformClassFile` 入口/类重载事件做监控；完整性校验 Agent 链上的对象类型与字段。
- 提示：任何“只扫 transformer 实现类”的查杀都会被该手法绕过。
