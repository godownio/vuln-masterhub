---
id: web-java-classloader-agent-self-build-jplisagent-java-vm-method-parse
title: 纯 Java 自建 JPLISAgent：符号定位 JavaVM/main_vm + setHasRetransformableTransformers 造 JvmtiEnv，解析 jobject→InstanceKlass._methods 取 jmethod
type: scenario
domain: web
path: web/java/classloader
technique: java-agent-self-build-jplisagent-method-parse
aliases:
- 自建 JPLISAgent
- AgentA 内存马
- 无 shellcode 注入 Agent
- 构造 InstrumentationImpl
- main_vm 符号
- InstanceKlass _methods 定位
tags:
- java
- agent
- memshell
- jvmti
- unsafe
- jplisagent
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:40:43+08:00'
  notes: 已对照原文 12556 全文与 49 张图核对：addTransformer→setHasRetransformableTransformers 源码（图26）、retransformableEnvironment/GetEnv/AddCapabilities/SetEventCallbacks（图27）、main_vm 符号 0xf959c8（图28/42）、oopDesc 与压缩类指针（图31-35）、ConstMethod _size_of_parameters=7 定位 transform（图36/37）、_minor_version/_major_version 锚点与 _methods 偏移（图38-40）、debug/8u181/arm64 8u202 三环境输出（图41-43）均与卡片一致；PoC 数字与图42逐项吻合。已把『0x74 对齐后 0x180/0x188』改写为『正文相对偏移 0x74+对齐；实测 _methods 绝对偏移 0x180/0x188』避免歧义。与 fileless-agent 改能力位路线不同，属自建完整 JPLISAgent，保留。未实测运行 PoC。
---

## 一句话结论

不落 jar、不用 shellcode，也能在纯 Java 内构造出可用的 `JPLISAgent`：用 Unsafe 调用 `setHasRetransformableTransformers`（依赖 `JavaVM`，可从 libjvm 符号 `main_vm` 取得）创建 `retransformerEnv` 补全 `JvmtiEnv` 节点；再用 `Unsafe.getObject` 取 `InstrumentationImpl` 的 `jobject`，通过解析 `oopDesc→klass→InstanceKlass._methods` 找到 `transform` 方法地址填入 `mTransform`，最后 `addTransformer`+`retransformClasses` 即可改写 `HttpServlet.service`。

## 原理

- `JPLISAgent` 的组成（jdk8 `JPLISAgent.h`）：`mJVM`、`mNormalEnvironment`/`mRetransformEnvironment`、`mInstrumentationImpl`（jobject）、`mTransform`（jmethodID 等）。`instrument` 修改类时最终经 `transformClassFile` 调用 `mInstrumentationImpl.mTransform`（`InstrumentationImpl.transform`）。
- **已有 API 可借用**：`InstrumentationImpl.addTransformer(canRetransform=true)` 内部调用 `setHasRetransformableTransformers(mNativeAgent, true)`；该 native 方法会经 `JavaVM->GetEnv(JVMTI_VERSION_1_1)` 为 agent 创建 `retransformerEnv`、`AddCapabilities(can_retransform_classes=1)`、`SetEventCallbacks` 并安装。即：只要拿到一个可调用的 `JavaVM` 和自制的 `JPLISAgent` 内存结构，就能让 JVM 帮我们生成合法 `JvmtiEnv`。
- **JavaVM 获取**：`main_vm` 是 libjvm 的静态符号（`JNI_CreateJavaVM` 保存的句柄），符号表可直接查到偏移；它是 `JNIInvokeInterface*` 结构指针。
- **jobject**：`Unsafe.getObject(base, offset)` 以 `oop*` 语义读对象地址；反过来把地址写入对象数组 0 号槽即可还原 Java 对象。
- **jmethod 定位**：JNI 的 `jmethodID` 实际上就是内部 `Method*` 地址。解析链：`jobject` 地址即 `oop*` → `oopDesc::_metadata._klass`（注意 `UseCompressedClassPointers`，压缩时按 `narrow_klass_base + (v << shift)` 解码，两个值都来自 `Universe::_narrow_klass` 静态符号）→ `InstanceKlass::_methods`（`Array<Method*>`）。`Method` 含 `constMethod`，其中 `_size_of_parameters` 可用于定位 `transform`：jdk8 的 `transform` 有 7 个参数，其它方法都不是 7，无需解析 Symbol 名字。
- **版本兼容**：`InstanceKlass` 结构随 JDK 版本/编译参数变化。用 `_minor_version`/`_major_version`（minor 基本恒为 0，major 从 45 到 65）作为锚点定位，再按结构偏移求 `_methods`（原文正文给出的相对偏移为 0x74 并做 8 字节对齐；实测输出中 `_methods` 的绝对偏移为 0x180/0x188，取决于 `NOT_PRODUCT(_verify_count)` 是否存在）；`_methods` 后是 `_default_methods`，若取到的前一项为 0 则回退一个地址。该逻辑在 jdk8u121/181、debug、arm64 上验证。
- 构造完成后即可 `addTransformer(canRetransform=true)` + `retransformClasses`，与正常 Agent 无差别；全程无文件、无 shellcode。

## 触发条件

- 目标为 JDK8 Linux 64 位（含 arm64），进程内可执行 Java 代码（JSP/反序列化等）；
- libjvm 符号可读（默认），Unsafe 可用（JDK8 默认 `sun.misc.Unsafe`）；
- 已知或可探测 JDK 版本以适配结构偏移（原文做成版本字段锚点自适应）；
- 需要修改的宿主类可 retransform（如 `javax.servlet.http.HttpServlet`）。

## 利用步骤

1. 读 `/proc/self/maps` 定位 libjvm 基址，解析符号：`main_vm`（JavaVM）、`Universe::_narrow_klass`、`UseCompressedClassPointers`。
2. 用 Unsafe 在堆外/内存中拼出 `JPLISAgent` 结构：填入 `mJVM=main_vm`，其余清零。
3. 通过反射/Unsafe 调用 `setHasRetransformableTransformers(agentPtr, true)`，让 JVM 创建 `retransformerEnv` 并回填 `mRetransformEnvironment`。
4. `unsafe.getObject` 拿到自建 `InstrumentationImpl` 对象的 jobject 地址填入 `mInstrumentationImpl`；按 `oop→klass→_methods` 解析出参数个数为 7 的 `transform` 方法地址填入 `mTransform`。
5. 以自建 `InstrumentationImpl` 调用 `addTransformer(evilTransformer, true)`、`retransformClasses(HttpServlet.class)`，注入内存马。
6. 用 `?cmd=` 访问验证；AgentX/NoAgent 之外，AgentA 在 debug jdk、1.8.0_181、arm64 1.8.0_202 均实测成功。

## PoC

关键输出（AgentA，正常 jdk 1.8.0_181）：

```text
main_vm offset: 0xf959c8
main_vm addr: 0x7f966012c830, agent addr: 0x938475a8
narrowKlass offset: 0xfa0a00, addr: 0x7f96671a0a00
_narrow_klass._base: 0x0, narrow_klass._shift: 3
klass addr: 0x100053c78
minor offset: 0x110, major version: 52, minor version: 0, use methods offset: 0x180
InstanceKlass field '_verify_count' maybe not exist, reuse methods offset: 0x180
methods addr: 0x7f9650aba318
_size_of_parameters: 7
the transform method is 0th
transform methodID is: 0x7f9650aba320
add transformer success!
Instrumentation object addr: 0x938475a8
will retransform class: T
will hook class ==========> com/rzte/agentcrack/T
```

结构字段（jdk8 `JPLISAgent`）：`mJVM`、`mInstrumentationImpl`、`mTransform` 是必须填对的三项；其余 `mRedefineAvailable`/`mAgentClassName` 等可留空。

## 变体与关联

- 变体：拿到自建 `JPLISAgent` 后不注册 transformer，直接把 `mInstrumentationImpl`/`mTransform` 换成自定义类/方法（见“替换 mTransform”卡），彻底消除 `ClassFileTransformer` 特征。
- 变体：JDK 高版本结构变化需重算偏移；`UseCompressedClassPointers` 关闭时直接使用 `_klass` 指针。
- 关联：[[web-java-classloader-fileless-agent-memshell-jvmti-can-redefine-patch]]——另一条“不落 jar”路线（改能力位+构造 InstrumentationImpl）。
- 关联：[[web-java-classloader-agent-reuse-existing-instrumentation-jvmti-chain]]——复用已有 Agent 对象，无需自建结构。
- 关联：[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]——标准 Attach 路线。

## 检测与防御

- 检测：JSP/动态类中出现 `main_vm`、`_narrow_klass`、`JPLISAgent` 结构偏移、`arrayBaseOffset`、`getObject` 解析 klass 等符号/常量；非预期重载容器类。
- 防御：JDK 高版本启用模块封装与 `-XX:+DisableAttachMechanism` 只能提高门槛；核心是监控类重载事件与 JSP 落地/执行。
- 提示：该手法依赖内部结构，跨 JDK 版本稳定性有限，但“用版本字段做锚点自适应”显著提高了兼容性。
