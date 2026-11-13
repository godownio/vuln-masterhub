---
id: web-java-classloader-agent-reuse-existing-instrumentation-jvmti-chain
title: 借尸还魂：遍历 jvmtiEnv 链复用已有 InstrumentationImpl，无 Attach 无 jar 注入 Agent 内存马（NoAgent.jsp）
type: scenario
domain: web
path: web/java/classloader
technique: java-agent-reuse-existing-instrumentation
aliases:
- 借尸还魂 Agent
- NoAgent.jsp
- 复用 InstrumentationImpl
- jvmtiEnv 链复用
- 不注入 Agent 改类
tags:
- java
- agent
- memshell
- jvmti
- instrumentation
- fileless
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:40:40+08:00'
  notes: 已对照原文 12556 全文与 49 张图核对：_head_environment 符号与 _next（图14/15）、_JPLISEnvironment/_JPLISAgent.mInstrumentationImpl（图13/25）、JOL arrayBaseOffset 技巧（图16/17）、NoAgent.jsp 输出（图18/21/22/23/24：jvmtiEnv 链遍历→instImpl→retransform HttpServlet→cmd=ls/whoami 执行、防御侧 dump 的 T.bb40.class 仍正常）均与卡片一致。修正两处：原稿『_next 偏移为当前节点+0x2』易误解为字节偏移，已按实测输出 the _next offset is 2 改为槽位 2（64 位即 +0x10）；触发条件由仅 JDK8 补为 JDK8/JDK11（原文 1.8.0_181 与 amazon-corretto 11 均实测）。与既有 fileless-agent-memshell-jvmti-can-redefine-patch（改能力位+新建 InstrumentationImpl）及 attach-api 卡机制不同，dedup_review 成立，保留。未实测运行 PoC。
---

## 一句话结论

生产 JVM 往往已加载 SkyWalking/RASP 等 Java Agent，`JvmtiEnvBase::_head_environment` 链上已有现成的 `JvmtiEnv` 节点及其关联的 `JPLISAgent→InstrumentationImpl`；攻击者只需用 Unsafe 从 `libjvm.so` 符号 `_ZN12JvmtiEnvBase17_head_environmentE` 走到链尾，取出已有 `InstrumentationImpl` 的 `jobject` 地址并用对象数组技巧转回 Java 对象，即可直接调用其 `retransformClasses`/`redefineClasses` 改写 `HttpServlet.service` 注入内存马——无需 Attach、无需落 jar、无需伪造 capabilities。

## 原理

- 每个 Java Agent（`-javaagent` 或 `loadAgent`）在 JVM 内对应一个 `JvmtiEnv` 节点：`JvmtiEnvBase` 结构含 `_next` 与 `_env_local_storage`，后者实际是 `_JPLISEnvironment`，内含 `mAgent`（`JPLISAgent`）与 `mJVMTIEnv`；`JPLISAgent.mInstrumentationImpl` 就是该 Agent 的 `sun.instrument.InstrumentationImpl`（`jobject`）。
- 链头 `JvmtiEnvBase::_head_environment` 是 `libjvm.so` 的静态符号，符号名 `_ZN12JvmtiEnvBase17_head_environmentE`，可读 `/proc/<pid>/maps` 得 libjvm 基址，加符号偏移定位；脚本实测 `_next` 的槽位偏移为 2（输出 `the _next offset is 2`，按指针大小换算即 64 位下节点 + 0x10），按指针大小读取即可遍历。
- `jobject` 本质是 `oop*`（JNIHandles::resolve 直接解引用），不能直接当 Java 对象用。用 JOL 的逆向技巧：`Object[] arr = new Object[1]; unsafe.putLong(arr, arrayBaseOffset, jobjectAddr);` 后 `arr[0]` 即为目标 Java 对象。
- 选链尾节点：若链尾 `InstrumentationImpl` 支持 retransform，攻击者后续 `addTransformer(...,true)` 追加的节点也在链尾，防护 Agent（更靠前）无法看到修改后的字节码（见链序/缓存卡）。
- 攻击代码运行在 JSP 中（如 NoAgent.jsp）：读符号→遍历→取 `InstrumentationImpl`→`retransformClasses(HttpServlet.class)`，用 ASM/javassist 在 `service` 方法插入按参数执行命令的逻辑；兼容 Tomcat 9（`javax.servlet`）与 Tomcat 10（`jakarta.servlet`）。
- 为什么成立：`InstrumentationImpl` 是普通 Java 对象，方法调用不校验调用者身份；JVM 也不区分“谁创建了这个 Agent”。只要目标链上存在任一 Agent，攻击者就能搭便车。

## 触发条件

- 目标 JVM（JDK8/JDK11，原文在 1.8.0_181 与 amazon-corretto 11 均实测；未做模块强封装限制）上已加载至少一个 Java Agent（可观测性、RASP、热部署等，生产环境常见）；
- 攻击者已有 JSP/代码执行能力，能在目标进程内执行 Java 代码（如上传 JSP）；
- 能读取 `/proc/self/maps` 与 libjvm 符号（默认进程内可读）；
- 目标类可在当前 JVM 中 retransform/redefine（JDK8 一般满足）。

## 利用步骤

1. 在 JSP 中读取 `/proc/self/maps` 找 `libjvm.so` 基址，解析 ELF 符号表取 `_ZN12JvmtiEnvBase17_head_environmentE` 与 `_ZN8Universe13_narrow_klassE` 等偏移。
2. 从链头遍历 `_next` 到最后一个 `JvmtiEnv`，按 `_JPLISEnvironment`/`_JPLISAgent` 结构偏移取 `mInstrumentationImpl`（`jobject` 地址）。
3. 用 `unsafe.putLong(objects, arrayBaseOffset, addr)` 把 jobject 地址写入对象数组 0 号位，`objects[0]` 得到可用 `Instrumentation` 对象。
4. 调用 `addTransformer(evilTransformer, true)`（或直接 `redefineClasses`），`retransformClasses(HttpServlet.class)` 把恶意逻辑写入 `service`。
5. 访问任意 URL 携带 `cmd` 参数验证命令执行；防护 Agent 侧只能看到 `HttpServlet` 被重载，dump 出的字节码仍是正常版本。

## PoC

```text
# 关键输出（NoAgent, Tomcat 9 + JDK11 环境实测）：
found jvmtiEnv addr: 0x7f820401cb70, the _next offset is 2
the last jvmtiEnv addr: 0x7f820401d2c0
envLocalStorage addr: 0x7f820401cdc0
instImpl addr: 0x7f82041c8030
obj addr: 0x93a17958
[NoAgent] will retransform the class: javax.servlet.http.HttpServlet
[NoAgent] will hook class ==========================> javax.servlet.http.HttpServlet

# 内存马访问：
GET /demo/test?cmd=ls     → 400 页面列出目录
GET /demo/test?cmd=whoami → 400 页面消息 root
```

对象转换核心：

```java
Object[] objects = new Object[1];
unsafe.putLong(objects, arrayBaseOffset, jobjectAddr);
Instrumentation inst = (Instrumentation) objects[0];
```

## 变体与关联

- 变体：直接复用已有 `InstrumentationImpl` 的 `redefineClasses`（不 addTransformer），一次性替换 `HttpServlet`，但会被防护模式检测到（链序/缓存卡）。
- 变体：若链上只有普通（不可 retransform）环境，可改修补 `can_redefine_classes` 能力位后自行构造 `InstrumentationImpl`（见无文件注入卡）。
- 关联：[[web-java-classloader-fileless-agent-memshell-jvmti-can-redefine-patch]]——同目标（不落 jar）但机制是改能力位+新建 InstrumentationImpl；本卡是复用现有 Agent 对象。
- 关联：[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]——标准 Attach + jar 路线。
- 关联：[[web-java-classloader-agent-jvmtienv-chain-order-cached-classfile]]——链序与检测可见性。

## 检测与防御

- 防御：不轻易在生产 JVM 中常驻第三方 Agent；对 Agent 链做完整性校验（节点数量/预期 Agent 列表）；RASP/防护 Agent 监控 `addTransformer`、`retransformClasses` 的调用来源与调用栈。
- 检测：JSP/动态类中出现读取 `/proc/self/maps`、libjvm 符号名、`arrayBaseOffset`、`putLong(objects...)` 等行为；非预期地重载 `HttpServlet` 等容器类。
- 提示：只要链上有 Agent，就存在被“借尸”复用的可能；JDK 高版本模块封装/`Instrumentation` 访问限制可提高门槛但非根本防护。
